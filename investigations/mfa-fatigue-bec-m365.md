---
title: "MFA Fatigue BEC in Microsoft 365"
permalink: /investigations/mfa-fatigue-bec-m365/
---
### [Home](/) | [Investigations](/investigations/)

# Security Incident Report

<div class="callout note">
  <div class="callout-title">Initial Brief</div>
  <p>LogN Pacific Financial Services received an urgent call from its bank's fraud department after a vendor payment of <code>£24,500</code> was redirected to an unknown account. 
    The receiving bank flagged the transaction as suspicious and froze the funds before it cleared. 
    Finance reported that they had followed normal process after receiving an email that appeared to come from a known colleague with updated banking details.</p>
</div>

## Executive Summary

**Incident ID:** `INC-2026-0225-LOGNPACIFIC`  
**Incident Severity:** `High`  
**Incident Status:** `Investigation Completed`

### Incident Overview

This investigation centered on the compromise of finance employee Mark Smith (`m.smith@lognpacific.org`) and the resulting business email compromise that led to a fraudulent wire transfer attempt. 
The events unfolded the way many BEC cases do: account access, mailbox control, and quiet persistence.

The earliest suspicious sign-in activity for `m.smith@lognpacific.org` appeared on `2026-02-25`, including sign-ins from the United States followed by a concentrated cluster of sign-in attempts from the Netherlands. 
The Netherlands activity included repeated failed attempts from `205[.]147[.]16[.]190` before a successful sign-in, which lines up closely with Mark Smith's report that he received repeated MFA prompts at home and 
eventually approved one just to make them stop.

Once access was established, the attacker moved quickly. Mailbox activity from the same IP showed email access, creation of inbox rules, forwarding of finance-related emails to `insights@duck[.]com`, and a second rule 
designed to delete messages containing words tied to security/compromise notifications. Shortly after that, the compromised account was used to send an internal message to `j.reynolds@lognpacific.org` with updated banking 
details, which is the  point where the intrusion crossed over into financial fraud.

The same session also touched cloud-hosted collaboration data. Cloud app telemetry showed file access in Microsoft OneDrive for Business, and successful sign-in activity showed access to Office 365 SharePoint Online.

### Key Findings

- `m.smith@lognpacific.org` was compromised after an MFA fatigue sequence tied to sign-ins from `205[.]147[.]16[.]190`.
- The attacker appears to have already had Mark Smith's password before the MFA bombardment began.
- The successful sign-in was tied to Outlook Web access from a Linux host using Firefox `147.0`, which did not match the victim's normal Windows-based usage.
- The first observed post-authentication mailbox action was `MailItemsAccessed`, which suggests the attacker immediately began reviewing email content.
- The attacker created an inbox rule named `.` that forwarded emails containing `invoice`, `payment`, `wire`, and `transfer` to `insights@duck[.]com`.
- The attacker created a second inbox rule named `..` that deleted messages containing `suspicious`, `security`, `phishing`, `unusual`, `compromised`, and `verify`.
- The compromised mailbox was then used to send an internal message to `j.reynolds@lognpacific.org` with the subject `RE: Invoice #INV-2026-0892 - Updated Banking Details`.
- The same attacker session also accessed Microsoft OneDrive for Business and Office 365 SharePoint Online.
- Conditional Access was set to `notApplied`, which likely explains why a risky sign-in from an unmanaged device and unusual location was not blocked.

### Immediate Actions

Because the notes indicate the attacker still had a valid session and active inbox rules at the time of investigation, the immediate response should focus on cutting off access before any additional fraud attempts or mailbox manipulation occur.

- Disable `m.smith@lognpacific.org` immediately.
- Revoke all active Entra ID and Microsoft 365 sessions for the user.
- Remove malicious inbox rules, especially the forwarding rule to `insights@duck[.]com` and the deletion rule targeting security-related keywords.
- Reset the user's password and require re-registration of MFA methods.
- Review recent sign-ins, mailbox rules, delegated access, and OAuth grants tied to the account.
- Search for additional mail-sending activity or forwarding rules from other finance or executive accounts.
- Confirm whether `j.reynolds@lognpacific.org` or any other recipients acted on the fraudulent message.
- Preserve sign-in logs, cloud app events, and mail flow evidence before automated cleanup or retention limits remove useful artifacts.
- Review Conditional Access coverage for unmanaged devices and risky sign-in locations.

### Stakeholder Impact

**Finance Team:**  
This case directly impacted finance operations. A payment of `£24,500` was redirected based on fraudulent instructions sent from a compromised internal account. 
The bank froze the funds, which limited the immediate financial loss, but the process breakdown is still significant.

**Security and IT Teams:**  
The compromise shows that a valid cloud identity with mailbox access was enough to drive a material business outcome.

**Leadership and Compliance Stakeholders:**  
Even though the fraudulent payment was frozen, the case still represents a confirmed business email compromise involving unauthorized account access, mailbox rule abuse, and potential exposure of business data in Microsoft 365 services.

---

## Technical Analysis

### Affected Accounts, Services, and Data

The core compromised identity in this investigation was:

- `m.smith@lognpacific.org`

The attacker activity observed in telemetry touched the following services:

- Outlook Web / Office 365 Exchange Online
- Microsoft OneDrive for Business
- Office 365 SharePoint Online

The highest-confidence business impact was the use of the compromised mailbox to send fraudulent payment instructions internally. 
In addition to that, the observed file access in OneDrive and SharePoint raises concerns about what other sensitive data the attacker had access to.

### Sign-in Activity and MFA Abuse

The first question in this case was whether Mark Smith's account was actually compromised or whether the MFA report was just noise. I started with the sign-in logs for `m.smith@lognpacific.org`.

```kusto
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where AlternateSignInName == "m.smith@lognpacific.org"
| project TimeGenerated, Location
| sort by TimeGenerated asc
```

The earliest login location in the review window was the United States at `2026-02-25T21:44:11.8042067Z`. After that, the activity shifted sharply. 
From `2026-02-25T21:54:24.731913Z` through `2026-02-25T22:31:19.6689495Z`, there were `25` sign-in events for the same user from the Netherlands.

To focus on the IP behind the impossible-travel pattern, I widened the view slightly:

```kusto
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where AlternateSignInName == "m.smith@lognpacific.org"
| project TimeGenerated, Location, IPAddress
| sort by TimeGenerated asc
```

That identified the source IP as:

```text
205[.]147[.]16[.]190
```

The next step was to understand how the sign-in succeeded. I narrowed the view to the Netherlands activity and looked at result signatures over time.

```kusto
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where AlternateSignInName == "m.smith@lognpacific.org"
| where Location == "NL"
| project TimeGenerated, IPAddress, ResultSignature
| sort by TimeGenerated asc
```

Between `2026-02-25T21:54:24.731913Z` and `2026-02-25T21:55:15.2129522Z`, there were three failed sign-in attempts before the first successful sign-in at `2026-02-25T22:01:11.6776859Z`, all from `205[.]147[.]16[.]190`.

That lines up closely with Mark Smith's statement about receiving recurring MFA notifications. The attacker's path through MFA was persistence and pressure.

What makes it more telling is that this technique only works if the attacker already has the victim's password. In this case, MFA was not the first barrier they touched, but rather the one they needed the victim to clear for them.

> Which brings up an important question, how did the attacker gain access to Mark's password? Dark web credential dumps? Inforstealer malware? Credential phishing?

The Sign-in logs provided additional insight including their authentication into Outlook Web using a Linux operating system and `Firefox 147.0` browswer, which stood out against the victim's normal Windows ednpoint.

<img width="810" height="459" alt="mfa-fatigue-signin-sequence" src="https://github.com/user-attachments/assets/1002532c-50d4-416e-847d-9662fea620a9" />

> MFA fatigue sequence showing repeated failed sign-ins from `205[.]147[.]16[.]190` before the first successful authentication to `m.smith@lognpacific.org`.

<img width="1069" height="379" alt="impossible-travel-context" src="https://github.com/user-attachments/assets/bf61d045-55e2-4b7d-afac-0ec8e521f18b" />

> Sign-in context showing two sign-in locations (different countries) for the same user account in quick succession.

### Mailbox Access and Rule Creation

With confirmation that the attacker had a valid session, I began to scope cloud activity tied to the attacker IP.

```kusto
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType
| sort by TimeGenerated asc
```

The first observed action after authentication was `MailItemsAccessed` at `2026-02-25T21:56:24Z`. This was a useful anchor point. 
In a BEC case, that usually means they're trying to understand the victim's role, relationships, and overall access they have, similar to an endpoint compromise.

And just as in an endpoint comproise, I shifted my attention to see whether the attacker created mailbox persistence by pivoting into inbox rule creation from the malicious IP.

```kusto
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, RawEventData
| sort by TimeGenerated asc
```

At `2026-02-25T22:02:33Z`, the attacker created a new inbox rule. The following information was gathered from the `RawEventData` field:

- Rule name: `.`
- `ForwardTo`: `insights@duck[.]com`
- `SubjectOrBodyContainsWords`: `invoice`, `payment`, `wire`, `transfer`
- `StopProcessingRules`: `True`

This rule says a lot in a small amount of space. The naming choice, "`.`", although weird, doesn't call much attention to itself. 
It also reveals that the forwarding target, `insights@duck[.]com`, received finance-related messages outside the organization. 
And we know this attack is finance motivated attack based on the keywords the attacker chose to trigger the message forwarding. 
Lastly, the final parameter `StopProcessingRules` set to `True` is meant to block any of the vicitim's current inbox rules from triggering after theirs

<img width="886" height="570" alt="forwarding-rule-finance-keywords" src="https://github.com/user-attachments/assets/9c28b770-4b12-4b3e-b869-a979497153d8" />

### Rule-Based Concealment

The first rule established visibility into finance-related email. The second rule showed the other side of the operation: keeping the victim and defenders from seeing signs of compromise.

Reviewing the next rule-creation event showed a second inbox rule at `2026-02-25T22:03:59Z`. This rule was named `..` and used the same naming trick as the first rule. 
This time the `SubjectOrBodyContainsWords` parameter included `suspicious`, `security`, `phishing`, `unusual`, `compromised`, and `verify`, and it set `DeleteMessage = True`.

This rule is a form of evasion, crafted to suppress user warnings. If Microsoft, an internal security team, or a colleague sent a message containing one of those words, 
the rule was positioned to delete it before it reached the user in a meaningful way.

This is one of the more telling details in the case because it shows the attacker thinking ahead, and planning for long-term persistence.

<img width="1020" height="321" alt="deletion-rule-security-keywords" src="https://github.com/user-attachments/assets/44c65486-86e9-47a2-8edb-0a8fcb078e5e" />

### Fraudulent Internal Communication

By this point, the attacker had access, persistence, and a way to hide some of the warning signs. The next step was to see whether they used the mailbox to reach anyone else.

I pivoted into `EmailEvents` for messages sent from the compromised account, `m.smith@lognpacific.org`.

```kusto
EmailEvents
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, EmailDirection, SenderIPv4
| sort by TimeGenerated asc
```

At `2026-02-25T22:06:39Z`, the compromised account sent a message to `j.reynolds@lognpacific.org` with the subject `RE: Invoice #INV-2026-0892 - Updated Banking Details`. 
The `EmailDirection` field showed that the message was `Intra-org`, confirming that it was internal communication, and the sender IP was again the attacker's, `205[.]147[.]16[.]190`.

That's the point where the account compromise clearly became a business email compromise. The attacker didn't need to spoof a sender externally. 
They already had a trusted internal identity and used it to push a payment change inside a normal business channel.

<img width="1355" height="366" alt="fraudulent-internal-email" src="https://github.com/user-attachments/assets/f23fbcaf-5a66-4e1c-a9f0-cc7fdf94e1ae" />

> Fraudulent internal email sent from `m.smith@lognpacific.org` to `j.reynolds@lognpacific.org` with updated banking details, tied to attacker IP `205[.]147[.]16[.]190`.

### Broader Microsoft 365 Access

Once the email fraud path was established, the next question was scope. Was this just a mailbox compromise, or did the attacker use the same session to access other Microsoft 365 resources?

I started with file activity tied to the same IP.

```kusto
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "FileAccessed"
```

At `2026-02-25T22:07:16Z`, the `Application` field showed Microsoft OneDrive for Business. That was enough to widen the investigation. I then checked successful sign-ins from the same IP to see what cloud services were accessed.

```kusto
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where IPAddress == "205.147.16.190"
| where ResultType == "0"
| project TimeGenerated, AppDisplayName, SessionId
| sort by TimeGenerated asc
```

At `2026-02-25T22:09:17.0366473Z`, the attacker also accessed Office 365 SharePoint Online. Correlating the `SessionId` from `SigninLogs` with `AADSessionId` in `CloudAppEvents` showed they were the same session: `00225cfa-a0ff-fb46-a079-5d152fcdf72a`. 
The session ID is the fingerprint that ties mailbox access, inbox rule creation, email sending, OneDrive access, and SharePoint access back to one attacker session rather than isolated events.

<img width="953" height="577" alt="onedrive-file-access" src="https://github.com/user-attachments/assets/5f2cab48-690a-4f97-8d81-d67276ab5d9c" />

> File access activity in Microsoft OneDrive for Business tied to the attacker session.

<img width="927" height="576" alt="sharepoint-session-access" src="https://github.com/user-attachments/assets/233d988d-0b6c-4ddf-91e8-922ac5cebded" />

> Successful access to Office 365 SharePoint Online from the same attacker IP and session context.

### Control Gaps

Once the session path was clear, the last question was why the environment allowed it.

Reviewing the sign-in fields showed `ConditionalAccessStatus = notApplied`. That helps explain why a sign-in from an unusual location and an unmanaged Linux device was able to succeed after the MFA approval. 
In this case, the attacker didn' have to defeat a "well-enforced" policy stack. They only had to get one MFA prompt approved.

That doesn't make the user response irrelevant, but it does matter for root cause. The account compromise was enabled by human action, then sustained by a control gap.

```kusto
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00) .. datetime(2026-02-26 00:00))
| where AlternateSignInName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, IPAddress, Location, ConditionalAccessStatus, AppDisplayName
| sort by TimeGenerated asc
```

<img width="1116" height="434" alt="conditional-access-not-applied" src="https://github.com/user-attachments/assets/e62dfb83-205e-4399-a3a0-8733f7a62420" />

> Successful sign-in from `205[.]147[.]16[.]190` showing `ConditionalAccessStatus` set to `notApplied`, which helps explain why the attacker was able to authenticate from an unmanaged device and unusual location.

## Root Cause Analysis

The immediate cause of this incident was the compromise of `m.smith@lognpacific.org` followed by a successful MFA fatigue sequence that allowed the attacker to establish a cloud session.

Several contributing weaknesses made the compromise more impactful:

- The attacker appears to have already had the user's password before the MFA push bombing began.
- The MFA method in use could be abused through repeated prompt generation.
- Conditional Access was `notApplied`, which likely allowed the attacker to authenticate from an unusual location and unmanaged Linux host without a stronger policy challenge or block.
- The mailbox rules the attacker created were subtle enough to blend in and were effective at both forwarding useful finance emails and suppressing warning messages.
- The compromised mailbox was trusted enough internally that a payment change request could be sent to a colleague and acted on inside normal process.

## Threat Actor Assessment

The tradecraft in this case is most consistent with **Scattered Spider**, also tracked as **Octo Tempest**, **UNC3944**, and **Storm-0875**.

That assessment is based on the following overlapping tradecraft:

- MFA fatigue / push bombing
- strong use of social engineering around identity workflows
- cloud-account-centric intrusion
- mailbox rule abuse to support fraud and persistence
- business email compromise aimed at finance processes
- known operational overlap with intrusions affecting MGM Resorts, Caesars Entertainment, and major UK retailers

I would still keep that assessment at **likely**, not **confirmed**.

## Technical Timeline

| Time (UTC) | Activity |
|---|---|
| `2026-02-25T21:44:11.8042067Z` | Earliest reviewed sign-in location for `m.smith@lognpacific.org` appears in the United States |
| `2026-02-25T21:54:24.731913Z` | Netherlands-based sign-in attempts begin from `205[.]147[.]16[.]190` |
| `2026-02-25T21:54:24.731913Z` to `2026-02-25T21:55:15.2129522Z` | Three failed sign-in attempts occur before successful access |
| `2026-02-25T22:01:11.6776859Z` | First successful sign-in from `205[.]147[.]16[.]190` |
| `2026-02-25T21:56:24Z` | First post-authentication action is `MailItemsAccessed` |
| `2026-02-25T22:02:33Z` | Inbox rule `.` created to forward finance-related email to `insights@duck[.]com` |
| `2026-02-25T22:03:59Z` | Inbox rule `..` created to delete security-related warning emails |
| `2026-02-25T22:06:39Z` | Compromised account sends internal message to `j.reynolds@lognpacific.org` with updated banking details |
| `2026-02-25T22:07:16Z` | File access observed in Microsoft OneDrive for Business |
| `2026-02-25T22:09:17.0366473Z` | Successful access to Office 365 SharePoint Online |
| `2026-02-25T22:31:19.6689495Z` | Final Netherlands sign-in in the reviewed cluster |

## MITRE ATT&CK Mapping Summary

| Tactic | Technique | Event |
|---|---|---|
| Credential Access | `T1621` Multi-Factor Authentication Request Generation | Repeated MFA prompts were generated until the user approved one |
| Defense Evasion / Persistence / Initial Access | `T1078.004` Valid Accounts: Cloud Accounts | The attacker used a valid Microsoft 365 cloud identity after obtaining credentials and MFA approval |
| Collection | `T1114.002` Remote Email Collection | The first post-authentication action was `MailItemsAccessed` in the compromised mailbox |
| Collection | `T1114.003` Email Forwarding Rule | A rule forwarded finance-related emails to `insights@duck[.]com` |
| Defense Evasion | `T1564.008` Hide Artifacts: Email Hiding Rules | A second inbox rule deleted messages containing likely security-warning keywords |
| Impact | `T1657` Financial Theft | The compromised account was used to facilitate a fraudulent payment redirection |
| Social Engineering | `T1656` Impersonation | The attacker used a trusted internal identity to send updated banking details to a colleague |

## Analyst Assessment

This was a straightforward case on the surface, but it was useful because it showed how much damage can be done without malware, noisy tools, or a sprawling post-exploitation chain.

The attacker did not need to land on an endpoint or execute payloads. They only needed a valid password, persistence with MFA prompts, and one successful approval. After that, the mailbox did the rest.

What stands out most is how quickly the attack moved from access to business impact:

- read the mailbox
- create a forwarding rule
- create a deletion rule
- send a believable internal finance message
- touch additional cloud data

That sequence is short, quiet, and very practical. It's also why BEC cases can be deceptively serious even when the technical footprint looks small at first.

From a learning perspective, this case reinforced a few things for me:

- repeated MFA prompts should never be treated as harmless background noise
- inbox rules can tell you just as much about attacker intent as sign-in logs
- cloud session scoping matters, especially when the same session touches mail, OneDrive, and SharePoint
- in BEC investigations, the mailbox often becomes both the persistence mechanism and the fraud platform
