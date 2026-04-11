---
title: "Investigations"
permalink: /investigations/
---

### [Home](/)

# Investigations

This section collects full case write-ups built from telemetry, timelines, and evidence. Some reports are tighter and more technical. 
Others leave a little more room for investigation. However, The goal is the same in each one: follow the evidence and write clearly enough that someone else can retrace the case.t

<div class="investigation-grid">

  <div class="investigation-card">
    <p class="investigation-label">Case Report</p>
    <h3><a href="/investigations/emberforge-source-code-theft/">EmberForge Source Code Theft</a></h3>
    <p>
      A multi-stage intrusion that began on an artist workstation and expanded to a server and Domain Controller. The case includes ISO-based execution, DLL launch through <code>rundll32.exe</code>, UAC bypass, LSASS dumping, lateral movement, shadow-copy abuse to access <code>ntds.dit</code>, and exfiltration to MEGA using <code>rclone.exe</code>.
    </p>

    <div class="investigation-tags">
      <span>Initial Access</span>
      <span>Privilege Escalation</span>
      <span>Credential Access</span>
      <span>Lateral Movement</span>
      <span>Exfiltration</span>
    </div>  

    <p class="attack-mapping">
      <strong>ATT&amp;CK:</strong>
      <code>T1204.002</code>
      <code>T1218.011</code>
      <code>T1548.002</code>
      <code>T1003.001</code>
      <code>T1021.002</code>
      <code>T1567.002</code>
    </p>

    <p class="investigation-link-row">
      <a class="feature-link" href="/investigations/emberforge-source-code-theft/">Open investigation</a>
    </p>
  </div>

</div>
