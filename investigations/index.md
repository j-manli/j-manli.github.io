---
title: "Investigations"
permalink: /investigations/
---

### [Home](/)

# Investigations

This section collects full case write-ups built from telemetry, timelines, and evidence. Some reports stay tight and technical. Others leave a little more room for the investigative thread behind the findings. The goal is the same in each one: follow the evidence, stay grounded, and write clearly enough that someone else could retrace the case.

<div class="investigation-grid">

  <div class="investigation-card">
    <p class="investigation-label">Case Report</p>
    <h3><a href="/investigations/emberforge-source-code-theft/">EmberForge Source Code Theft</a></h3>
    <p>
      A multi-stage intrusion that began on an artist workstation and expanded to a server and Domain Controller. The case follows ISO-based execution, DLL launch through <code>rundll32.exe</code>, UAC bypass, LSASS dumping, lateral movement, shadow-copy abuse to access <code>ntds.dit</code>, and exfiltration to MEGA using <code>rclone.exe</code>.
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

  <div class="investigation-card">
    <p class="investigation-label">Case Report</p>
    <h3><a href="/investigations/mfa-fatigue-bec-m365/">MFA Fatigue BEC in Microsoft 365</a></h3>
    <p>
      A business email compromise that began with repeated MFA prompts against a finance employee and ended in a fraudulent payment redirection attempt. The case follows suspicious sign-in activity, inbox rule abuse, internal payment-change fraud, and additional access to OneDrive and SharePoint from the same attacker session.
    </p>

    <div class="investigation-tags">
      <span>Credential Access</span>
      <span>Email Collection</span>
      <span>Persistence</span>
      <span>Defense Evasion</span>
      <span>Financial Theft</span>
    </div>

    <p class="attack-mapping">
      <strong>ATT&amp;CK:</strong>
      <code>T1621</code>
      <code>T1078.004</code>
      <code>T1114.002</code>
      <code>T1114.003</code>
      <code>T1564.008</code>
      <code>T1657</code>
    </p>

    <p class="investigation-link-row">
      <a class="feature-link" href="/investigations/mfa-fatigue-bec-m365/">Open investigation</a>
    </p>
  </div>

</div>
