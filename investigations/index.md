---
title: "Investigations"
layout: default
permalink: /investigations/
---

<div class="investigations-wrap">
  <header class="investigations-header">
    <p class="signal-badge">// CASEFILE_INDEX //</p>
    <h1 class="page-title">Investigations</h1>

    <div class="hero-callout investigations-callout">
     These are the cases I’ve worked through and written up, with the goal of showing the evidence, the reasoning behind each step, and what each investigation taught me.
    </div>
    
  </header>

  <div class="investigations-list">
    <article class="case-card investigation-index-card">
      <div class="investigation-index-main">
        <p class="panel-label">Case Report</p>
        <h2><a href="/investigations/mfa-fatigue-bec-m365/">MFA Fatigue BEC in Microsoft 365</a></h2>
        <p>
          A business email compromise that began with repeated MFA prompts against a finance employee and ended in a fraudulent payment redirection attempt. The case follows suspicious sign-in activity, inbox rule abuse, internal payment-change fraud, and additional access to OneDrive and SharePoint from the same attacker session.
        </p>

        <div class="case-tags">
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
      </div>

      <div class="investigation-index-side">
        <a class="text-link" href="/investigations/mfa-fatigue-bec-m365/">Open report</a>
      </div>
    </article>

    <article class="case-card investigation-index-card">
      <div class="investigation-index-main">
        <p class="panel-label">Case Report</p>
        <h2><a href="/investigations/emberforge-source-code-theft/">EmberForge Source Code Theft</a></h2>
        <p>
          A multi-stage intrusion that began on an artist workstation and expanded to a server and Domain Controller. The case follows ISO-based execution, DLL launch through <code>rundll32.exe</code>, UAC bypass, LSASS dumping, lateral movement, shadow-copy abuse to access <code>ntds.dit</code>, and exfiltration to MEGA using <code>rclone.exe</code>.
        </p>

        <div class="case-tags">
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
      </div>

      <div class="investigation-index-side">
        <a class="text-link" href="/investigations/emberforge-source-code-theft/">Open report</a>
      </div>
    </article>
  </div>
</div>
