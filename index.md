---
title: "Threat Hunting and IR Case Files"
permalink: /
---

### [Home](/) | [Investigations](/investigations/)

<div class="callout note">
  <div class="callout-title">What this site is</div>
  <p>This is a collection of threat hunts, incident investigations, and technical write-ups built from telemetry, timelines, and evidence. My goal here is to show not just what happened, but how an investigation comes together.</p>
</div>

I built this site to document cases in a way that feels readable, grounded, and useful to other analysts. Each write-up focuses on following the evidence, making careful pivots, and turning messy findings into a clear report.

## What you'll find here

- Incident reports built from process, network, DNS, file, registry, cloud sign-in, and mailbox telemetry
- Technical timelines that trace attacker activity from initial access through impact
- Clear pivots and reasoning, not just final answers
- Write-ups that balance technical depth with readable reporting

## Featured Investigation

<div class="feature-card">
  <div class="feature-card-content">
    <p class="feature-label">Featured Case</p>
    <h3><a href="/investigations/emberforge-source-code-theft/">EmberForge Source Code Theft</a></h3>
    <p>
      A multi-stage intrusion that began on an artist workstation and expanded to a server and Domain Controller. The case includes ISO-based execution, DLL launch through <code>rundll32.exe</code>, UAC bypass, LSASS dumping, lateral movement, shadow-copy abuse to access <code>ntds.dit</code>, and exfiltration to MEGA using <code>rclone.exe</code>.
    </p>
    <p>
      <a class="feature-link" href="/investigations/emberforge-source-code-theft/">Read the full investigation</a>
    </p>
  </div>
</div>

## Latest Investigation

<div class="feature-card">
  <div class="feature-card-content">
    <p class="feature-label">Latest Case</p>
    <h3><a href="/investigations/mfa-fatigue-bec-m365/">MFA Fatigue BEC in Microsoft 365</a></h3>
    <p>
      A business email compromise that began with repeated MFA prompts against a finance employee and ended in a fraudulent payment redirection attempt. The case follows suspicious sign-in activity, inbox rule abuse, internal payment-change fraud, and additional access to OneDrive and SharePoint from the same attacker session.
    </p>
    <p>
      <a class="feature-link" href="/investigations/mfa-fatigue-bec-m365/">Read the full investigation</a>
    </p>
  </div>
</div>

## Explore More

You can browse the full collection of case write-ups on the [Investigations](/investigations/) page.
