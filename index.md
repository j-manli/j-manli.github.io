---
title: "Threat Hunting and Incident Response Portfolio"
permalink: /
---

[Home](/) | [Investigations](/investigations/)

<div class="callout note">
  <div class="callout-title">What this site is</div>
  <p>This is a collection of threat hunts, incident investigations, and technical write-ups built from telemetry, timelines, and evidence. My goal here is to show not just what happened, but how an investigation comes together.</p>
</div>

I built this site to document cases in a way that feels readable, grounded, and useful to other analysts. 
Each write-up focuses on following the evidence, making careful pivots, and (trying) to make sense of messy findings.  
Above all else, I want to be able to track and see how my thinking and methodology evolve (hopefully) over time.

## What you'll find here

- Technical timelines that trace attacker activity from initial execution through impact
- Clear pivots and reasoning (not just final answers)
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
