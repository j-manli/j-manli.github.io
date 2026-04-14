---
title: "Home"
layout: default
permalink: /
---

<div class="hero-wrap">
  <section class="hero-card">
    <p class="kicker">Threat Hunting · Incident Response · Case Files</p>

    <h1 class="hero-title">Threat hunts and investigations built from evidence, timelines, and process.</h1>

    <p class="hero-intro">
      This site collects technical case reports built from telemetry, timelines, and investigative reasoning. The goal is simple: follow the evidence, stay grounded, and write clearly enough that someone else can retrace the case.
    </p>

    <div class="button-row">
      <a class="button-link" href="/investigations/">Browse investigations</a>
      <a class="button-link" href="/investigations/emberforge-source-code-theft/">Featured case</a>
    </div>

    <div class="home-grid">
      <section class="panel">
        <p class="panel-label">Featured Investigation</p>
        <h2><a href="/investigations/emberforge-source-code-theft/">EmberForge Source Code Theft</a></h2>
        <p>
          A multi-stage intrusion that began on an artist workstation and expanded to a server and Domain Controller. The case follows ISO-based execution, DLL launch through <code>rundll32.exe</code>, UAC bypass, LSASS dumping, lateral movement, shadow-copy abuse to access <code>ntds.dit</code>, and exfiltration to MEGA using <code>rclone.exe</code>.
        </p>
      </section>

      <section class="panel">
        <p class="panel-label">Latest Investigation</p>
        <h3><a href="/investigations/mfa-fatigue-bec-m365/">MFA Fatigue BEC in Microsoft 365</a></h3>
        <p>
          A business email compromise that began with repeated MFA prompts against a finance employee and ended in a fraudulent payment redirection attempt.
        </p>
      </section>
    </div>
  </section>
</div>
