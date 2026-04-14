---
title: "Home"
layout: default
permalink: /
---

<div class="hero-wrap">
  <section class="hero-card hero-card-split">
    <div class="hero-grid-uneven">
      <div class="hero-left">
        <p class="signal-badge">// EVIDENCE_INBOUND //</p>

        <h1 class="hero-title">TRACK <span class="accent">ATTACK</span> CHAINS</h1>

        <div class="hero-callout">
          Threat hunting and incident response case files built around timelines, pivots, evidence, and the reasoning that moved each investigation forward.
        </div>

        <p class="hero-intro hero-intro-tight">
          This site collects technical write-ups designed to show process, not just conclusions. Each case follows the evidence and tries to make the investigative thread easy to retrace.
        </p>

        <div class="button-row">
          <a class="button-link" href="/investigations/">Browse investigations</a>
        </div>

        <ul class="compact-list">
          <li>Attack-chain walkthroughs grounded in case evidence</li>
          <li>Clear pivots showing how one finding led to the next</li>
          <li>Technical write-ups built for learning and review</li>
        </ul>
      </div>

      <aside class="hero-right">
        <section class="panel right-rail-card">
          <p class="panel-label">Featured Investigation</p>
          <h2><a href="/investigations/emberforge-source-code-theft/">EmberForge Source Code Theft</a></h2>
          <p>
            Multi-stage intrusion involving ISO-based execution, <code>rundll32.exe</code>, UAC bypass, LSASS dumping, lateral movement, shadow-copy abuse, and exfiltration to MEGA.
          </p>
          <a class="text-link" href="/investigations/emberforge-source-code-theft/">Open case</a>
        </section>

        <section class="panel right-rail-card">
          <p class="panel-label">Latest Investigation</p>
          <h3><a href="/investigations/mfa-fatigue-bec-m365/">MFA Fatigue BEC in Microsoft 365</a></h3>
          <p>
            Business email compromise involving MFA fatigue, inbox rule abuse, internal payment fraud attempts, and attacker cloud activity tied to the same session.
          </p>
          <a class="text-link" href="/investigations/mfa-fatigue-bec-m365/">Open case</a>
        </section>
      </aside>
    </div>
  </section>
</div>
