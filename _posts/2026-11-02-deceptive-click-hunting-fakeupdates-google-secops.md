---
layout: post
title: "Deceptive Click: Hunting FAKEUPDATES in Google SecOps"
description: "A Google SecOps investigation from a fake Chrome update and JavaScript execution to a Kerberos ticket request, service-account activity and an archive on a file server."
date: 2026-11-02 10:00:00 +0100
category: "Incident analysis"
tags: [FAKEUPDATES, Google SecOps, Threat Hunting, YARA-L, Detection Engineering]
permalink: /articles/deceptive-click-fakeupdates/
thumbnail: /assets/images/deceptive-click/deceptive-click-hero.png
thumbnail_alt: "Google SecOps and FAKEUPDATES article artwork showing a deceptive Chrome update prompt"
---

*The Guarded Kernel · Incident analysis · Research reviewed: 2 November 2026*

A browser update is an easy thing to trust. In **Deceptive Click**, the apparent update led from a third-party blog to a ZIP download, a JavaScript file and hidden PowerShell. The first alert described a download-and-execute command. The useful investigation began when I worked backwards to the web request and then forwards to the file server.

This was one of the simulated incidents in [Operation Cymbal: Cold Room][event], a Google Cloud Security Community capture-the-flag event hosted with Hack The Box. I investigated the Cymbal Investments environment in **Google Security Operations (Google SecOps)**. The events in the case occurred on **15 October 2026**; the community event ran **29 October–1 November 2026**.

Google Threat Intelligence's supplied *FAKEUPDATES Malware Profile* (23 July 2024) gave me a hypothesis: compromised sites can present fake browser updates and deliver a JavaScript dropper. The PDF was a local export and has no public link, so I do not redistribute it here. [Mandiant's public FAKEUPDATES research][mandiant] documents the same broad delivery pattern. The profile helped me decide what to search for; the case logs had to establish what happened in this environment.

**Scope:** one exercise incident, reconstructed from Google SecOps case data, Zscaler proxy events, Sysmon and Windows Security logs. The figures show selected events, not a full forensic image. I label deductions that the supplied telemetry cannot prove.

## 1. Why Google SecOps helped this hunt

Google SecOps normalizes different sources into the **Unified Data Model (UDM)**. That let me move from a case alert to `PROCESS_LAUNCH`, `NETWORK_HTTP`, `USER_LOGIN` and `FILE_CREATION` events without learning a separate search language for each log source. I could still expand the original event fields when the normalized result lacked detail. This was especially useful when correlating Zscaler web traffic with Sysmon process activity and Windows authentication records. [Google's UDM Search guide][udm-search] describes that normalization and search workflow.

The platform also has a [Gemini-assisted search][gemini-search]: an analyst can describe a question in English and review the generated query before running it. Gemini can help draft searches and summarize results, but the output still needs field-level checking. **I wrote the queries below manually**; I did not use a generated query as evidence. The practical value in this case was having the case, normalized searches, raw event detail and threat-intelligence context close together. That is a workflow observation, not a claim that these capabilities are exclusive to Google SecOps.

One small lesson came early. Searching all `NETWORK_HTTP` events across the entire time range produced too many unrelated hits. Adding the **Cymbal namespace**, a tight time window and eventually an exact URL made the proxy evidence reviewable.

## 2. The attack chain

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/deceptive-click-attack-chain.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Deceptive Click attack-chain diagram at full size">
    <img src="{{ '/assets/images/deceptive-click/deceptive-click-attack-chain.png' | relative_url }}" alt="Attack-chain diagram from a referred fake Chrome-update ZIP through JavaScript, PowerShell, a SYSTEM process interaction, a Kerberos ticket request, service-account access and file-server archive creation." width="5120" height="4373" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 1 — Reconstructed Deceptive Click chain. The links from the blog to injected content and from the ticket request to a cracked password remain hypotheses; the ZIP's creation is observed, but exfiltration is not. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The first confirmed web step was a GET for `ChromeSetup_v124.zip` from `static.cdn-updater-distribution.net`. Its HTTP referral URL was `https://marketingtrends-insider.com/`. A `ChromeSetup.js` file then appeared on the Denver workstation, where `wscript.exe` launched hidden PowerShell. PowerShell fetched a `.png` URL, saved the response as `d27e15eb.exe` and started that file.

A later Sysmon event records the executable creating a remote thread in a SYSTEM-owned `svchost.exe`. The host then shows discovery commands and a Kerberos service-ticket request. The next strong identity pivot is a `svc_backup` logon from the Denver endpoint toward the file server, followed by creation of `Financial_Audit_2026.zip` there. These are **observed stages and correlations**; they do not by themselves show the ZIP's contents or an outbound transfer.

## 3. How I found it

I used **15 October 2026, approximately 19:30–21:15 UTC** as the search range. Some result rows displayed local time one hour ahead of the raw event timestamp, so the times below use raw UTC fields where available. Each query is a way to retrieve the event; the expanded fields in the screenshots are the evidence.

### Start with the case, then fix the endpoint

The *PowerShell Download and Execute* case pointed to a process launched by `wscript.exe`. I pivoted to the endpoint, `CYM-DEN-W10-042.cymbal.corp`, to see activity before and after the alert:

```text
principal.hostname = "CYM-DEN-W10-042.cymbal.corp"
```

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/denver-host-timeline.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Denver endpoint timeline at full size">
    <img src="{{ '/assets/images/deceptive-click/denver-host-timeline.png' | relative_url }}" alt="Google SecOps host search showing ChromeSetup.js creation, wscript and PowerShell launches, payload activity and later discovery commands on the Denver workstation." width="2458" height="1202" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 2 — The endpoint timeline joined the alert to the earlier script and later discovery events. Result-row times are local display times, so I checked raw timestamps before building the timeline. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The Sysmon process-launch record at **19:55:50Z** gave the decisive parent-child link: `wscript.exe` running `ChromeSetup.js` launched PowerShell with a hidden window. The command downloaded `https://static.cdn-updater-distribution.net/assets/d27e15eb.png`, wrote it to `C:\Users\marcus.vance\AppData\Local\Temp\d27e15eb.exe`, then called `Start-Process` on that executable. The `.png` extension in the URL did not determine the saved file type or prove the response was an image.

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/powershell-alert.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the PowerShell alert at full size">
    <img src="{{ '/assets/images/deceptive-click/powershell-alert.png' | relative_url }}" alt="Google SecOps PowerShell Download and Execute alert associated with the wscript-to-PowerShell process launch." width="2484" height="1243" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 3 — The alert was the entry point for the hunt. The command line and parent process came from the expanded Sysmon Event ID 1 record, not from the alert title alone. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### Work backwards to the fake update

I narrowed the proxy search to the archive URL seen in the web activity:

```text
metadata.event_type = "NETWORK_HTTP" and namespace = "Cymbal" and target.url = "https://static.cdn-updater-distribution.net/releases/ChromeSetup_v124.zip"
```

The selected **19:41:59Z** GET identifies `marcus.vance`, client IP `10.240.32.115`, the ZIP URL and `network.http.referral_url = "https://marketingtrends-insider.com/"` in **the same event**. That is stronger than finding the blog and ZIP in separate searches. It makes `marketingtrends-insider.com` the observed referring domain. It does **not** independently show the blog's HTML, an injected script or the actual click.

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/proxy-update-archive-exact-query.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the exact proxy archive query and referral at full size">
    <img src="{{ '/assets/images/deceptive-click/proxy-update-archive-exact-query.png' | relative_url }}" alt="Exact Google SecOps proxy search showing the ChromeSetup ZIP URL, GET method, user and marketingtrends-insider.com referral URL on one event." width="2537" height="1452" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 4 — Exact archive GET with `target.url` and `network.http.referral_url` expanded. The referral supports the entry-path assessment; it is not proof of a compromised website by itself. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### Follow the network and process evidence forward

With `metadata.event_type = "NETWORK_HTTP" and namespace = "Cymbal"` over a tighter window, I found a **19:49:17Z POST** to `https://sdce.distributors.commdistinc.com/editContent`. The supplied GTI profile lists that host and path as a representative FAKEUPDATES destination. The match is useful family context, although the request body and malware sample were not available to verify the communication independently. For a repeatable search after discovery, I would use:

```text
metadata.event_type = "NETWORK_HTTP" and namespace = "Cymbal" and target.url = "https://sdce.distributors.commdistinc.com/editContent"
```

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/proxy-c2-post.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the proxy editContent event at full size">
    <img src="{{ '/assets/images/deceptive-click/proxy-c2-post.png' | relative_url }}" alt="Zscaler proxy event at 19:49:17 UTC showing the sdce.distributors.commdistinc.com editContent destination." width="2551" height="1289" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 5 — The `/editContent` destination and event time. The <a href="{{ '/assets/images/deceptive-click/proxy-c2-http-method.png' | relative_url }}" target="_blank" rel="noopener">expanded HTTP field</a> records the `POST` method; the request body was not supplied. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Next, I searched for the temporary executable as a Sysmon source process and `svchost.exe` as the target:

```text
metadata.log_type = "WINDOWS_SYSMON" and principal.process.file.full_path = /d27e15eb\.exe/ nocase and target.process.file.full_path = /svchost\.exe/ nocase
```

The **20:03:45Z Sysmon Event ID 8** records `d27e15eb.exe` creating a remote thread in `C:\Windows\System32\svchost.exe`, **PID 624**, running as `NT AUTHORITY\SYSTEM`. The event carries a *Process Hollowing* rule label. Event ID 8 establishes the cross-process action and target identity; it does not, on its own, show every step of hollowing or prove that the attacker obtained a SYSTEM token.

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/sysmon-process-injection.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Sysmon process interaction at full size">
    <img src="{{ '/assets/images/deceptive-click/sysmon-process-injection.png' | relative_url }}" alt="Sysmon Event ID 8 showing d27e15eb.exe as source and SYSTEM svchost.exe PID 624 as target." width="2441" height="1024" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 6 — Source executable and SYSTEM-owned target process. The event's technique label is a detection interpretation; the remote-thread record is the underlying observation. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### Connect the domain activity to the file server

The endpoint timeline showed `net.exe` and `nltest.exe` launches around **20:29–20:32Z**. Their full arguments were not visible in the supplied screenshot. A Windows Security **4769** event at **20:35:37Z** then recorded a TGS request for `MSSQLSvc/CYM-DB-01.cymbal.corp:1433`:

```text
metadata.product_event_type = "4769" and namespace = "Cymbal"
```

This is consistent with the scenario's Kerberoasting stage, but **one TGS request cannot prove offline cracking** or tell us which account owns the SPN.

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/kerberos-tgs-request.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Kerberos service-ticket event at full size">
    <img src="{{ '/assets/images/deceptive-click/kerberos-tgs-request.png' | relative_url }}" alt="Windows Security Event 4769 in Google SecOps showing the full MSSQLSvc service principal name in target.application." width="2459" height="1138" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 7 — The full SPN in `target.application`. The ticket request is observed; password recovery is not. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The next query found a **20:48:45Z Security 4624** event for `svc_backup`:

```text
metadata.product_event_type = "4624" and namespace = "Cymbal" and target.user.userid = "svc_backup"
```

Its expanded fields show source `CYM-DEN-W10-042` / `10.240.32.115` and intermediary `CYM-FS-01.cymbal.corp`. That source IP matches the earlier archive GET. The event supports use of `svc_backup` along a Denver-to-file-server route, though the screenshot does not expose the logon type or prove where the credential came from.

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/svc-backup-logon-event.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the service-account logon at full size">
    <img src="{{ '/assets/images/deceptive-click/svc-backup-logon-event.png' | relative_url }}" alt="Security Event 4624 showing svc_backup, Denver source hostname and IP, and the CYM-FS-01 file-server intermediary." width="2465" height="1368" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 8 — The service-account logon with source and intermediary fields expanded. It does not establish that `svc_backup` owns the earlier MSSQL SPN. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Finally, a Sysmon **Event ID 11** on the file server shows `svc_backup` creating `C:\Windows\Temp\Financial_Audit_2026.zip` at **21:08:35Z**:

```text
metadata.event_type = "FILE_CREATION" and namespace = "Cymbal" and target.file.full_path = /\.zip$/ nocase
```

<figure class="article-figure">
  <a href="{{ '/assets/images/deceptive-click/file-server-archive-creation.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the file-server archive event at full size">
    <img src="{{ '/assets/images/deceptive-click/file-server-archive-creation.png' | relative_url }}" alt="Sysmon Event ID 11 on CYM-FS-01 showing svc_backup creating Financial_Audit_2026.zip in Windows Temp." width="2249" height="1052" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 9 — The archive path, creator and file-server host. The name suggests financial-audit data; the contents and any exfiltration remain unverified. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## 4. Detection: turn the hunt into layers

The hunt suggests **three different detection layers**. An exact C2 URL is a useful high-precision lead for this case, but an adversary can rotate infrastructure. The process chain is more portable, but legitimate administrative scripts can also launch PowerShell. The remote-thread event is a strong post-execution signal, with different possible causes. I would deploy them only after checking the local parser fields and testing against normal activity. These are **YARA-L 2.0 drafts, not rules I ran or deployed in the Cymbal tenant**. Google's [single-event rule examples][yara-examples], [regex reference][regex] and [Sysmon mappings][sysmon-mapping] informed their structure.

**Layer 1 — known FAKEUPDATES destination.** Start with the observed POST URL. This is an indicator rule with limited life; investigate a hit and keep the destination list maintained.

```yara
rule fakeupdates_known_editcontent_post {
  meta:
    author = "The Guarded Kernel"
    description = "POST to the FAKEUPDATES URL observed in Deceptive Click"
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.target.url = "https://sdce.distributors.commdistinc.com/editContent"
    $e.network.http.method = "POST"
  condition:
    $e
}
```

**Layer 2 — script host to download-and-execute PowerShell.** The parent and child images give the command-line terms context. Test exclusions for trusted software deployment and signed administrative scripts; do not suppress the entire pattern merely because PowerShell is common.

```yara
rule wscript_powershell_download_execute {
  meta:
    author = "The Guarded Kernel"
    description = "Wscript launches PowerShell to download and start a file"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /\\wscript\.exe$/ nocase
    $e.target.process.file.full_path = /\\powershell\.exe$/ nocase
    $e.target.process.command_line = /(iwr|Invoke-WebRequest)/ nocase
    $e.target.process.command_line = /-OutFile/ nocase
    $e.target.process.command_line = /Start-Process/ nocase
  condition:
    $e
}
```

**Layer 3 — temporary executable entering `svchost.exe`.** Sysmon Event ID 8 captures remote-thread creation. This rule should be investigated as cross-process activity, with process identity, signer, path and surrounding events; the event alone is not a process-hollowing verdict.

```yara
rule temp_exe_remote_thread_svchost {
  meta:
    author = "The Guarded Kernel"
    description = "Temporary executable creates a remote thread in svchost"
    severity = "HIGH"
  events:
    $e.metadata.log_type = "WINDOWS_SYSMON"
    $e.metadata.product_event_type = "8"
    $e.principal.process.file.full_path = /\\Temp\\[^\\]+\.exe$/ nocase
    $e.target.process.file.full_path = /\\svchost\.exe$/ nocase
  condition:
    $e
}
```

For each draft, I would first confirm the field mappings in the tenant, run it over the known incident window, and compare matches with a benign baseline. Only then would I tune severity and consider a [historical rule run][historical-rules] or live alerting. A further correlation could join the workstation event to a service-account logon and file-server ZIP creation, but that requires reliable host and identity joins; the single-event examples above make no such claim.

## What this case taught me

The proxy referral turned a PowerShell alert into an entry-path hypothesis. The same UDM workflow then tied a script on one workstation to a SYSTEM-process interaction, a Kerberos ticket request and activity under another identity on a file server. The strongest conclusion is **archive creation after a suspicious chain**. To claim a compromised blog, cracked service password or completed data theft, I would need the blog content, authentication details, archive manifest and outbound-transfer evidence.

That distinction is the point of the hunt: use threat intelligence to ask better questions, then let the logs set the strength of each answer.

### Sources

- [Google Cloud Security Community: Operation Cymbal: Cold Room][event] — event and exercise context.
- Google Threat Intelligence, *FAKEUPDATES Malware Profile*, 23 July 2024 — supplied local PDF; no public URL and not reproduced here.
- [Mandiant: Head Fake: Tackling Disruptive Ransomware Attacks][mandiant] — public FAKEUPDATES delivery context.
- [Google SecOps: Understand search][udm-search] and [Generate search queries with Gemini][gemini-search] — platform behavior.
- [Google SecOps: YARA-L examples][yara-examples], [regex reference][regex], [Sysmon parser mappings][sysmon-mapping] and [historical rule runs][historical-rules] — detection syntax and validation workflow.

[event]: https://security.googlecloudcommunity.com/events/community-capture-the-flag-with-hack-the-box-operation-cymbal-cold-room-141
[mandiant]: https://cloud.google.com/blog/topics/threat-intelligence/head-fake-tackling-disruptive-ransomware-attacks
[udm-search]: https://docs.cloud.google.com/chronicle/docs/investigation/udm-search
[gemini-search]: https://docs.cloud.google.com/chronicle/docs/investigation/generate-udm-search-queries-gemini
[yara-examples]: https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples
[regex]: https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-functions/re-regex
[sysmon-mapping]: https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/windows-sysmon
[historical-rules]: https://docs.cloud.google.com/chronicle/docs/detection/run-rule-historical-data
