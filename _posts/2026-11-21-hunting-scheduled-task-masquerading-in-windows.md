---
layout: post
title: "Hunting Scheduled Task Masquerading in Windows"
description: "One missing letter exposed a lookalike Windows task. I used Elastic to connect an RDP session, network reconnaissance, and suspicious execution on a SQL server."
card_description: "One missing letter gave away a lookalike Windows task. I followed the trail in Elastic."
date: 2026-11-21
category: "Incident analysis"
tags: [Windows, Threat Hunting, Scheduled Tasks, Elastic, DFIR]
permalink: /articles/hunting-scheduled-task-masquerading-in-windows/
thumbnail: /assets/images/windows-task-masquerading/windows-task-masquerading-cover.png
card_thumbnail: /assets/images/windows-task-masquerading/windows-task-masquerading-cover.webp
thumbnail_alt: "Blue Windows logo wearing black round glasses and a curled moustache"
---

*The Guarded Kernel · Incident analysis · Research reviewed 21 November 2026*

## Scenario

Alliance had recently started forwarding Windows logs to Elastic. Coverage varied by host and channel, and some local logs rolled over before they could be collected. I started with a hypothesis that someone had created or changed a scheduled task with a name close enough to an existing task to escape a quick review.

Two names in Task Scheduler differed by one letter. A separate process audit on the SQL server recorded an executable with a plausible backup name running from Public Pictures. I worked backward from those observations to a workstation RDP session and a network scanner. All times in this article are **UTC**.

## Attack chain

On 9 June 2026, the earliest retained activity for the RDP session was on **ALLIANCE-WS07**. The session recorded the client hostname **`kali`**, and a PowerShell script and process creation event showed that SoftPerfect Network Scanner was downloaded and launched on the workstation. That evening, a Security audit recorded two starts of `SQLBackup.exe` on **ALLIANCE-CENTRAL** with **`ALLIANCE\john.shepard`** as the target account. The workstation's scanner launch recorded the same username as the creator.

The lookalike task appears in a separate **15 June** record on the SQL server. The captured events leave the route between the hosts, the task creation time, and the task action unresolved.

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/attack-chain.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the attack chain at full size">
    <img src="{{ '/assets/images/windows-task-masquerading/attack-chain.png' | relative_url }}" alt="Timeline of an RDP session from kali, NetScan execution on ALLIANCE-WS07, SQLBackup.exe execution on ALLIANCE-CENTRAL, and a later skipped launch of a lookalike task. Dashed links mark unresolved relationships." width="1800" height="954" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 1 — The dashed connectors mark the unknown route to the SQL server and the unconfirmed link between the lookalike task and SQLBackup.exe. The PowerShell label shows the search window visible in the capture. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

| Date and time (UTC) | Host | Observed event |
| --- | --- | --- |
| 9 Jun 12:41:09.624 | ALLIANCE-WS07 | Security `4688` records `TSTheme.exe` for logon ID `0x7b9417`. `rdpclip.exe` follows at `12:41:09.821`. |
| 9 Jun 12:41:09.833 | ALLIANCE-WS07 | Two Sysmon `13` writes record `SESSIONNAME = RDP-Tcp#0` and `CLIENTNAME = kali`. |
| 9 Jun 12:54–12:57 | ALLIANCE-WS07 | The captured PowerShell `4104` search window contains the NetScan download, extract, and launch script. |
| 9 Jun 12:55:28.050 | ALLIANCE-WS07 | Security `4688` records the start of `netscan.exe` with `John.shepard` as creator. |
| 9 Jun 22:37:53.015 and .280 | ALLIANCE-CENTRAL | Two Security `4688` records name `SQLBackup.exe` in Public Pictures and `ALLIANCE\john.shepard` as target. |
| 15 Jun 14:10:24.329 | ALLIANCE-CENTRAL | Task Scheduler `332` records a skipped launch of `\SQLConnectvityCheck`. |

## Step-by-step threat hunt

### 1. Group Task Scheduler events by exact name

I used the historical event window in Discover and scoped the search to `Microsoft-Windows-TaskScheduler/Operational`. The initial rows were dominated by normal Windows activity. Grouping by exact task name gave me one row per name, a host count, and any recorded action. I reviewed the tasks seen on two hosts or fewer first. Host rarity helped rank the results for inspection.

```esql
FROM logs-*
| WHERE winlog.channel == "Microsoft-Windows-TaskScheduler/Operational"
  AND winlog.event_data.TaskName IS NOT NULL
| STATS events = COUNT(*),
        hosts = COUNT_DISTINCT(winlog.computer_name),
        actions = VALUES(winlog.event_data.ActionName)
  BY task = winlog.event_data.TaskName
| WHERE hosts <= 2
| SORT hosts ASC, events ASC, task ASC
| LIMIT 1000
```

The reference task is `\SQLConnectivityCheck`. The suspicious one is `\SQLConnectvityCheck`, with the first `i` after `Connect` removed. Each name appeared once in the grouped results. The spelling difference gave me a candidate to verify against the original events. [Elastic ES&#124;QL documentation][esql]

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/task-name-comparison.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the side-by-side task name comparison">
    <img src="{{ '/assets/images/windows-task-masquerading/task-name-comparison.png' | relative_url }}" alt="Discover aggregation showing SQLConnectivityCheck and SQLConnectvityCheck on adjacent rows, with the missing letter annotated." width="2497" height="1025" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 2 — Grouping by task name puts both spellings side by side. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Filtering on the two names put the lookalike on **ALLIANCE-CENTRAL** at **14:10:24.329 on 15 June**, with event `332`. That event means Task Scheduler skipped a launch because the user was logged off when the conditions were met. The reference name appears on **ALLIANCE-WS07** at **14:14:36.760** with event `153`. The `332` record establishes the lookalike's presence on the server. The task definition and the action it would have run remain unknown. [Task Scheduler event reference][task-events]

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/task-scheduler-events.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Task Scheduler event evidence">
    <img src="{{ '/assets/images/windows-task-masquerading/task-scheduler-events.png' | relative_url }}" alt="Two raw Task Scheduler rows. Event 332 names SQLConnectvityCheck on ALLIANCE-CENTRAL at 14:10:24.329 and event 153 names SQLConnectivityCheck on ALLIANCE-WS07." width="1576" height="640" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 3 — The raw events identify the host, time, and event code for each spelling. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### 2. Pivot to process creation on the SQL server

I searched Security event `4688` for executable paths containing `SQL`. Most paths around the hit pointed into installed SQL Server or SQL Server Management Studio directories. One pointed into Public Pictures. Two events on **ALLIANCE-CENTRAL** recorded that executable starting a quarter of a second apart on 9 June. [Microsoft event 4688 reference][event-4688]

```esql
FROM logs-*
| WHERE event.code == "4688"
  AND process.executable LIKE "*SQL*.exe"
| KEEP @timestamp, host.name, process.executable, message
| SORT @timestamp ASC
| LIMIT 1000
```

The full path was **`C:\Users\Public\Pictures\SQLBackup.exe`**. Its name matches the SQL theme, and its location gives me a concrete reason to investigate. The process records establish execution. A task action, task-instance ID, or equivalent linkage would be needed to establish what launched it.

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/sqlbackup-process-path.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the SQLBackup process path evidence">
    <img src="{{ '/assets/images/windows-task-masquerading/sqlbackup-process-path.png' | relative_url }}" alt="Two SQLBackup.exe starts from the Public Pictures folder among process events for normally installed SQL tools." width="2273" height="848" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 4 — The executable name fits the server’s role. Its path stands out against the surrounding SQL process events. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### 3. Reconstruct the RDP session

On **ALLIANCE-WS07**, I traced logon ID `0x7b9417` backward from the scanner process through subject and target logon fields. I kept the search on the workstation because the ID is local to the host. The earliest matching event was `TSTheme.exe` at **12:41:09.624**, followed by `rdpclip.exe` and `sihost.exe`. This is the earliest retained session activity I could place, based on process creation. [Microsoft logon correlation guidance][event-4624]

```esql
FROM logs-*
| WHERE winlog.computer_name LIKE "ALLIANCE-WS07*"
  AND (TO_LOWER(winlog.event_data.SubjectLogonId) == "0x7b9417"
    OR TO_LOWER(winlog.event_data.TargetLogonId) == "0x7b9417"
    OR TO_LOWER(message) LIKE "*0x7b9417*")
| KEEP @timestamp, event.code, winlog.computer_name, process.executable, message
| SORT @timestamp ASC
| LIMIT 50
```

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/rdp-session-processes.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the RDP session process events">
    <img src="{{ '/assets/images/windows-task-masquerading/rdp-session-processes.png' | relative_url }}" alt="Earliest process creation records for logon ID 0x7b9417 on ALLIANCE-WS07, beginning with TSTheme.exe and rdpclip.exe." width="2012" height="777" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 5 — The first retained session activity appears in Security process creation events. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Sysmon registry telemetry supplied the client hostname. Two event `13` records at **12:41:09.833** write to the same user's `Volatile Environment\2` key. `SESSIONNAME` records `RDP-Tcp#0` and `CLIENTNAME` records **`kali`**. This establishes the recorded client name. The source IP and client operating system remain unknown. [Microsoft Sysmon event reference][sysmon]

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/rdp-client-registry.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the RDP client name registry evidence">
    <img src="{{ '/assets/images/windows-task-masquerading/rdp-client-registry.png' | relative_url }}" alt="Two Sysmon registry value writes at 12:41:09.833 showing SESSIONNAME RDP-Tcp#0 and CLIENTNAME kali." width="2100" height="694" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 6 — The RDP session and client name are visible in registry telemetry from the workstation. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### 4. Recover the reconnaissance script and confirm the launch

On the workstation, I narrowed PowerShell event `4104` to **12:54–12:57**. The script block uses `Invoke-WebRequest` to retrieve the portable SoftPerfect Network Scanner archive, extracts it into `C:\Users\Public\SoftPerfect`, and invokes the 64-bit `netscan.exe`. The process creation event at **12:55:28.050** corroborates the launch. The captures leave any subsequent scan targets or results unknown. [PowerShell script-block logging][powershell]

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/powershell-netscan-script.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the PowerShell script block evidence">
    <img src="{{ '/assets/images/windows-task-masquerading/powershell-netscan-script.png' | relative_url }}" alt="PowerShell event 4104 shows the SoftPerfect Network Scanner download, archive extraction, and executable invocation." width="2553" height="939" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 7 — The script block records the download and launch instructions. The process audit supplies the observed execution time. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### 5. Compare the account fields across both hosts

I put the events for both executables in one table. In the workstation row, `John.shepard` appears in `SubjectUserName`. On the SQL server, the two `SQLBackup.exe` rows list `ALLIANCE-CENTRA$` in that creator field and `ALLIANCE\john.shepard` in the target fields. The distinction matters because Security event `4688` can record a new process running under an account different from the creator. Combined with the RDP session evidence, this makes **`ALLIANCE\john.shepard`** the account I would investigate first. The captures leave how the credentials were obtained and how access reached the SQL server unresolved. [Microsoft event 4688 reference][event-4688]

<figure class="article-figure">
  <a href="{{ '/assets/images/windows-task-masquerading/account-across-hosts.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the process and account comparison">
    <img src="{{ '/assets/images/windows-task-masquerading/account-across-hosts.png' | relative_url }}" alt="Process creation rows showing John.shepard as creator of netscan.exe and ALLIANCE john.shepard as target account of SQLBackup.exe." width="2483" height="729" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 8 — The workstation record shows the creator username. The SQL server records show the explicit target domain and username. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## Mitigation

- **Contain the hosts and account.** Isolate the workstation and coordinate SQL server containment with the service owner. Revoke active sessions for the affected account, reset its credentials, and review recent sign-ins, group membership, and access to other hosts.
- **Preserve the task and executable before removal.** Collect the task definition, Task Scheduler and Security logs, the executable with its hash, and relevant EDR history. Review the configured action, trigger, and account before disabling the task and quarantining the executable.
- **Reduce the execution opportunity.** Restrict RDP to approved administrative paths. Review where the account can sign in and run jobs. Use application control to limit execution from user-writable locations, starting in audit mode where the server workload needs compatibility testing. [Microsoft App Control for Business][app-control]
- **Fix collection and retention.** Forward Task Scheduler Operational events and enable audit coverage for task creation, updates, and process creation. Retain PowerShell and Sysmon telemetry centrally. Check coverage by host and channel so an empty query can be interpreted against the collection state. [Microsoft Windows Event Forwarding guidance][wef]

## Artifacts and IOCs

| Artifact | Value | How to use it |
| --- | --- | --- |
| Lookalike task | `\SQLConnectvityCheck` | Search exact spelling on Windows hosts. |
| Reference task | `\SQLConnectivityCheck` | Compare names and actions against the approved baseline. |
| Suspicious executable | `C:\Users\Public\Pictures\SQLBackup.exe` | Hunt by full path and collect the file hash if available. |
| Account | `ALLIANCE\john.shepard` | Pivot across logons and process creator and target fields. |
| RDP client hostname | `kali` | Correlate with the affected workstation and session time. |
| Workstation logon ID | `0x7b9417` | Correlate session events on `ALLIANCE-WS07`. |
| Reconnaissance tool | `netscan_portable.zip` and `C:\Users\Public\SoftPerfect\x86_64\netscan.exe` | Scope the legitimate tool's use to the account, host, and time. |

The archive was fetched from the legitimate vendor site, `www.softperfect.com/download/files/netscan_portable.zip`. The account, location, and associated execution make it relevant to this investigation. [SoftPerfect Network Scanner product page][softperfect]

## Detection

**Task name and behavior.** Compare new and modified task names with the approved inventory for each host role. A one-character edit becomes more meaningful when the task also appears on an unexpected host or its action points into a user-writable directory. Collect Security `4698` and `4702` for task definitions and use Task Scheduler Operational events to cover run and skip activity. Treat a `332` match as evidence of the skipped trigger. The naming pattern maps to **Masquerade Task or Service (T1036.004)**. Scheduled task execution is the **T1053.005** behavior to investigate. [Microsoft task audit events][event-4698] · [Elastic scheduled task detection][elastic-task] · [MITRE ATT&CK task masquerading][mitre-masquerade] · [MITRE ATT&CK scheduled task][mitre-task]

**Process execution from Public Pictures.** Use an ES&#124;QL search like the one below to surface executables starting in that folder. Start with servers and review the parent image, signer, account, and host role before tuning an alert. This is a hunt query for the observed path pattern.

```esql
FROM logs-*
| WHERE event.code == "4688"
  AND STARTS_WITH(TO_LOWER(process.executable), "c:\\users\\public\\pictures\\")
  AND ENDS_WITH(TO_LOWER(process.executable), ".exe")
| KEEP @timestamp, winlog.computer_name, process.executable,
       winlog.event_data.SubjectUserName, winlog.event_data.TargetUserName
| SORT @timestamp DESC
```

**RDP followed by reconnaissance.** Correlate a remote session and a scanner launch on the same host within a short window. Prefer a matching logon ID, and use approved scanning hosts and accounts to reduce noise. On this workstation, the scanner launched about 14 minutes after the earliest observed session process. The PowerShell and registry records add context when Security logon coverage is incomplete.

## Sources

- Hack The Box lab telemetry and scenario. The evidence figures are from my Kibana investigation.
- Event semantics and log correlation. [Microsoft Security event 4688][event-4688] · [Event 4624][event-4624] · [Task creation 4698][event-4698] · [Task update 4702][event-4702] · [Task Scheduler event IDs][task-events] · [Sysmon][sysmon] · [PowerShell logging][powershell]
- Search and detection references. [Elastic ES&#124;QL in Kibana][esql] · [Elastic scheduled task creation rule][elastic-task] · [MITRE T1036.004][mitre-masquerade] · [MITRE T1053.005][mitre-task]
- Diagram icons and scanner context. [Kali Linux][kali-icon] · [SoftPerfect Network Scanner][softperfect] · [SQL Server icon via Devicon][sql-icon]

[event-4688]: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
[event-4624]: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
[event-4698]: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
[event-4702]: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702
[task-events]: https://dahall.github.io/TaskScheduler/html/T_Microsoft_Win32_TaskScheduler_StandardTaskEventId.htm
[sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-13-registryevent-value-set
[powershell]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
[app-control]: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol
[wef]: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
[esql]: https://www.elastic.co/guide/en/elasticsearch/reference/8.19/esql-kibana.html
[elastic-task]: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_scheduled_task_creation_winlog
[mitre-masquerade]: https://attack.mitre.org/techniques/T1036/004/
[mitre-task]: https://attack.mitre.org/techniques/T1053/005/
[softperfect]: https://www.softperfect.com/products/networkscanner/
[kali-icon]: https://www.kali.org/images/kali-dragon-icon.svg
[sql-icon]: https://github.com/devicons/devicon/blob/master/icons/microsoftsqlserver/microsoftsqlserver-original.svg
