---
layout: post
title: "Tracking Winnti: From Threat Intelligence to Detection"
description: "A visual investigation of Winnti, RevivalStone, related campaigns, and practical detection opportunities."
date: 2026-10-24 12:00:00 +0200
category: "Threat intelligence"
tags: [APT41, Winnti, RevivalStone, MITRE ATT&CK, Detection Engineering]
permalink: /articles/tracking-winnti/
thumbnail: /assets/images/tracking-winnti/apt41logo.png
thumbnail_alt: "APT41 emblem"
---

*The Guarded Kernel · Threat intelligence · Research reviewed: 24 October 2026*

Manufacturing and energy companies hold information that can take years to develop: designs, formulas, research and production knowledge. Understanding the attackers interested in that information gives defenders a useful starting point for deciding what to monitor.

After completing Hack The Box's **KitsuneHook** Sherlock, I followed the research behind the questions. This article connects the actor names, selected campaigns and technical findings to practical detection ideas.

**Scope:** an analysis of public reporting, centred on **RevivalStone**. Related cases are labelled separately. The figures are reproduced from the research credited in their captions; the detection examples are research drafts.

## 1. Who is behind the activity?

<figure class="article-figure">
  <a href="{{ '/assets/images/tracking-winnti/whoarewinnti.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 1 at full size">
    <img src="{{ '/assets/images/tracking-winnti/whoarewinnti.png' | relative_url }}" alt="LAC&#x27;s attribution diagram connects APT41 with Chengdu 404, Winnti Group, Earth Baku and Earth Freybug, with an alias relationship marked as uncertain." width="562" height="355" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 1 — LAC's view of actor relationships; the labels and question mark reflect that report's attribution model. Source: <a href="https://www.lac.co.jp/lacwatch/report/20250213_004283.html">LAC, Figure 1</a>. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

- **APT41:** MITRE tracks it as **G0096**, active since at least 2012, with state-sponsored espionage and financially motivated activity.
- **Winnti Group:** a separate ATT&CK entry, **G0044**, with activity traced to at least 2010. MITRE describes APT41's overlap with Winnti reporting as partial.
- **Blackfly:** the name used by Symantec in the materials-sector investigation discussed below.
- **Winnti malware:** software associated with this ecosystem. A malware-family name and an actor designation describe different things.

Sources: [MITRE: APT41][apt41] · [MITRE: Winnti Group][winnti] · [Symantec: Blackfly][blackfly]

Mandiant's original APT41 profile describes the combination of espionage and financially motivated operations. That does not make every intrusion in this article financially motivated: the objective needs to be assessed for the particular case.

Source: [Mandiant: APT41's dual operations][apt41-profile]

## 2. Campaigns and targeting: put dates beside the names

<figure class="article-figure">
  <a href="{{ '/assets/images/tracking-winnti/minntitimeline.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 2 at full size">
    <img src="{{ '/assets/images/tracking-winnti/minntitimeline.png' | relative_url }}" alt="A historical timeline of Winnti research, malware versions and targeted sectors from 2013 to March 2024." width="1000" height="438" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 2 — LAC's historical Winnti timeline, ending in March 2024. The reporting snapshots below also cover later publications. Source: <a href="https://www.lac.co.jp/lacwatch/report/20250213_004283.html">LAC, Figure 2</a>. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

- **Operation CuckooBees:** espionage against technology and manufacturing organizations across East Asia, Western Europe and North America. MITRE records activity from December 2019 through May 2022.
- **Blackfly:** Symantec reported attacks in late 2022 and early 2023 affecting materials and composites businesses within an Asian conglomerate.
- **Earth Freybug:** Trend Micro's January 2025 presentation separates two APAC cases spanning November 2023–October 2024.
- **RevivalStone:** Japanese manufacturing, materials and energy; observed March 2024, reported February 2025.

Sources: [MITRE: CuckooBees][cuckoo-mitre] · [Symantec][blackfly] · [Trend Micro, JSAC 2025][freybug-slides] · [LAC][revivalstone]

### Recent context: a separate 2026 report

Check Point's **3 March 2026** report describes **Silver Dragon**, active since at least mid-2024, with government organizations prominent among victims in Southeast Asia and Europe. Its assessment places the cluster **likely within the APT41 umbrella**.

- The report describes service hijacking, public-facing server exploitation and phishing.
- Its **GearDoor** backdoor uses Google Drive for C2.
- This is additional context about the broader ecosystem, with its own evidence and attribution assessment.

Source: [Check Point Research: Silver Dragon][silver-dragon]

**Date discipline:** a publication date, an observed intrusion window and a file's compilation timestamp answer different questions. A 2021 compilation timestamp can guide a historical search; it cannot establish attribution on its own. The selected reporting here is a dated research snapshot, not a complete inventory of current operations.

## 3. Inside RevivalStone


- **Entry:** ERP SQL injection.
- **Web shells:** China Chopper, Behinder and sqlmap's file uploader.
- **Expansion:** stolen maintenance credentials and an MSP pivot.

Source: [LAC: RevivalStone][revivalstone]

<figure class="article-figure">
  <a href="{{ '/assets/images/tracking-winnti/revivalstoneattackphases.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 3 at full size">
    <img src="{{ '/assets/images/tracking-winnti/revivalstoneattackphases.png' | relative_url }}" alt="RevivalStone execution flow: SessionEnv loads TSMSISrv.dll, then the loader and encrypted DAT payload, followed by the RAT and rootkit deployment." width="800" height="340" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 3 — The RevivalStone malware execution flow, from the SessionEnv service to rootkit deployment. Source: <a href="https://www.lac.co.jp/lacwatch/report/20250213_004283.html">LAC, Figure 7</a>. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The defensive questions are useful beyond this particular case:

- Which application identities can write executable content into web directories?
- Which maintenance accounts can reach more than one customer or environment?
- Can the SOC connect a web-server alert to later account activity?

These are **hunting questions derived from the reported chain**. They need local answers about permissions, logging and normal administration before they become reliable alerts.

## 4. Malware roles and technical clues

<figure class="article-figure">
  <a href="{{ '/assets/images/tracking-winnti/winntiattackckain.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 4 at full size">
    <img src="{{ '/assets/images/tracking-winnti/winntiattackckain.png' | relative_url }}" alt="The Operation CuckooBees attack life cycle, including exploitation, persistence, reconnaissance, credential dumping, lateral movement and collection." width="586" height="523" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 4 — The Operation CuckooBees attack life cycle. This historical case provides context for the component roles in the table below. Source: <a href="https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques">Cybereason, Operation CuckooBees</a>. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

| Component | Role in that investigation | Why the distinction matters |
|---|---|---|
| **PRIVATELOG** | Extracts and deploys the next payload. | Investigate the loading mechanism and its surrounding process context. |
| **DEPLOYLOG** | Deploys WINNKIT and provides a user-mode communication component. | Follow the transition between user mode and the kernel component. |
| **WINNKIT** | Kernel-level rootkit. | Host visibility can be affected; corroborate observations across data sources. |

Cybereason also describes PRIVATELOG masquerading as **prntvpt.dll** and using the **PrintNotify** service. Those historical details belong to that investigation; identical roles do not establish identical samples or deployment paths in a later case.

Source: [Cybereason: malware arsenal deep-dive][cuckoo-arsenal]


- **TreadStone:** Unit 42 found the controller name in Linux remote-control documentation from the **i-Soon leak**. Its report distinguishes the evidence from the unresolved question of who developed or supplied the tools.
- **Version inference:** LAC interpreted `StoneV5` PDB strings as suggesting **Winnti v5.0**.
- **Behinder:** its documented default key is `MD5("rebeyond")[:16]`, producing `e45e329feb5d925b`. Operators can change defaults.
- **DAT decryption:** **AES-OFB**, then ChaCha20, per LAC.

Sources: [Unit 42: i-Soon][isoon] · [LAC][revivalstone] · [Sangfor: Behinder][behinder]

For an investigation, I would record **where each clue came from**. A PDB string, a default key and a controller manual provide different kinds of evidence. A shared tool or string supports further research; it does not identify an operator by itself.

## 5. C2: three communication models


### A. RevivalStone: a listening implant

The **listening RAT** receives specially handled inbound traffic through the rootkit.

<figure class="article-figure">
  <a href="{{ '/assets/images/tracking-winnti/revivalstonekernel.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 5 at full size">
    <img src="{{ '/assets/images/tracking-winnti/revivalstonekernel.png' | relative_url }}" alt="RevivalStone communication diagram showing the user-mode RAT, kernel rootkit, Beep and Null devices, TCP/IP handlers and C2 traffic." width="800" height="434" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 5 — RevivalStone's user-mode, kernel-mode and network communication flow. Source: <a href="https://www.lac.co.jp/lacwatch/report/20250213_004283.html">LAC, Figure 8</a>. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

- **Hunting implication:** outbound beaconing is only one possible C2 pattern.
- Correlate inbound sessions with host evidence and the exposed service inventory.
- Unexpected traffic remains a lead until the underlying protocol and application context are understood.

Source: [LAC: communication flow][revivalstone]

### B. Earth Freybug: commands through Microsoft Graph

Trend Micro describes **CUNNINGPIGEON** retrieving instructions from mailbox messages through Microsoft Graph. Its configuration supports a custom proxy.

- **Hunting implication:** investigate the process, application identity and account responsible for access.
- Compare mailbox/API activity against expected software and business use.
- Seeing `graph.microsoft.com` establishes the service being contacted, not whether the activity is malicious.

Source: [Trend Micro: JSAC 2025, CUNNINGPIGEON slides][freybug-slides]

### C. Silver Dragon: tasking through Google Drive

Check Point describes GearDoor using Google Drive files for communication and tasking.

- **Hunting implication:** combine endpoint provenance with cloud and proxy records where available.
- Investigate unusual application access and unexpected automated file activity.
- Domain reputation alone provides limited context when a trusted service carries the communication.

Source: [Check Point Research: GearDoor][silver-dragon]

The shared defensive problem is **understanding who or what is using a channel**. Useful context includes the process, identity, permissions, timing and related activity on the same host.

## 6. Map the evidence to MITRE ATT&CK

This is a **selected analyst mapping**, with the supporting investigation identified in each row. It combines several cases for comparison; it does not claim that all techniques occurred in one intrusion.

<figure class="article-figure">
  <a href="{{ '/assets/images/tracking-winnti/apt41mittreframe.webp' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 6 at full size">
    <img src="{{ '/assets/images/tracking-winnti/apt41mittreframe.webp' | relative_url }}" alt="Group-IB ATT&amp;CK matrix for four APT41 campaigns observed in 2021, with techniques arranged under tactics." width="1680" height="1034" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 6 — Group-IB's mapping of four APT41 campaigns observed in 2021, published in 2022. This is historical context, separate from our selected mapping below. Source: <a href="https://www.group-ib.com/blog/apt41-world-tour-2021/">Group-IB, APT41 World Tour 2021</a>. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

| Reported behavior | ATT&CK technique | Evidence source |
|---|---|---|
| ERP exploitation | [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | [RevivalStone][revivalstone] |
| Server-side web shell | [T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/) | [RevivalStone][revivalstone] |
| A service loads an attacker-controlled DLL | [T1574.001 — DLL](https://attack.mitre.org/techniques/T1574/001/) | [CuckooBees][cuckoo-arsenal] |
| Kernel rootkit conceals activity | [T1014 — Rootkit](https://attack.mitre.org/techniques/T1014/) | [CuckooBees][cuckoo-arsenal] |
| Encrypted payload decoded before use | [T1140 — Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/) | [CuckooBees][cuckoo-arsenal] |
| Cloud service carries commands and results | [T1102.002 — Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/) | [GearDoor][silver-dragon] |
| SAM and SYSTEM hive collection | [T1003.002 — Security Account Manager](https://attack.mitre.org/techniques/T1003/002/) | [Earth Freybug][freybug-slides] |
| Collected data archived with utilities | [T1560.001 — Archive via Utility](https://attack.mitre.org/techniques/T1560/001/) | [CuckooBees][cuckoo-mitre] |

Technique IDs make the research easier to compare with detections and coverage gaps. The supporting behavior matters more than the number of techniques listed.

## 7. From reporting to detection


### Start with the telemetry

| Question | Useful data | Practical limit |
|---|---|---|
| Which process loaded the DLL? | Sysmon **7**, image-load telemetry | Collection must be configured; broad DLL logging can be noisy. |
| Was a payload written? | Sysmon **11**, EDR file events | A file-creation event does not establish execution. |
| Did a driver load? | Sysmon **6**, EDR driver telemetry | Memory-resident behavior and collection gaps require other evidence. |
| Did service-related registry data change? | Sysmon **12–14**, EDR registry events | Examine the exact operation and value; legitimate changes also occur. |
| Which process made a connection? | Sysmon **3**, EDR/network records | Network connection collection is configuration-dependent. |

Source for event semantics: [Microsoft: Sysmon][sysmon]. The investigation questions and limitations are analysis guidance.

### Example 1: a Sigma starting point

The **SessionEnv** chain provides a DLL-loading lead: `svchost.exe` and `TSMSISrv.dll`.

```yaml
title: TSMSISrv DLL Loaded by Svchost
id: 94368eb6-42a1-4a04-95f2-15374336a160
status: experimental
description: Flags a DLL-loading pattern for investigation.
author: The Guarded Kernel
date: 2026-10-24
references:
    - https://www.lac.co.jp/lacwatch/report/20250213_004283.html
tags:
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        ImageLoaded|endswith: '\TSMSISrv.dll'
    condition: selection
falsepositives:
    - Software using the same DLL name
    - Authorized security testing
level: medium
```

- **Needs:** image-load events containing `Image` and `ImageLoaded`, mapped correctly by the chosen Sigma backend.
- **Investigate:** the full module path, hash, signature, host baseline and surrounding activity. This event alone does not identify which service instance loaded the module.
- **Limit:** a renamed DLL evades this filename-based selection. A match does not establish Winnti attribution.
- **Status:** reviewed as an illustrative research rule; no SIEM conversion or operational validation was performed for this article.

Sources: [LAC][revivalstone] · [Microsoft: image-load telemetry][sysmon] · [Sigma documentation][sigma]

### Example 2: a YARA string cluster

This small derivative selects three strings from LAC's published rootkit rule:

```yara
rule TGK_Winnti_Rootkit_String_Cluster
{
    meta:
        author = "The Guarded Kernel"
        description = "Research triage; not an attribution rule"
        reference = "https://www.lac.co.jp/lacwatch/report/20250213_004283.html"
    strings:
        $protocol = "IPSecMiniPort" wide
        $driver = "NDIS.SYS" ascii
        $beep = "\\Device\\Beep" wide
    condition:
        $protocol and $driver and $beep
}
```

- **Needs:** scanning a file or memory region containing the relevant strings in those encodings.
- **Meaning:** YARA's doubled backslashes escape the literal path `\Device\Beep`; `wide` matches the UTF-16LE-style byte representation.
- **Limit:** this is broader than LAC's original rule. Unrelated driver material could match, while encrypted or changed strings could evade it.
- **Status:** illustrative and uncompiled in this workflow; it has not been tested against malware or a benign corpus. It does not reproduce LAC's full signature.

Sources: [LAC: YARA appendix][revivalstone] · [YARA: rule syntax][yara]

### Build an investigation around the alert

For either example, I would:

1. **Validate the observation:** check the original event or matched bytes.
2. **Establish context:** identify the host's role, software owner and recent approved changes.
3. **Pivot:** look for related account, process, file and network activity in the same period.
4. **Record the assessment:** explain what supports the conclusion and what evidence is still missing.

That is the part I want to carry from threat intelligence into SOC work: using a report to ask better questions, then testing those questions against the environment's own evidence.

## Download the example rules

- [Sigma: TSMSISrv DLL image-load rule]({{ '/assets/downloads/tracking-winnti/tsmsisrv-image-load.yml' | relative_url }})
- [YARA: Winnti rootkit string cluster]({{ '/assets/downloads/tracking-winnti/winnti-string-cluster.yar' | relative_url }})

These are the illustrative research drafts discussed above.

## Sources

- [Group-IB — APT41 World Tour 2021 on a tight schedule][group-ib], 18 August 2022. Source of the historical ATT&CK matrix in Figure 6.
- [MITRE ATT&CK — APT41, G0096][apt41]. Actor profile and partial-overlap wording.
- [MITRE ATT&CK — Winnti Group, G0044][winnti]. Separate actor record and Blackfly association.
- [Mandiant — APT41: A Dual Espionage and Cyber Crime Operation][apt41-profile], 7 August 2019. Original actor-profile research.
- [Symantec — Blackfly: Espionage Group Targets Materials Technology][blackfly], 28 February 2023. Victimology and vendor naming.
- [MITRE ATT&CK — Operation CuckooBees, C0012][cuckoo-mitre]. Campaign record and references to the original investigation.
- [Cybereason — Operation CuckooBees: Deep-Dive into Stealthy Winnti Techniques][cuckoo-techniques], 4 May 2022. Historical original; its URL currently redirects following the site's migration. Use the linked MITRE campaign record for a live summary and original citation.
- [Cybereason — Operation CuckooBees: A Winnti Malware Arsenal Deep-Dive][cuckoo-arsenal], 4 May 2022. Historical original used for component roles; its URL currently redirects.
- [LAC — RevivalStone][revivalstone], 13 February 2025. Japanese-language original and detection appendix.
- [Trend Micro — Stealth in the Shadows: Dissecting Earth Freybug's Recent Campaign and Operational Techniques][freybug-slides], JSAC, 21 January 2025. See PDF pages 15–19 for CUNNINGPIGEON and related components.
- [Unit 42 — Data From Chinese Security Services Company i-Soon Linked to Previous Chinese APT Campaigns][isoon], February 2024. Controller documentation and attribution limits.
- [Sangfor — Behinder v3.0 Analysis][behinder]. Default-key derivation and web-shell behavior.
- [Check Point Research — Silver Dragon Targets Organizations in Southeast Asia and Europe][silver-dragon], 3 March 2026. Separately attributed recent context and GearDoor research.
- [Microsoft — Sysmon][sysmon]. Event descriptions and collection requirements.
- [SigmaHQ — Sigma rules][sigma]. Detection-rule structure and backend considerations.
- [YARA — Writing YARA rules][yara]. String syntax and modifiers.

[apt41]: https://attack.mitre.org/groups/G0096/
[winnti]: https://attack.mitre.org/groups/G0044/
[apt41-profile]: https://cloud.google.com/blog/topics/threat-intelligence/apt41-dual-espionage-and-cyber-crime-operation
[blackfly]: https://www.security.com/threat-intelligence/blackfly-espionage-materials
[cuckoo-mitre]: https://attack.mitre.org/campaigns/C0012/
[cuckoo-techniques]: https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques
[cuckoo-arsenal]: https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive
[revivalstone]: https://www.lac.co.jp/lacwatch/report/20250213_004283.html
[freybug-slides]: https://jsac.jpcert.or.jp/archive/2025/pdf/JSAC2025_1_2_theo-chen_leon-chang_en.pdf
[isoon]: https://unit42.paloaltonetworks.com/i-soon-data-leaks/
[behinder]: https://www.sangfor.com/blog/cybersecurity/behinder-v30-analysis
[silver-dragon]: https://research.checkpoint.com/2026/silver-dragon-targets-organizations-in-southeast-asia-and-europe/
[sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
[sigma]: https://sigmahq.io/docs/basics/rules.html
[yara]: https://yara.readthedocs.io/en/stable/writingrules.html

[group-ib]: https://www.group-ib.com/blog/apt41-world-tour-2021/
