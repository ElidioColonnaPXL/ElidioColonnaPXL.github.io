---
layout: post
title: "Inside PHP2Shell: From Multipart OOM to a Reverse Shell"
description: "A packet-and-log reconstruction of a PHP2Shell attack: Apache worker saturation, multipart memory exhaustion, a PHPSESSID heap leak, and a www-data reverse shell."
date: 2026-11-07 13:00:00 +0100
category: "Incident analysis"
tags: [PHP2Shell, PHP, CVE-2026-109618, CVE-2026-109619, DFIR, Detection Engineering]
permalink: /articles/inside-php2shell-multipart-oom-reverse-shell/
thumbnail: /assets/images/php2shell/php2shell-cover.png
thumbnail_alt: "A PHP logo with binary digits leaking beneath it"
---

*The Guarded Kernel · Incident analysis · Research reviewed: 7 November 2026*

## Scenario

The DevNotes.org team noticed suspicious traffic to an internal development server. In the retired Hack The Box Sherlock *dOOMs Day*, we receive a subnet packet capture and Apache access and error logs. The server is **192.168.72.50**; the attack traffic comes from **192.168.72.1**. My goal was to reconstruct what the traffic did, not just identify the CVE names.

The short version: an attacker filled the Apache prefork worker pool with multipart uploads, sent memory-intensive requests to PHP, received an unusually large `PHPSESSID` cookie containing heap data, and obtained a reverse shell as `www-data`. The network capture then shows database-file discovery and a read of a SQLite file. PHP's October 2026 advisories explain how [OOM corruption][php-oom] and [stale worker-global state][php-stale] can be chained across requests handled by the same worker. The packets and logs show the effects in this lab; they do not expose every internal heap operation.

**Scope:** `Capture.pcap`, `access.log`, and `error.log` supplied with the Sherlock. All incident times below are **UTC** on 28 October 2026. Wireshark set to local time in Belgium can show these packets one hour later. The screenshots are selected views from my investigation; the full capture and logs support the counts and timestamps.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/php2shell-attack-chain.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the PHP2Shell attack chain at full size">
    <img src="{{ '/assets/images/php2shell/php2shell-attack-chain.png' | relative_url }}" alt="Chronological chain: 149 occupied workers, PHP OOM, PHPSESSID heap leak, reverse shell, database discovery, worker crash, shell reconnection, database read, and second worker crash." width="1800" height="1700" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 1 — Observed order in the PCAP and Apache logs. The arrows show chronology. The two crash records do not, by themselves, prove what caused each crash. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## 1. Establish the server and the first request

Apache's startup line identifies `Apache/2.4.69 (Debian) PHP/8.4.26` with `mpm_prefork`. The HTTP `X-Powered-By` response also exposes PHP 8.4.26. That release precedes the [8.4.27 security fix][php-advisory].

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/php-version.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the PHP version evidence">
    <img src="{{ '/assets/images/php2shell/php-version.png' | relative_url }}" alt="HTTP response header revealing PHP/8.4.26 on the DevNotes server." width="837" height="299" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 2 — The response header identifies the PHP version; the Apache startup entry independently corroborates it. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

The first anomalous request in `error.log` begins at **08:42:52.530199 UTC**. The corresponding PCAP request begins at **08:42:52.530036 UTC** (frame 6089); the small difference is between two observation points. It is a `POST /index.php` with `Transfer-Encoding: chunked` and `Content-Type: multipart/form-data; boundary=ZZZZZZZZZZ`.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/first-exploit-request.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the first attack request timestamp">
    <img src="{{ '/assets/images/php2shell/first-exploit-request.png' | relative_url }}" alt="Apache error log search showing the first attacker request at 08:42:52.530199 UTC." width="1185" height="208" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 3 — The first attack request in the Apache log, before the OOM and reverse-shell events. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## 2. Occupy the worker pool

The attacker sent **149** chunked multipart `POST /index.php` requests using the `ZZZZZZZZZZ` boundary. The access log records 149 completed posts from the attacker, each with a `200` status and zero response bytes. The verbose `mod_dumpio` log shows the boundary on requests handled by **149 distinct child PIDs**. The repeated long-running uploads are consistent with deliberately occupying prefork workers so subsequent exploit requests reach a reusable worker. At **08:43:02.243607 UTC**, Apache reports `AH00161: server reached MaxRequestWorkers setting`.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/multipart-worker-occupation.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open a stalled multipart request in Wireshark">
    <img src="{{ '/assets/images/php2shell/multipart-worker-occupation.png' | relative_url }}" alt="Wireshark view of the attacker's chunked multipart POST to index.php with boundary ZZZZZZZZZZ." width="2532" height="938" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 4 — A chunked multipart request with the repeated boundary. The capture shows the wire behavior; the worker count comes from the Apache PIDs. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/occupied-workers.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the worker-count terminal evidence">
    <img src="{{ '/assets/images/php2shell/occupied-workers.png' | relative_url }}" alt="Terminal count of unique Apache child PIDs handling requests with the ZZZZZZZZZZ multipart boundary, yielding 149." width="795" height="863" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 5 — The access-log count gives 149 completed `/index.php` POSTs. A separate count of distinct PIDs associated with the boundary also gives 149; `MaxRequestWorkers` confirms saturation. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

This count describes the **lab exploit's deliberate worker occupation**. It is not a universal number to put in an alert: different prefork configurations have different pool sizes. An access log records a request when it completes, so it alone cannot show how long an upload held a worker; connection telemetry or request-body tracing is needed for that part.

## 3. Trigger OOM during multipart processing

The next requests target `/api/health.php` with different multipart boundaries. One response (PCAP frame 16904) contains `PHP Request Startup: Input variables exceeded 1000`. The Apache trace then records `Allowed memory size of 134217728 bytes exhausted` at **08:42:59.466137 UTC**. That is a **128 MiB PHP memory limit**, not the size of the HTTP request. There are 13 `/api/health.php` requests visible in the PCAP but only 11 completed entries in `access.log`; failed or crashed requests need not appear as completed access-log lines.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/php-oom-response.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the PHP OOM response in Wireshark">
    <img src="{{ '/assets/images/php2shell/php-oom-response.png' | relative_url }}" alt="Wireshark HTTP response showing PHP request-startup input-variable warning and fatal memory-exhaustion text." width="1015" height="396" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 6 — The PHP warning and fatal response locate the failure in request startup. `134217728` bytes is the configured PHP memory ceiling observed in the log. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

[CVE-2026-109618][php-oom] concerns an OOM exit while request data is incompletely initialized, followed by cleanup that treats invalid state as valid. [CVE-2026-109619][php-stale] concerns request-owned state surviving in a persistent worker after its backing memory is freed, then being consumed by a later request. The advisory says demonstrated producer and consumer requests must reach the same worker. The occupied pool explains why the attacker tried to control that placement. The capture establishes the OOM and later effects; the exact in-memory transition is an **advisory-backed interpretation**, not directly visible in HTTP.

## 4. Identify the heap disclosure and code execution

At **08:43:01.936952 UTC**, `mod_dumpio` records a **773,518-byte** outgoing data chunk. Two microseconds later, the same client and PID 145 have an outgoing value beginning `PHPSESSID=WWWW...`; the PCAP response at frame 23192 carries the abnormal `Set-Cookie`. This is the heap disclosure evidence. The logged chunk size is **not** the full response length: the access log reports **774,455** response bytes for that request. I have kept those two measurements separate.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/session-cookie-heap-leak.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the PHPSESSID leak response">
    <img src="{{ '/assets/images/php2shell/session-cookie-heap-leak.png' | relative_url }}" alt="Wireshark response showing an unusually large Set-Cookie PHPSESSID value in the heap-leak sequence." width="1658" height="603" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 7 — The abnormal `PHPSESSID` response. Its length and binary-looking content are evidence of disclosure; an ordinary session cookie is not itself a detection for this exploit. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

At **08:43:02.401261 UTC**, the server opens a TCP connection from `192.168.72.50:55914` to `192.168.72.1:4444` (PCAP frame 23797). By **08:43:02.458047 UTC**, the stream contains a `www-data` shell prompt. That prompt is the clearest observed point at which interactive code execution is established. The attacker runs `cat /proc/version`, `uname -a`, and `ps aux` over the stream.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/reverse-shell.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the reverse-shell packet evidence">
    <img src="{{ '/assets/images/php2shell/reverse-shell.png' | relative_url }}" alt="Wireshark showing the server-to-attacker TCP connection on port 4444 and interactive shell traffic." width="1557" height="451" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 8 — Server-originated connection to port 4444, followed by interactive shell data as `www-data`. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## 5. Follow the shell and the worker crashes

At **08:46:00.336542 UTC**, the shell stream shows a search for database files. It returns `/var/www/data/devnotes.sqlite`. The exact command in the capture is:

```sh
find / -type f \( -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.db" -o -name "*.db3" -o -name "*.s3db" -o -name "*.sl3" \) 2>/dev/null
```

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/database-discovery.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the database discovery evidence">
    <img src="{{ '/assets/images/php2shell/database-discovery.png' | relative_url }}" alt="Follow TCP Stream excerpt showing the find command and the devnotes.sqlite path returned by the shell." width="857" height="137" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 9 — Database-file discovery in the reverse-shell stream. The later `strings` output shows the file was read; this capture does not establish a separate outbound exfiltration destination. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

Apache records child **PID 145** exiting with segmentation fault at **08:46:16.516499 UTC**. A second server-to-attacker connection on port 4444 establishes another shell by **08:46:29.945 UTC**. At **08:46:48.604351 UTC**, the attacker runs `strings /var/www/data/devnotes.sqlite`, and content returns in the shell stream. A second Apache child, **PID 170**, exits with segmentation fault at **08:47:42.631917 UTC**. The sequence strongly links these events to the active exploitation window, but timing alone cannot show why each child crashed.

<figure class="article-figure">
  <a href="{{ '/assets/images/php2shell/worker-crashes-and-saturation.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Apache worker saturation and crash records">
    <img src="{{ '/assets/images/php2shell/worker-crashes-and-saturation.png' | relative_url }}" alt="Apache error-log matches for PHP OOM, MaxRequestWorkers, and segmentation faults of child PIDs 145 and 170." width="1811" height="221" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 10 — Apache recorded pool saturation and both child crashes. These are high-value hunt pivots, although a crash alone is not a PHP2Shell signature. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## 6. Reproduce the hunt

These filters bring the relevant packets or log lines back into view. Set Wireshark's time display to **UTC** when comparing it with the Apache `+0000` timestamps. The `tcp contains` filters match packet bytes and may miss a string split across TCP segments; **Follow TCP Stream** is useful for the shell and long responses.

| Question | Wireshark display filter or log query |
| --- | --- |
| Worker occupation | `ip.src == 192.168.72.1 && tcp contains "boundary=ZZZZZZZZZZ"` |
| OOM endpoint | `http.request.uri == "/api/health.php"` |
| PHP fatal response | `ip.src == 192.168.72.50 && tcp contains "Allowed memory size"` |
| Leaked cookie response | `frame.number == 23192` |
| Reverse shell | `tcp.port == 4444 && ip.addr == 192.168.72.50` |
| Database search | `tcp.port == 4444 && tcp contains "find / -type f"` |
| SQLite path | `tcp.port == 4444 && tcp contains "devnotes.sqlite"` |

From the supplied `logs/` directory, I used:

```sh
rg -n -m 1 'boundary=ZZZZZZZZZZ' error.log | cut -c1-260
rg '^192\.168\.72\.1 .*"POST /index\.php HTTP/1\.1"' access.log | wc -l
rg -F 'boundary=ZZZZZZZZZZ' error.log | sed -E 's/.*\[pid ([0-9]+):.*/\1/' | sort -u | wc -l
rg -n 'Input variables exceeded|Allowed memory size|MaxRequestWorkers|AH00052' error.log | cut -c1-280
rg -n -m 1 'dumpio_out \(data-HEAP\): 773518 bytes' error.log
```

The two counts return **149** for this dataset. The final query identifies the log's outgoing chunk-size record; the following line holds the `PHPSESSID` value. I avoid printing the entire cookie because it is hundreds of kilobytes and adds nothing to the finding.

## 7. Detection: think in stages

A single multipart request or a single PHP OOM can be benign. The useful analytic is the **sequence** across request metadata, server health, response behavior, and outbound traffic. I would start with three candidate rules, validate their fields against the local parser, then test them on normal traffic and this incident. These are **detection designs, not deployed production rules**.

| Candidate rule | Required telemetry | Trigger and triage |
| --- | --- | --- |
| **A. Worker starvation** | Per-request client IP, method, path, content type, transfer encoding, connection duration; Apache pool status | Alert on a sudden burst of long-lived chunked multipart POSTs from one source approaching the worker limit, especially with `AH00161`. Tune the count to the actual pool size and normal upload patterns. Completed access logs alone cannot measure occupancy. |
| **B. PHP startup OOM and disclosure** | PHP/Apache errors plus response header sizes | Within a short window, correlate input-variable warnings or `Allowed memory size ... exhausted` with an unusually large `Set-Cookie: PHPSESSID` on the same service/client. The cookie-length condition needs response-header telemetry; ordinary combined access logs do not include it. |
| **C. Post-execution egress** | Host network and process telemetry | Alert when a web worker account or Apache/PHP process opens an outbound interactive connection to an unapproved destination. In this case, `192.168.72.50 → 192.168.72.1:4444` plus shell commands is conclusive; port 4444 alone is not portable detection. |

Here is a **Sigma correlation draft** for the access-log burst in rule A. It assumes the parser exposes `client_ip`, `method`, `path`, `status`, and numeric `response_bytes`. I have **not** converted or run it in a SIEM; the [Sigma correlation specification][sigma-correlation] informed the `event_count` structure. A threshold of 40 completed posts in 30 seconds would catch this lab's burst, but needs tuning for each site and cannot by itself prove concurrent worker occupancy.

```yaml
title: Repeated Empty PHP POST Responses
name: php_empty_post
status: experimental
logsource:
  category: webserver
detection:
  selection:
    method: POST
    path: /index.php
    status: 200
    response_bytes: 0
  condition: selection
---
title: Burst of Empty PHP POST Responses From One Client
status: experimental
correlation:
  type: event_count
  rules:
    - php_empty_post
  group-by:
    - client_ip
  timespan: 30s
  condition:
    gte: 40
```

For a first pass over **this dataset**, the following raw-log hunt catches the server-side failure cluster:

```sh
rg -n 'Input variables exceeded|Allowed memory size|AH00161|AH00052' error.log | cut -c1-280
```

For response disclosure, inspect header-length distributions at the reverse proxy, or add a **bounded** response-header-length field to logging. `mod_dumpio` is enabled at trace level in this lab, but its full payload logging is too verbose and can expose sensitive data in production. The evidence gap matters: without response-header visibility, rule B is only a hypothesis built from OOM and worker saturation. For shell detection, an endpoint event tying a web process to the outbound socket would strengthen attribution; the supplied PCAP gives the network direction and the interactive stream, but no EDR process tree.

## 8. Mitigation and response

**Update PHP first.** For the affected supported branches, PHP's [21 October 2026 advisory][php-advisory] lists **8.4.27, 8.3.36, 8.2.35, and 8.5.12** as fixed releases. Check distribution backports where the package version does not mirror upstream. Restart every PHP worker after updating so old processes do not retain vulnerable code or state. An update is the only complete mitigation described by PHP.

Until an update is possible, PHP recommends limiting multipart and decoded request sizes at the web server or proxy, including requests without a useful `Content-Length`, and bounding parts, headers, variables, and nesting. `memory_limit=-1` removes the predictable PHP-limit OOM path, while `session.upload_progress.enabled=0` breaks the confirmed session lifecycle path; **neither setting is a complete fix**. Apply them administratively and restart workers. Avoid treating a higher `MaxRequestWorkers` value as a vulnerability fix: it may change the attacker's effort but leaves the PHP bugs present. The [OOM][php-oom] and [stale-state][php-stale] advisories explain the limits of these measures.

In an incident like this one, I would isolate the exposed service, preserve PCAP, access/error logs and PHP configuration, identify the vulnerable worker version, and review outbound connections and files the web account could read. The observed `devnotes.sqlite` access means database contents and any credentials within it need separate assessment. The capture proves reading through an interactive shell; it does not prove an additional transfer outside that channel or modification of the database.

## What this case taught me

The most useful evidence was not a single exploit string. It was the progression from **149 occupied workers** to **request-startup OOM**, **an abnormal session cookie**, and **a server-originated shell**. The Apache log supplied worker PIDs and failure times; the PCAP supplied connection direction and commands. Keeping those sources together made the reconstruction stronger, while the PHP advisories supplied the internal explanation that the wire data cannot show.

### Sources

- [PHP security advisory, 21 October 2026][php-advisory] — affected versions, patch levels and mitigations.
- [PHP: RCE via OOM corruption, CVE-2026-109618][php-oom] — multipart OOM and request-cleanup mechanism.
- [PHP: RCE via stale global state, CVE-2026-109619][php-stale] — cross-request producer/consumer mechanism and memory disclosure.
- [Sigma correlation rules][sigma-correlation] — syntax for the illustrative event-count analytic.
- Hack The Box, retired *dOOMs Day* Sherlock — scenario and supplied `Capture.pcap`, `access.log` and `error.log`; figures are from my analysis of those files.

[php-advisory]: https://www.php.net/?p=6507
[php-oom]: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
[php-stale]: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
[sigma-correlation]: https://sigmahq.io/docs/meta/correlations.html
