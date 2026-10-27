# KeyDis detection drafts

Companion files for **KeyDis: Anatomy of a Windows Keylogger**, The Guarded Kernel, 27 October 2026.

These are research drafts derived from static analysis of one HTB Sherlock sample. No malware binary or plaintext bot token is included.

## Sample identity

- File: `keydis.exe`, 34,304 bytes
- SHA-256: `caf4e182e31631bba63fcc17c30b8ec23cdd77147f445b01e1681d1830fe932f`

## Files and validation

| File | Purpose | Check performed |
|---|---|---|
| `keydis-string-cluster.yar` | Triage the examined PE build using four strings. | Compiled with YARA-X 1.22.1 and matched the identified executable. |
| `discord-dns-user-directory.yml` | Investigate Discord DNS queries from Downloads or user temporary directories. | Parsed with pySigma 1.5.1. |
| `discord-dns-user-directory.spl` | Splunk conversion of the Sigma rule. | Converted with pysigma-backend-splunk 2.1.0 and pysigma-pipeline-sysmon 2.0.0. |

The conversion used `sysmon_pipeline() + splunk_windows_pipeline()`. The generated query selects `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` and `EventCode=22`. Select the appropriate index and adapt source/field mappings to your ingestion before use. XML ingestion and other field schemas may need different mappings. Conversion is a syntax check; the query was not run in a SIEM.

The YARA match offsets were `0x7BC8` (endpoint), `0x7AF8` (authorization), `0x7C18` (RC4 key), and `0x7AB0` (block-format string). Nine non-PE article/image fixtures did not match. These fixtures are not a representative benign PE corpus, so no false-positive rate is claimed.

## Collection and interpretation

- The Sigma rule requires process-origin DNS telemetry with `Image` and `QueryName`. Sysmon Event 22 is one suitable source.
- Portable clients, legitimate bots, installers and developer utilities can match. Correlate with the executable's hash, provenance, parent process and network activity.
- DNS results alone establish neither keylogging nor successful exfiltration. Cached DNS, another executable directory, or a different destination can avoid this selection.
- The YARA rule is specific to the recovered build. Changed strings, rebuilding or packing can evade it. A match does not attribute an operator.
- The malware was not executed. No Discord requests were made and no bot credential was validated online.

## Sources

- Article: https://theguardedkernel.be/articles/keydis/
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- YARA-X: https://virustotal.github.io/yara-x/docs/api/python/
- pySigma: https://github.com/SigmaHQ/pySigma
- Sysmon pipeline: https://github.com/SigmaHQ/pySigma-pipeline-sysmon
- Splunk backend: https://github.com/SigmaHQ/pySigma-backend-splunk
