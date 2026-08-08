# Playbook: Suspicious Process Execution

**Alert type:** `suspicious_process`

## Overview

Covers execution of "living-off-the-land binaries" (LOLBins) — legitimate OS tools
(`powershell.exe`, `certutil.exe`, `rundll32.exe`, `wmic.exe`, `regsvr32.exe`) that
are frequently abused for download-and-execute, defense evasion, or credential access,
as well as known attacker tooling (e.g. Mimikatz) when it appears at all.

## Indicators to check

1. **Command-line content** — encoded/obfuscated PowerShell (`-enc`, `-nop`, `-w hidden`),
   download cradles (`DownloadString`, `certutil -urlcache`), or execution from
   world-writable paths (`C:\Users\Public\`, `C:\Windows\Temp\`).
2. **Parent process** — was this spawned by an unexpected parent (e.g. an Office app
   spawning PowerShell)? (Not always present in this alert set, but check `raw_description`
   for context.)
3. **Known attacker tooling** — any alert naming `mimikatz.exe` or similar credential-dumping
   tools is a true positive by default; there is no legitimate business reason for this
   binary to run on a Meridian Cloud endpoint.
4. **Baseline deviation** — does this host/user normally run this binary? Engineering and
   CI hosts legitimately run PowerShell/bash scripts constantly; a sales laptop running
   obfuscated PowerShell is far more anomalous than the same on `ci-01`.

## Investigation steps

1. Decode any base64/encoded command-line content (conceptually — flag it for the
   investigation summary even if not decoded programmatically).
2. Check whether the destination in any download-cradle command line matches a known
   Meridian Cloud package mirror or vendor IP, or an unrecognized external IP.
3. Query the entity graph for correlated alerts on the same host (e.g. a lateral-movement
   or privilege-escalation alert following this one).
4. Compare against playbook: general-triage-checklist.md for change-ticket / maintenance-window checks.

## MITRE ATT&CK mapping

- **T1059 — Command and Scripting Interpreter** (T1059.001 PowerShell, T1059.003 Windows Command Shell)
- **T1218 — System Binary Proxy Execution** (certutil, rundll32, regsvr32)
- **T1027 — Obfuscated Files or Information**
- **T1105 — Ingress Tool Transfer**
- **T1003 — OS Credential Dumping** (Mimikatz)

## False-positive patterns

- Scripted deployment/patch tooling (`Deploy-Patch.ps1`) run by IT.
- CI/CD pipeline steps (`git pull`, `docker build`) on `ci-01`.
- Backup/robocopy jobs.

## Escalation criteria

Escalate as **true_positive / critical** immediately for any confirmed credential-dumping
tool signature, or obfuscated PowerShell combined with an external download destination.
