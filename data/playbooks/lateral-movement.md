# Playbook: Lateral Movement

**Alert type:** `lateral_movement`

## Overview

Covers an account moving between hosts in a way that deviates from its normal access
pattern — PsExec/WMI-based remote execution, RDP hopping, and pass-the-hash-style
authentication spread across multiple hosts in a short window.

## Indicators to check

1. **Breadth and speed** — authentication to many hosts (3+) within a short window
   (minutes) is far more suspicious than a single RDP hop.
2. **Tooling** — PsExec and WMI are used by IT for legitimate fleet-wide patch
   deployment (typically during a known change window) but are also classic
   lateral-movement tools.
3. **Access-pattern baseline** — does this account normally touch these hosts? IT
   admin accounts routinely touch many servers; a sales or support account touching
   multiple servers is a major deviation.
4. **Preceding signals** — lateral movement that immediately follows a credential-dumping
   or privilege-escalation alert on the source host is a near-certain true positive.

## Investigation steps

1. Check whether the activity falls inside a known patch/maintenance window and was
   performed by an IT admin account.
2. Query the entity graph for the source host's alert history in the preceding
   30 minutes — specifically credential-access (`mimikatz`) or privilege-escalation alerts.
3. Count distinct destination hosts touched by the account in the window; compare to
   this account's historical norm.
4. Identify whether any destination host is high-value (domain controller, database
   tier) — this changes severity regardless of other factors.

## MITRE ATT&CK mapping

- **T1021 — Remote Services** (T1021.001 RDP, T1021.002 SMB/Windows Admin Shares)
- **T1570 — Lateral Tool Transfer**
- **T1569 — System Services** (PsExec-style remote execution)
- **T1550 — Use Alternate Authentication Material** (pass-the-hash indicators)

## False-positive patterns

- IT admin patch deployment across the server fleet during a documented change window.
- Scheduled configuration-management runs touching multiple hosts.

## Escalation criteria

Escalate as **true_positive / critical** immediately for: movement touching the
domain controller or database tier, movement to 3+ hosts by a non-admin account,
or any lateral movement chained after a credential-dumping alert.
