# Playbook: Failed / Anomalous Logins

**Alert type:** `anomalous_login`

## Overview

Covers failed login bursts, logins from unfamiliar source IPs or geographies, and
"impossible travel" patterns (successful logins from two distant locations too close
together in time to be the same person).

## Indicators to check

1. **Failure count and window** — a handful of failures followed by a success within
   minutes usually means a mistyped password. Dozens of failures in a short window,
   especially from a single external IP, indicates brute forcing.
2. **Source IP history** — has this account ever authenticated from this IP/ASN before?
   Meridian Cloud employees primarily connect via the corporate VPN gateway
   (`vpn-gw-01`, 10.42.24.1) or recognized home-ISP ranges.
3. **Impossible travel** — two successful logins for the same account from geographically
   distant source IPs closer together in time than plausible travel allows.
4. **Account sensitivity** — IT admin, finance, and exec accounts are higher-value targets;
   weight anomalies on these accounts more heavily.

## Investigation steps

1. Pull the last 30 days of login source IPs/ASNs for this account and compare.
2. Check whether the account owner has any recorded travel or new-device enrollment
   (would explain a new source IP).
3. Query the entity graph: has this host or user shown up in any other alert category
   in the same time window (e.g. a suspicious process alert on the same host right after
   the login)?
4. If the source IP is external, check whether it falls in a known-bad range or has no
   reputation history at all (neutral, not automatically bad).

## MITRE ATT&CK mapping

- **T1078 — Valid Accounts**
- **T1110 — Brute Force**
- **T1110.003 — Password Spraying** (if failures span many accounts from one source)

## False-positive patterns

- IT-driven password reset (failed logins immediately after a reset ticket).
- Employee travel or new device/browser triggering a "new location" flag.
- VPN client reconnect producing a burst of duplicate auth attempts.

## Escalation criteria

Escalate as **true_positive / high-critical** when: brute-force success, impossible
travel with no travel record, or login anomaly correlates with a suspicious-process
or privilege-escalation alert on the same account within the hour.
