# Playbook: Unusual Outbound Network Traffic

**Alert type:** `unusual_outbound_network`

## Overview

Covers outbound connections that deviate from a host's normal network baseline:
beaconing, large transfers, DNS tunneling indicators, and connections to
IPs/domains with no prior history for that host.

## Indicators to check

1. **Destination reputation and history** — is the destination a known Meridian Cloud
   vendor (backup provider, SaaS CRM, video conferencing, package mirror)? Check
   against the known-vendor list before treating as suspicious.
2. **Beaconing pattern** — near-identical connection size/interval repeating over time
   is a strong C2 (command-and-control) indicator, distinct from normal bursty
   human/application traffic.
3. **Volume and direction** — large outbound transfers (multi-GB) are far more
   concerning than small ones, especially off-hours or to a destination with no
   business relationship.
4. **DNS anomalies** — high-entropy subdomains or an unusually high query volume to a
   single external resolver can indicate DNS tunneling used for covert data exfiltration
   or C2.

## Investigation steps

1. Match the destination IP against the known-vendor list (backup, CRM, conferencing,
   package mirror). If matched, this is very likely a false positive.
2. If unmatched, check whether the connection pattern is periodic/beacon-like versus a
   one-off event.
3. Query the entity graph: does the source host have any other alerts in the same
   window (e.g. a suspicious-process alert that could explain the traffic, such as a
   download cradle contacting the same IP)?
4. Consider host role — a database or file server initiating unexpected outbound traffic
   is more severe than a workstation doing so, since these hosts normally have very
   narrow, predictable egress patterns.

## MITRE ATT&CK mapping

- **T1071 — Application Layer Protocol** (C2 over common protocols)
- **T1071.004 — DNS** (tunneling)
- **T1041 — Exfiltration Over C2 Channel**
- **T1048 — Exfiltration Over Alternative Protocol**
- **T1090 — Proxy**

## False-positive patterns

- Scheduled backup jobs to the backup vendor.
- CRM sync jobs, video conferencing traffic, package-mirror pulls during builds.

## Escalation criteria

Escalate as **true_positive / high-critical** for confirmed beaconing patterns,
multi-GB transfers to unrecognized destinations, or any outbound anomaly from the
database or domain-controller tier.
