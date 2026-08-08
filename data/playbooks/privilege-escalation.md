# Playbook: Privilege Escalation

**Alert type:** `privilege_escalation`

## Overview

Covers changes that grant an account more access than it previously had: group
membership changes (local admin, Domain Admins), UAC bypass / token manipulation,
and sudoers modifications.

## Indicators to check

1. **Change ticket correlation** — Meridian Cloud IT tracks privileged group changes
   via change tickets. A privilege change with no matching ticket is the single
   strongest signal in this category.
2. **Who performed the change** — was it initiated by a recognized IT admin account,
   or by the affected account itself / an unexpected actor?
3. **Timing relative to other alerts** — privilege escalation immediately following a
   suspicious-process or credential-access alert on the same host is a strong
   true-positive chain.
4. **Scope of the grant** — local admin on a single workstation is lower blast-radius
   than Domain Admins or sudoers NOPASSWD, which affect the whole environment.

## Investigation steps

1. Check for a matching, recent IT change ticket for this account/group change.
   Note tickets are sometimes logged with a short delay — absence alone at the
   moment of alerting is weaker evidence than absence after 24 hours.
2. Query the entity graph for alerts on the same host in the preceding 30 minutes
   (especially `suspicious_process` — credential dumping or token manipulation
   often precedes a privilege escalation step).
3. Identify the scope of the new privilege (local vs. domain vs. root) to set severity.

## MITRE ATT&CK mapping

- **T1548 — Abuse Elevation Control Mechanism** (UAC bypass)
- **T1068 — Exploitation for Privilege Escalation**
- **T1098 — Account Manipulation** (group membership changes)
- **T1136 — Create Account**

## False-positive patterns

- IT admin performing a documented, ticketed group-membership change.
- Configuration-management tooling (e.g. Ansible/Puppet runs) legitimately modifying
  sudoers as part of a scheduled convergence run.

## Escalation criteria

Escalate as **true_positive / critical** for any Domain Admins addition or sudoers
NOPASSWD grant with no change ticket, or any privilege escalation directly preceded
by a credential-dumping signature on the same host.
