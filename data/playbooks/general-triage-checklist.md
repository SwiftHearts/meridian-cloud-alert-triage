# Playbook: General Alert Triage Checklist

**Applies to:** all alert categories (starting point before category-specific playbooks)

## Overview

This is the baseline checklist every analyst (human or agent) runs before diving into
a category-specific investigation. It exists to keep triage consistent across alert
types and to avoid skipping cheap checks that resolve a large fraction of alerts
in under a minute.

## Step 1 — Establish identity context

- Is the user/host a known Meridian Cloud asset (matches inventory), or unrecognized?
- Is the account a standard employee account, a shared/service account, or an IT admin account?
  IT admin and service accounts (`svc_ci`, `svc_backup`, IT department users) generate more
  legitimate-looking "suspicious" activity than regular employees — check for a change ticket
  before assuming malice.

## Step 2 — Establish time context

- Is the activity inside or outside business hours (Meridian Cloud core hours: 08:00–18:00,
  primary time zone)?
- Off-hours activity is not inherently malicious (deploys, backups, and on-call work happen
  off-hours) but raises the prior probability of a true positive when combined with other signals.

## Step 3 — Check for a business justification

- Is there a matching change ticket, scheduled job, or known maintenance window?
- Common legitimate explanations that look suspicious in isolation: patch deployment via
  PsExec/WinRM, backup jobs producing large outbound transfers, CI/CD pipelines running
  PowerShell/bash scripts, IT password resets producing failed-then-successful logins.

## Step 4 — Check for correlation

- Query the entity graph for other alerts sharing the same user, host, or destination IP
  within the last few hours. A single anomalous signal is often noise; 2+ correlated
  signals across different alert types is the strongest true-positive indicator.

## Step 5 — Classify

Use this rough decision guide (category playbooks refine this further):

| Signal strength | Classification |
|---|---|
| Matches known benign pattern, no correlation | **false_positive** |
| Anomalous but isolated, no correlation, ambiguous intent | **needs_investigation** |
| Anomalous AND correlates with 1+ other alert, OR matches a known attack pattern | **true_positive** |

## Step 6 — Severity

Severity should reflect **potential blast radius**, not just confidence:

- **low** — confirmed benign, or minor deviation with no access-impact potential
- **medium** — ambiguous, would matter if confirmed, limited blast radius (single workstation, non-privileged account)
- **high** — likely malicious, meaningful blast radius (server, privileged account, or customer-data-adjacent system)
- **critical** — likely malicious with high blast radius (domain controller, database, credential dumping, confirmed lateral movement, or privilege escalation)

## Escalation

Escalate to a human analyst immediately (do not wait for the full investigation to
complete) when an alert involves: domain controller (`dc-01`), the database tier
(`db-01`, `db-02`), credential dumping tooling (e.g. Mimikatz signatures), or any
alert already classified `critical`.
