"""
Runs the Phase 4 multi-agent triage pipeline (triage_graph.py) against a
handful of sample alerts and prints each verdict — a sanity check that
retrieval, graph context, and the analyst/reviewer loop all work end to end.

Run: python agents/run_triage.py [n]   (n = number of alerts to sample, default 5)
"""
# Sample alerts in JSON
import json

# Read command line arguments
import sys

# Build file paths
from pathlib import Path

# Import the function that runs the triage graph from the triage_graph module
from triage_graph import triage_alert

# Define the path to the data directory: __file__ is the current file, resolve() gets the 
# absolute path, and parent.parent goes up two levels to the project root
# which contains the raw_alerts.json file
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def main():
    # Read the number of alerts to sample from command line arguments, defaulting to 5 if not provided
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    # Read the raw alerts from the JSON file in the data directory and parse them into a Python 
    # list of dictionaries
    alerts = json.loads((DATA_DIR / "raw_alerts.json").read_text())

    # One alert per alert_type, for a varied sample.
    seen_types = set()
    sample = []
    # Loop through the alerts and add them to the sample list if their alert_type has not been seen yet,
    # until the sample list reaches the desired size (n)
    for alert in alerts:
        if alert["alert_type"] not in seen_types:
            sample.append(alert)
            seen_types.add(alert["alert_type"])
        if len(sample) >= n:
            break

    # Loop through the sampled alerts, print their details, run the triage graph on each alert, and 
    # print the verdict
    for alert in sample:
        # Print a separator line, the alert ID, type, host, and raw description for context
        print(f"\n{'=' * 70}\n{alert['alert_id']} ({alert['alert_type']}) — {alert['host']}")
        print(f"  {alert['raw_description']}")

        # Run the triage graph on the alert and get the verdict
        verdict = triage_alert(alert)

        print(f"\n  -> label: {verdict['label']} | severity: {verdict['severity']} "
              f"| reviewed: {verdict['reviewed']} | revisions: {verdict['revision_count']}")
        print(f"  rationale: {verdict['rationale']}")
        print(f"  recommended actions: {verdict['recommended_actions']}")
        if verdict.get("reviewer_note"):
            print(f"  reviewer note (unresolved): {verdict['reviewer_note']}")

# If you run this file directly (not imported as a module), call the main() function to 
# execute the triage pipeline. If another module imports this file, the main() function 
# will not be called automatically.
if __name__ == "__main__":
    main()
