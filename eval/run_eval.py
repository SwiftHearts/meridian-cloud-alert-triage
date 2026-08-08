"""
Scores the Phase 4 triage pipeline (agents/triage_graph.py) against the
labeled eval set (data/eval_set.json — a stratified 45-alert sample held
out of raw_alerts.json, 3 per alert_type x ground_truth_label combination).

Runs every eval alert through the full analyst/reviewer graph, compares
the predicted label/severity to ground truth, and reports:
  - overall + per-alert-type label accuracy
  - a confusion matrix (ground truth vs predicted label)
  - severity exact-match rate
  - missed true positives — the one error class that actually matters in a
    SOC (a real attack triaged as benign/low-priority)

Writes per-alert results to eval/results.csv.

Run: python eval/run_eval.py
"""

import json
import sys
from pathlib import Path

import pandas as pd

# Add the agents directory to the Python path so we can import triage_graph.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))
from triage_graph import triage_alert  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RESULTS_PATH = Path(__file__).resolve().parent / "results.csv"

LABELS = ["false_positive", "needs_investigation", "true_positive"]


def load_eval_alerts():
    # Load the eval set and the corresponding raw alerts, returning a list of (record, alert) pairs.
    eval_set = json.loads((DATA_DIR / "eval_set.json").read_text())
    alerts_by_id = {a["alert_id"]: a for a in json.loads((DATA_DIR / "raw_alerts.json").read_text())}
    # Return the record (correct label/severity) and the corresponding raw alert for each eval record.
    return [(record, alerts_by_id[record["alert_id"]]) for record in eval_set]

# Score a single alert by running it through the triage pipeline and comparing the predicted 
# label/severity to ground truth (correct label/severity).
def score_alert(record: dict, alert: dict) -> dict:
    verdict = triage_alert(alert)
    return {
        "alert_id": alert["alert_id"],
        "alert_type": alert["alert_type"],
        "ground_truth_label": record["ground_truth_label"],
        "predicted_label": verdict["label"],
        # Create boolean columns for whether the predicted label/severity matches the ground truth.
        "label_correct": verdict["label"] == record["ground_truth_label"],
        "expected_severity": record["expected_severity"],
        "predicted_severity": verdict["severity"],
        # Create a boolean column for whether the predicted severity matches the expected severity.
        "severity_correct": verdict["severity"] == record["expected_severity"],
        "reviewed": verdict["reviewed"],
        "revision_count": verdict["revision_count"],
        # Create a boolean column for whether a true positive was missed highlighted by the reviewer
        # (i.e., a real attack was triaged as non-true-positive).
        "missed_true_positive": (
            record["ground_truth_label"] == "true_positive" and verdict["label"] != "true_positive"
        ),
    }


def print_report(df: pd.DataFrame):
    print(f"\nScored {len(df)} alerts.\n")

    print(f"Overall label accuracy:    {df['label_correct'].mean():.1%}")
    print(f"Overall severity accuracy: {df['severity_correct'].mean():.1%}")

    print("\nLabel accuracy by alert_type:")
    # Group by alert_type and calculate the mean of label_correct, formatting as a percentage.
    print(df.groupby("alert_type")["label_correct"].mean().apply(lambda x: f"{x:.1%}").to_string())

    print("\nConfusion matrix (rows = ground truth, cols = predicted):")
    confusion = pd.crosstab(df["ground_truth_label"], df["predicted_label"]).reindex(
        index=LABELS, columns=LABELS, fill_value=0
    )
    print(confusion.to_string())

    missed = df[df["missed_true_positive"]]
    print(f"\nMissed true positives (real attack triaged as non-true-positive): {len(missed)}")
    if len(missed):
        print(missed[["alert_id", "alert_type", "predicted_label"]].to_string(index=False))

    print(f"\nRevisions triggered by reviewer: {(df['revision_count'] > 0).sum()} / {len(df)}")


def main():
    eval_pairs = load_eval_alerts()
    print(f"Running triage pipeline on {len(eval_pairs)} labeled alerts...")

    # Score each alert and collect the results in a list of dictionaries, printing progress as we go.
    rows = []
    for i, (record, alert) in enumerate(eval_pairs, start=1):
        rows.append(score_alert(record, alert))
        print(f"  [{i}/{len(eval_pairs)}] {alert['alert_id']} ({alert['alert_type']}) -> {rows[-1]['predicted_label']}"
              f" (truth: {rows[-1]['ground_truth_label']})")

    df = pd.DataFrame(rows)
    df.to_csv(RESULTS_PATH, index=False)
    print(f"\nWrote per-alert results to {RESULTS_PATH}")

    print_report(df)


if __name__ == "__main__":
    main()
