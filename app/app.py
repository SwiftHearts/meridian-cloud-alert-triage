"""
Streamlit UI for Meridian Cloud Alert Triage.

Two tabs:
  - Alert Triage: pick any alert from data/raw_alerts.json, run it through
    the Phase 4 analyst/reviewer graph live, and inspect exactly what it
    saw — retrieved playbook/ATT&CK guidance, entity-graph context, the
    analyst's verdict, and any reviewer pushback — not just the final label.
  - Eval Dashboard: Phase 5's scored results (eval/results.csv), if present.

Run: streamlit run app/app.py
"""

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))
from triage_graph import run_triage  # noqa: E402

DATA_DIR = ROOT / "data"
EVAL_RESULTS_PATH = ROOT / "eval" / "results.csv"

st.set_page_config(page_title="Meridian Cloud Alert Triage", layout="wide")


@st.cache_data
# Load the raw alerts from data/raw_alerts.json, returning a list of alert dictionaries.
def load_alerts() -> list[dict]:
    return json.loads((DATA_DIR / "raw_alerts.json").read_text())


@st.cache_data
# Load the eval set from data/eval_set.json, returning a dictionary mapping alert_id to 
# the corresponding record.
def load_eval_labels() -> dict:
    path = DATA_DIR / "eval_set.json"
    if not path.exists():
        return {}
    # Load the eval set and return a dictionary mapping alert_id to the corresponding record
    # to allow quick lookup of ground truth labels and expected severities for alerts in the eval set.
    return {r["alert_id"]: r for r in json.loads(path.read_text())}


LABEL_COLOR = {
    "false_positive": "green",
    "needs_investigation": "orange",
    "true_positive": "red",
}
SEVERITY_COLOR = {
    "low": "green",
    "medium": "orange",
    "high": "red",
    "critical": "red",
}


def render_verdict_badge(label: str, severity: str):
    st.markdown(
        # Put the label in uppercase and replace underscores with spaces, and color it according 
        # to the label/severity.
        f":{LABEL_COLOR[label]}[**{label.upper().replace('_', ' ')}**] &nbsp;&nbsp; "
        f"severity: :{SEVERITY_COLOR[severity]}[**{severity.upper()}**]"
    )


def render_triage_tab():
    alerts = load_alerts()
    eval_labels = load_eval_labels()
    # Build a dictionary of alerts by alert_id for quick lookup.
    alerts_by_id = {a["alert_id"]: a for a in alerts}

    # Create two columns: one for filtering by alert type, and one for picking an alert from 
    # the filtered list.
    col_filter, col_pick = st.columns([1, 2])
    with col_filter:
        alert_types = sorted({a["alert_type"] for a in alerts})
        selected_type = st.selectbox("Alert type", ["all"] + alert_types)

    # Keep the alert if the selected type is "all" or if its alert_type matches the selected type.
    with col_pick:
        filtered = [a for a in alerts if selected_type == "all" or a["alert_type"] == selected_type]
        options = [a["alert_id"] for a in filtered]
        # Format dropdown options to show the alert_id and host, and indicate if the alert is in 
        # the eval set.
        labels = {
            a["alert_id"]: f"{a['alert_id']} — {a['host']}"
            + (" (in eval set)" if a["alert_id"] in eval_labels else "")
            for a in filtered
        }
        alert_id = st.selectbox("Alert", options, format_func=lambda x: labels[x])

    alert = alerts_by_id[alert_id]

    st.subheader(f"{alert['alert_id']} — {alert['alert_type']}")
    st.write(alert["raw_description"])

    with st.expander("Raw alert fields", expanded=False):
        st.json(alert)

    if alert_id in eval_labels:
        gt = eval_labels[alert_id]
        st.info(f"Ground truth (eval set): **{gt['ground_truth_label']}**, "
                f"expected severity **{gt['expected_severity']}**")

    run = st.button("Run triage", type="primary")

    cache_key = f"triage_result::{alert_id}"
    if run:
        with st.spinner("Running analyst + reviewer..."):
            st.session_state[cache_key] = run_triage(alert)

    result = st.session_state.get(cache_key)
    if result is None:
        st.caption("Click “Run triage” to send this alert through the analyst/reviewer pipeline.")
        return

    verdict = result["final_verdict"]
    st.divider()
    render_verdict_badge(verdict["label"], verdict["severity"])
    if alert_id in eval_labels:
        gt_label = eval_labels[alert_id]["ground_truth_label"]
        st.markdown("✅ matches ground truth" if verdict["label"] == gt_label else "⚠️ differs from ground truth")

    st.markdown(f"**Rationale:** {verdict['rationale']}")
    st.markdown("**Recommended actions:**")
    for action in verdict["recommended_actions"]:
        st.markdown(f"- {action}")

    if verdict["reviewed"]:
        st.success(f"Reviewer approved (after {verdict['revision_count']} revision(s)).")
    else:
        st.warning(f"Reviewer pushback not fully resolved: {verdict.get('reviewer_note', '')}")

    with st.expander("Playbook / MITRE ATT&CK context retrieved (Phase 2 RAG)"):
        for chunk in result["playbook_context"]:
            technique = f" ({chunk['technique_id']})" if chunk["technique_id"] else ""
            st.markdown(f"**[{chunk['source']}] {chunk['doc_title']} — {chunk['section_title']}**{technique}")
            st.text(chunk["content"])

    with st.expander("Entity graph context (Phase 3)"):
        st.text(result["graph_context"])

# Define a function to render the evaluation dashboard tab, which displays metrics and results from the evaluation of the alert triage system.
def render_eval_tab():
    if not EVAL_RESULTS_PATH.exists():
        st.info("No eval results yet — run `python eval/run_eval.py` first.")
        return

    df = pd.read_csv(EVAL_RESULTS_PATH)

    c1, c2, c3 = st.columns(3)
    c1.metric("Alerts scored", len(df))
    c2.metric("Label accuracy", f"{df['label_correct'].mean():.1%}")
    c3.metric("Missed true positives", int(df["missed_true_positive"].sum()))

    st.subheader("Label accuracy by alert type")
    st.bar_chart(df.groupby("alert_type")["label_correct"].mean())

    st.subheader("Confusion matrix (rows = ground truth, cols = predicted)")
    labels = ["false_positive", "needs_investigation", "true_positive"]
    confusion = pd.crosstab(df["ground_truth_label"], df["predicted_label"]).reindex(
        index=labels, columns=labels, fill_value=0
    )
    st.dataframe(confusion, width="stretch")

    st.subheader("Per-alert results")
    st.dataframe(df, width="stretch", hide_index=True)


st.title("Meridian Cloud Alert Triage")
st.caption("RAG-grounded, graph-aware, multi-agent SOC alert triage — a portfolio project.")

tab_triage, tab_eval = st.tabs(["Alert Triage", "Eval Dashboard"])
with tab_triage:
    render_triage_tab()
with tab_eval:
    render_eval_tab()
