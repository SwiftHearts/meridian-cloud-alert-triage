"""
REST API for Meridian Cloud Alert Triage — wraps the Phase 4 LangGraph
analyst/reviewer pipeline (agents/triage_graph.py) so triage can be called
from anywhere, not just the Streamlit UI in app/app.py.

Run: uvicorn api.main:app --reload   (from the project root)
Docs: http://127.0.0.1:8000/docs
"""

import json
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException

from api.schemas import AlertIn, AlertType, PlaybookChunk, TriageResponse, Verdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))
from triage_graph import run_triage  # noqa: E402

DATA_DIR = ROOT / "data"

app = FastAPI(
    title="Meridian Cloud Alert Triage API",
    description="Multi-agent SOC alert triage: submit an alert, get back a reviewed verdict.",
    version="1.0.0",
)

_alerts_by_id: Optional[dict[str, dict]] = None


def _load_alerts() -> dict[str, dict]:
    global _alerts_by_id
    if _alerts_by_id is None:
        alerts = json.loads((DATA_DIR / "raw_alerts.json").read_text())
        _alerts_by_id = {a["alert_id"]: a for a in alerts}
    return _alerts_by_id


def _run_pipeline(alert: dict) -> TriageResponse:
    try:
        state = run_triage(alert)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"triage pipeline error: {exc}") from exc

    return TriageResponse(
        alert_id=alert.get("alert_id"),
        verdict=Verdict(**state["final_verdict"]),
        playbook_context=[PlaybookChunk(**c) for c in state["playbook_context"]],
        graph_context=state["graph_context"],
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/alerts")
def list_alerts(alert_type: Optional[AlertType] = None, limit: int = 50):
    alerts = list(_load_alerts().values())
    if alert_type is not None:
        alerts = [a for a in alerts if a["alert_type"] == alert_type]
    return alerts[:limit]


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = _load_alerts().get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"unknown alert_id: {alert_id}")
    return alert


@app.post("/triage", response_model=TriageResponse)
def triage_alert(alert: AlertIn):
    """Run the analyst/reviewer pipeline on an arbitrary alert body."""
    return _run_pipeline(alert.model_dump())


@app.post("/alerts/{alert_id}/triage", response_model=TriageResponse)
def triage_known_alert(alert_id: str):
    """Run the pipeline on an alert already in data/raw_alerts.json, by id."""
    alert = _load_alerts().get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"unknown alert_id: {alert_id}")
    return _run_pipeline(alert)
