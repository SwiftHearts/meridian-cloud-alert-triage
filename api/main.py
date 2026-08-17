# Network accessible layer
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

# FastAPI: create a REST API; HTTPException for error handling
from fastapi import FastAPI, HTTPException

# Schemas for request/response validation and documentation
from api.schemas import AlertIn, AlertType, PlaybookChunk, TriageResponse, Verdict

ROOT = Path(__file__).resolve().parent.parent
# Make the agents directory importable so we can call run_triage() from triage_graph.py
sys.path.insert(0, str(ROOT / "agents"))
from triage_graph import run_triage  # noqa: E402 (don't flag  import order; we need to modify sys.path first)

DATA_DIR = ROOT / "data"

# FastAPI app instance
app = FastAPI(
    title="Meridian Cloud Alert Triage API",
    description="Multi-agent SOC alert triage: submit an alert, get back a reviewed verdict.",
    version="1.0.0",
)

# Global variable to cache loaded alerts from raw_alerts.json: lazy-loaded on first request, then reused for subsequent requests.
_alerts_by_id: Optional[dict[str, dict]] = None

# Load alerts from raw_alerts.json into a dictionary keyed by alert_id. 
def _load_alerts() -> dict[str, dict]:
    # Variable created outside the function
    global _alerts_by_id
    if _alerts_by_id is None:
        alerts = json.loads((DATA_DIR / "raw_alerts.json").read_text())
        # Create a dictionary keyed by alert_id for quick lookup
        _alerts_by_id = {a["alert_id"]: a for a in alerts}
    return _alerts_by_id


def _run_pipeline(alert: dict) -> TriageResponse:
    try:
        state = run_triage(alert)
    except Exception as exc:
        # Raise an HTTP 502 Bad Gateway error if the triage pipeline fails, with the exception message included in the response.
        raise HTTPException(status_code=502, detail=f"triage pipeline error: {exc}") from exc

    return TriageResponse(
        alert_id=alert.get("alert_id"),
        # Unpack the final verdict dictionary into a Verdict model instance for structured response.
        verdict=Verdict(**state["final_verdict"]),
        # Unpack each playbook context dictionary into a PlaybookChunk model instance for structured response.
        playbook_context=[PlaybookChunk(**c) for c in state["playbook_context"]],
        graph_context=state["graph_context"],
    )

# Retrieve the health status of the API. Returns a simple JSON indicating the service is operational.
@app.get("/health")
def health():
    return {"status": "ok"}

# Retrieve a list of alerts, optionally filtered by alert_type and limited to a specified number of results. 
# Returns a list of alert dictionaries.
@app.get("/alerts")
def list_alerts(alert_type: Optional[AlertType] = None, limit: int = 50):
    alerts = list(_load_alerts().values())
    if alert_type is not None:
        alerts = [a for a in alerts if a["alert_type"] == alert_type]
    return alerts[:limit]

# Retrieve a specific alert by its alert_id. Returns the alert dictionary if found, or raises a 404 error if not found.
@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = _load_alerts().get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"unknown alert_id: {alert_id}")
    return alert

# Run the triage pipeline on an arbitrary alert body submitted in the request. Returns a TriageResponse containing the final verdict and context.
@app.post("/triage", response_model=TriageResponse)
def triage_alert(alert: AlertIn):
    """Run the analyst/reviewer pipeline on an arbitrary alert body."""
    # Convert the Pydantic model to a dictionary and pass it to the triage pipeline.
    return _run_pipeline(alert.model_dump())

# Run the triage pipeline on an alert already in data/raw_alerts.json, identified by its alert_id. Returns a TriageResponse containing 
# the final verdict and context.
@app.post("/alerts/{alert_id}/triage", response_model=TriageResponse)
def triage_known_alert(alert_id: str):
    """Run the pipeline on an alert already in data/raw_alerts.json, by id."""
    alert = _load_alerts().get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"unknown alert_id: {alert_id}")
    return _run_pipeline(alert)
