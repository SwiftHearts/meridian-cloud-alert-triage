"""Pydantic request/response models for the Meridian Cloud Alert Triage API."""

from typing import Literal, Optional

from pydantic import BaseModel

AlertType = Literal[
    "anomalous_login",
    "suspicious_process",
    "unusual_outbound_network",
    "privilege_escalation",
    "lateral_movement",
]
Label = Literal["false_positive", "needs_investigation", "true_positive"]
Severity = Literal["low", "medium", "high", "critical"]


class AlertIn(BaseModel):
    """A raw alert submitted for triage — same shape as data/raw_alerts.json records."""

    alert_id: Optional[str] = None
    timestamp: Optional[str] = None
    host: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    process: Optional[str] = None
    command_line: Optional[str] = None
    alert_type: AlertType
    raw_description: str


class PlaybookChunk(BaseModel):
    content: str
    doc_title: str
    section_title: str
    source: str
    technique_id: Optional[str] = None


class Verdict(BaseModel):
    label: Label
    severity: Severity
    rationale: str
    recommended_actions: list[str]
    reviewed: bool
    revision_count: int
    reviewer_note: Optional[str] = None
    degraded_components: Optional[list[str]] = None


class TriageResponse(BaseModel):
    alert_id: Optional[str] = None
    verdict: Verdict
    playbook_context: list[PlaybookChunk]
    graph_context: str
