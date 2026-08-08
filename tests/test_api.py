"""
Tests for api/main.py. The pipeline itself (api.main.run_triage) is always
mocked here — these tests are about the API layer's own behavior (routing,
404s, error mapping, request/response schemas), not the triage logic, which
is covered by tests/test_triage_graph.py.
"""

from fastapi.testclient import TestClient

import api.main as api_main

client = TestClient(api_main.app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_alerts_respects_limit():
    resp = client.get("/alerts", params={"limit": 5})
    assert resp.status_code == 200
    assert len(resp.json()) == 5


def test_list_alerts_filters_by_type():
    resp = client.get("/alerts", params={"alert_type": "lateral_movement", "limit": 200})
    assert resp.status_code == 200
    body = resp.json()
    assert body  # the synthetic dataset has at least one of each type
    assert all(a["alert_type"] == "lateral_movement" for a in body)


def test_get_known_alert_round_trips():
    known_id = client.get("/alerts", params={"limit": 1}).json()[0]["alert_id"]
    resp = client.get(f"/alerts/{known_id}")
    assert resp.status_code == 200
    assert resp.json()["alert_id"] == known_id


def test_get_unknown_alert_404s():
    resp = client.get("/alerts/does-not-exist")
    assert resp.status_code == 404


def _fake_triage_state(alert, **verdict_overrides):
    verdict = {
        "label": "true_positive",
        "severity": "high",
        "rationale": "test rationale",
        "recommended_actions": ["do a thing"],
        "reviewed": True,
        "revision_count": 0,
    }
    verdict.update(verdict_overrides)
    return {
        "alert": alert,
        "playbook_context": [],
        "graph_context": "no related activity",
        "final_verdict": verdict,
    }


def test_triage_endpoint_returns_pipeline_result(monkeypatch):
    monkeypatch.setattr(api_main, "run_triage", lambda alert: _fake_triage_state(alert))

    resp = client.post(
        "/triage",
        json={
            "host": "WKS-1",
            "alert_type": "lateral_movement",
            "raw_description": "test",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"]["label"] == "true_positive"
    assert body["graph_context"] == "no related activity"


def test_triage_endpoint_surfaces_degraded_components(monkeypatch):
    """Regression test: api/schemas.py's Verdict model previously had no
    degraded_components field, so Pydantic silently dropped it (v2 default
    is to ignore unknown fields) — a degraded triage result looked identical
    to a healthy one over the API. Verdict now declares the field; this
    confirms it actually reaches the response."""
    monkeypatch.setattr(
        api_main,
        "run_triage",
        lambda alert: _fake_triage_state(alert, reviewed=False, degraded_components=["reviewer"]),
    )

    resp = client.post(
        "/triage",
        json={"host": "WKS-1", "alert_type": "lateral_movement", "raw_description": "test"},
    )

    assert resp.status_code == 200
    assert resp.json()["verdict"]["degraded_components"] == ["reviewer"]


def test_triage_endpoint_maps_pipeline_error_to_502(monkeypatch):
    def boom(alert):
        raise RuntimeError("pipeline exploded")

    monkeypatch.setattr(api_main, "run_triage", boom)

    resp = client.post(
        "/triage",
        json={"host": "WKS-1", "alert_type": "lateral_movement", "raw_description": "test"},
    )

    assert resp.status_code == 502
    assert "pipeline exploded" in resp.json()["detail"]


def test_triage_endpoint_rejects_invalid_alert_type():
    resp = client.post(
        "/triage",
        json={"host": "WKS-1", "alert_type": "not_a_real_type", "raw_description": "test"},
    )
    assert resp.status_code == 422


def test_triage_known_alert_by_id(monkeypatch):
    known_id = client.get("/alerts", params={"limit": 1}).json()[0]["alert_id"]
    monkeypatch.setattr(api_main, "run_triage", lambda alert: _fake_triage_state(alert))

    resp = client.post(f"/alerts/{known_id}/triage")

    assert resp.status_code == 200
    assert resp.json()["alert_id"] == known_id


def test_triage_unknown_alert_by_id_404s_without_calling_pipeline(monkeypatch):
    calls = []
    monkeypatch.setattr(api_main, "run_triage", lambda alert: calls.append(alert))

    resp = client.post("/alerts/does-not-exist/triage")

    assert resp.status_code == 404
    assert calls == []
