"""
Tests for agents/triage_graph.py: the pure formatting/routing helpers, each
node's fallback behavior in isolation, and the assembled graph end-to-end
with every external dependency mocked. The degradation-path tests here are
the automated form of the manual scenarios (Cosmos down, analyst LLM down,
reviewer LLM down, and the timeout deadline itself) that were hand-verified
against the live pipeline when this fallback handling was first built.
"""

import time
from types import SimpleNamespace

import pytest
import triage_graph as tg


def _stub_llm(invoke_fn):
    """_analyst_llm/_reviewer_llm are pydantic-backed LangChain Runnables
    (AzureChatOpenAI.with_structured_output(...)), which reject
    monkeypatch.setattr(obj, "invoke", ...) on the instance — pydantic's
    __setattr__ only allows declared fields. Swapping the whole module-level
    name for a plain stub with an .invoke() sidesteps that; analyst_node/
    reviewer_node only ever call `_analyst_llm.invoke(...)` looked up fresh
    from the module globals, so this is a transparent substitution."""
    return SimpleNamespace(invoke=invoke_fn)


ALERT = {
    "alert_id": "ALERT-TEST-1",
    "host": "WKS-TEST",
    "user": "jdoe",
    "alert_type": "lateral_movement",
    "raw_description": "test alert",
}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_format_playbook_context_empty():
    assert tg._format_playbook_context([]) == "No matching playbook/ATT&CK guidance found."


def test_format_playbook_context_with_technique_id():
    chunks = [
        {
            "source": "mitre",
            "doc_title": "Lateral Movement",
            "section_title": "PsExec",
            "technique_id": "T1021",
            "content": "Adversaries may use PsExec.",
        }
    ]
    formatted = tg._format_playbook_context(chunks)
    assert "[mitre] Lateral Movement — PsExec (T1021)" in formatted
    assert "Adversaries may use PsExec." in formatted


def test_format_playbook_context_without_technique_id():
    chunks = [
        {
            "source": "playbook",
            "doc_title": "General Playbook",
            "section_title": "Intro",
            "technique_id": None,
            "content": "Some guidance.",
        }
    ]
    formatted = tg._format_playbook_context(chunks)
    assert "(None)" not in formatted
    assert "General Playbook — Intro\nSome guidance." in formatted


# ---------------------------------------------------------------------------
# _run_with_deadline
# ---------------------------------------------------------------------------


def test_run_with_deadline_returns_result_within_budget():
    assert tg._run_with_deadline(lambda: 42, timeout=2) == 42


def test_run_with_deadline_raises_on_timeout():
    def slow():
        time.sleep(5)
        return "too late"

    start = time.time()
    with pytest.raises(Exception):
        tg._run_with_deadline(slow, timeout=0.3)
    assert time.time() - start < 2  # raised at the deadline, not after slow() finished


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def test_route_after_analyst_degraded_skips_reviewer():
    assert tg.route_after_analyst({"degraded": ["analyst"]}) == "finalize"


def test_route_after_analyst_healthy_goes_to_reviewer():
    assert tg.route_after_analyst({"degraded": []}) == "reviewer"


def test_route_after_review_approved():
    assert tg.route_after_review({"review_feedback": None, "revision_count": 0}) == "finalize"


def test_route_after_review_rejected_under_max_revisions():
    assert tg.route_after_review({"review_feedback": "fix it", "revision_count": 0}) == "revise"


def test_route_after_review_rejected_at_max_revisions():
    assert tg.route_after_review({"review_feedback": "fix it", "revision_count": tg.MAX_REVISIONS}) == "finalize"


# ---------------------------------------------------------------------------
# finalize_node
# ---------------------------------------------------------------------------


def _base_state(**overrides):
    state = {
        "analyst_verdict": {
            "label": "true_positive",
            "severity": "high",
            "rationale": "because",
            "recommended_actions": ["do something"],
        },
        "review_feedback": None,
        "revision_count": 0,
        "degraded": [],
    }
    state.update(overrides)
    return state


def test_finalize_node_clean_run_has_no_degraded_key():
    result = tg.finalize_node(_base_state())
    verdict = result["final_verdict"]
    assert verdict["reviewed"] is True
    assert "degraded_components" not in verdict
    assert "reviewer_note" not in verdict


def test_finalize_node_records_reviewer_feedback():
    result = tg.finalize_node(_base_state(review_feedback="missing correlation"))
    verdict = result["final_verdict"]
    assert verdict["reviewer_note"] == "missing correlation"


def test_finalize_node_reviewer_degraded():
    result = tg.finalize_node(_base_state(degraded=["reviewer"]))
    verdict = result["final_verdict"]
    assert verdict["reviewed"] is False
    assert verdict["degraded_components"] == ["reviewer"]
    assert "not independently checked" in verdict["reviewer_note"]


def test_finalize_node_analyst_degraded_no_reviewer_note():
    result = tg.finalize_node(_base_state(degraded=["analyst"]))
    verdict = result["final_verdict"]
    assert verdict["reviewed"] is False
    assert verdict["degraded_components"] == ["analyst"]
    assert "reviewer_note" not in verdict


# ---------------------------------------------------------------------------
# gather_context — mocked RAG + graph lookups
# ---------------------------------------------------------------------------


def test_gather_context_happy_path(monkeypatch):
    monkeypatch.setattr(tg, "retrieve_playbook_guidance", lambda alert: [{"content": "guidance"}])
    monkeypatch.setattr(tg, "summarize_context", lambda client, etype, value, hops: "graph summary")

    result = tg.gather_context({"alert": ALERT, "degraded": []})

    assert result["playbook_context"] == [{"content": "guidance"}]
    assert result["graph_context"] == "graph summary"
    assert result["degraded"] == []


def test_gather_context_playbook_failure_degrades(monkeypatch):
    def boom(alert):
        raise RuntimeError("Azure Search down")

    monkeypatch.setattr(tg, "retrieve_playbook_guidance", boom)
    monkeypatch.setattr(tg, "summarize_context", lambda client, etype, value, hops: "graph summary")

    result = tg.gather_context({"alert": ALERT, "degraded": []})

    assert result["playbook_context"] == []
    assert result["graph_context"] == "graph summary"
    assert result["degraded"] == ["playbook_context"]


def test_gather_context_graph_failure_degrades(monkeypatch):
    def boom(client, etype, value, hops):
        raise RuntimeError("Cosmos down")

    monkeypatch.setattr(tg, "retrieve_playbook_guidance", lambda alert: [])
    monkeypatch.setattr(tg, "summarize_context", boom)

    result = tg.gather_context({"alert": ALERT, "degraded": []})

    assert "unavailable" in result["graph_context"]
    assert result["degraded"] == ["graph_context"]


def test_gather_context_both_fail_accumulates_degraded(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(tg, "retrieve_playbook_guidance", boom)
    monkeypatch.setattr(tg, "summarize_context", boom)

    result = tg.gather_context({"alert": ALERT, "degraded": []})

    assert set(result["degraded"]) == {"playbook_context", "graph_context"}


# ---------------------------------------------------------------------------
# analyst_node — mocked LLM
# ---------------------------------------------------------------------------


def _analyst_state(**overrides):
    state = {
        "alert": ALERT,
        "playbook_context": [],
        "graph_context": "no activity",
        "degraded": [],
    }
    state.update(overrides)
    return state


def test_analyst_node_success(monkeypatch):
    verdict = tg.AnalystVerdict(
        label="false_positive",
        severity="low",
        rationale="benign",
        recommended_actions=["close"],
    )
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt: verdict))

    result = tg.analyst_node(_analyst_state())

    assert result["analyst_verdict"]["label"] == "false_positive"
    assert result["revision_count"] == 0
    assert result["degraded"] == []


def test_analyst_node_revision_increments_count(monkeypatch):
    verdict = tg.AnalystVerdict(
        label="true_positive", severity="high", rationale="r", recommended_actions=[]
    )
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt: verdict))

    result = tg.analyst_node(_analyst_state(review_feedback="do better", revision_count=0))

    assert result["revision_count"] == 1


def test_analyst_node_llm_failure_falls_back_safely(monkeypatch):
    def boom(prompt):
        raise RuntimeError("Azure OpenAI outage")

    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(boom))

    result = tg.analyst_node(_analyst_state())

    assert result["analyst_verdict"]["label"] == "needs_investigation"
    assert result["degraded"] == ["analyst"]


def test_analyst_node_preserves_prior_degraded_components(monkeypatch):
    verdict = tg.AnalystVerdict(
        label="true_positive", severity="high", rationale="r", recommended_actions=[]
    )
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt: verdict))

    result = tg.analyst_node(_analyst_state(degraded=["graph_context"]))

    assert result["degraded"] == ["graph_context"]


# ---------------------------------------------------------------------------
# reviewer_node — mocked LLM
# ---------------------------------------------------------------------------


def _reviewer_state(**overrides):
    state = {
        "alert": ALERT,
        "playbook_context": [],
        "graph_context": "no activity",
        "analyst_verdict": {
            "label": "true_positive",
            "severity": "high",
            "rationale": "r",
            "recommended_actions": [],
        },
        "degraded": [],
    }
    state.update(overrides)
    return state


def test_reviewer_node_approves(monkeypatch):
    result_obj = tg.ReviewResult(approved=True, feedback="")
    monkeypatch.setattr(tg, "_reviewer_llm", _stub_llm(lambda prompt: result_obj))

    result = tg.reviewer_node(_reviewer_state())

    assert result["review_feedback"] is None
    assert result["degraded"] == []


def test_reviewer_node_rejects_with_feedback(monkeypatch):
    result_obj = tg.ReviewResult(approved=False, feedback="ignores graph correlation")
    monkeypatch.setattr(tg, "_reviewer_llm", _stub_llm(lambda prompt: result_obj))

    result = tg.reviewer_node(_reviewer_state())

    assert result["review_feedback"] == "ignores graph correlation"


def test_reviewer_node_llm_failure_fails_open(monkeypatch):
    def boom(prompt):
        raise RuntimeError("Azure OpenAI outage")

    monkeypatch.setattr(tg, "_reviewer_llm", _stub_llm(boom))

    result = tg.reviewer_node(_reviewer_state())

    assert result["review_feedback"] is None
    assert result["degraded"] == ["reviewer"]


# ---------------------------------------------------------------------------
# Full graph — every external dependency mocked
# ---------------------------------------------------------------------------


def _patch_context_lookups(monkeypatch, playbook=None, graph="no related activity"):
    monkeypatch.setattr(tg, "retrieve_playbook_guidance", lambda alert: playbook or [])
    monkeypatch.setattr(tg, "summarize_context", lambda client, etype, value, hops: graph)


def test_full_graph_happy_path(monkeypatch):
    _patch_context_lookups(monkeypatch)
    analyst_verdict = tg.AnalystVerdict(
        label="true_positive", severity="critical", rationale="r", recommended_actions=["escalate"]
    )
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt: analyst_verdict))
    monkeypatch.setattr(tg, "_reviewer_llm", _stub_llm(lambda prompt: tg.ReviewResult(approved=True, feedback="")))

    final = tg.run_triage(ALERT)["final_verdict"]

    assert final["label"] == "true_positive"
    assert final["reviewed"] is True
    assert "degraded_components" not in final


def test_full_graph_analyst_down_skips_reviewer(monkeypatch):
    _patch_context_lookups(monkeypatch)
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt: (_ for _ in ()).throw(RuntimeError("down"))))

    reviewer_calls = []
    monkeypatch.setattr(
        tg,
        "_reviewer_llm",
        _stub_llm(lambda prompt: reviewer_calls.append(1) or tg.ReviewResult(approved=True, feedback="")),
    )

    final = tg.run_triage(ALERT)["final_verdict"]

    assert final["label"] == "needs_investigation"
    assert final["degraded_components"] == ["analyst"]
    assert reviewer_calls == []  # reviewer must never be called on a fallback verdict


def test_full_graph_reviewer_down_ships_unreviewed_verdict(monkeypatch):
    _patch_context_lookups(monkeypatch)
    analyst_verdict = tg.AnalystVerdict(
        label="true_positive", severity="high", rationale="r", recommended_actions=[]
    )
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt: analyst_verdict))
    monkeypatch.setattr(tg, "_reviewer_llm", _stub_llm(lambda prompt: (_ for _ in ()).throw(RuntimeError("down"))))

    final = tg.run_triage(ALERT)["final_verdict"]

    assert final["label"] == "true_positive"  # analyst's verdict still ships
    assert final["reviewed"] is False
    assert final["degraded_components"] == ["reviewer"]


def test_full_graph_revision_loop_runs_once_then_finalizes(monkeypatch):
    _patch_context_lookups(monkeypatch)

    verdicts = [
        tg.AnalystVerdict(label="false_positive", severity="low", rationale="v1", recommended_actions=[]),
        tg.AnalystVerdict(label="true_positive", severity="high", rationale="v2", recommended_actions=[]),
    ]
    monkeypatch.setattr(tg, "_analyst_llm", _stub_llm(lambda prompt, _it=iter(verdicts): next(_it)))

    reviews = [
        tg.ReviewResult(approved=False, feedback="reconsider — graph shows correlation"),
        tg.ReviewResult(approved=True, feedback=""),
    ]
    monkeypatch.setattr(tg, "_reviewer_llm", _stub_llm(lambda prompt, _it=iter(reviews): next(_it)))

    final = tg.run_triage(ALERT)["final_verdict"]

    assert final["rationale"] == "v2"
    assert final["revision_count"] == 1
    assert final["reviewed"] is True
