"""
Tests for agents/rag_retrieval.py: retrieve_playbook_guidance's request
construction and response mapping, with the Azure OpenAI embeddings client
and Azure Search client both mocked. Not testing that Azure Search actually
finds relevant chunks — that's what eval/run_eval.py's accuracy numbers are
for — just that this function builds the right query and shapes the
response correctly.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import rag_retrieval as rr

ALERT = {
    "alert_id": "ALERT-1",
    "alert_type": "lateral_movement",
    "raw_description": "suspicious lateral movement",
}


def _fake_embedding_response(vector):
    return SimpleNamespace(data=[SimpleNamespace(embedding=vector)])


def test_retrieve_playbook_guidance_maps_results(monkeypatch):
    monkeypatch.setattr(
        rr._openai_client.embeddings, "create", lambda model, input: _fake_embedding_response([0.1, 0.2])
    )
    monkeypatch.setattr(
        rr._search_client,
        "search",
        lambda **kwargs: [
            {
                "content": "guidance text",
                "doc_title": "Lateral Movement Playbook",
                "section_title": "Detection",
                "source": "playbook",
                "technique_id": "T1021",
            }
        ],
    )

    result = rr.retrieve_playbook_guidance(ALERT, k=3)

    assert result == [
        {
            "content": "guidance text",
            "doc_title": "Lateral Movement Playbook",
            "section_title": "Detection",
            "source": "playbook",
            "technique_id": "T1021",
        }
    ]


def test_retrieve_playbook_guidance_normalizes_missing_technique_id(monkeypatch):
    monkeypatch.setattr(
        rr._openai_client.embeddings, "create", lambda model, input: _fake_embedding_response([0.1])
    )
    monkeypatch.setattr(
        rr._search_client,
        "search",
        lambda **kwargs: [
            {
                "content": "c",
                "doc_title": "d",
                "section_title": "s",
                "source": "src",
                "technique_id": "",  # falsy, not None
            }
        ],
    )

    result = rr.retrieve_playbook_guidance(ALERT)

    assert result[0]["technique_id"] is None


def test_retrieve_playbook_guidance_filters_by_alert_type_and_k(monkeypatch):
    monkeypatch.setattr(
        rr._openai_client.embeddings, "create", lambda model, input: _fake_embedding_response([0.1])
    )
    search_mock = MagicMock(return_value=[])
    monkeypatch.setattr(rr._search_client, "search", search_mock)

    rr.retrieve_playbook_guidance(ALERT, k=5)

    _, kwargs = search_mock.call_args
    assert kwargs["top"] == 5
    assert "lateral_movement" in kwargs["filter"]
    assert kwargs["vector_queries"][0].k_nearest_neighbors == 5


def test_retrieve_playbook_guidance_embeds_raw_description(monkeypatch):
    embed_mock = MagicMock(return_value=_fake_embedding_response([0.1]))
    monkeypatch.setattr(rr._openai_client.embeddings, "create", embed_mock)
    monkeypatch.setattr(rr._search_client, "search", lambda **kwargs: [])

    rr.retrieve_playbook_guidance(ALERT)

    _, kwargs = embed_mock.call_args
    assert kwargs["input"] == [ALERT["raw_description"]]
