"""
Tests for graph/cosmos_graph.py. The Gremlin dialect quirks this module
works around (no .hasNext(), no bound .times(), no plain multi-ID g.V()
lookups on a partitioned graph) were verified against the live Cosmos DB
instance when this module was built — these tests aren't re-proving Cosmos
behaves a certain way, they're pinning summarize_context's own orchestration
and formatting logic by faking what _submit returns for each of its four
queries in turn, so a refactor here can't silently break the output shape
agents/triage_graph.py depends on.
"""

import cosmos_graph as cg


def test_node_id_format():
    assert cg._node_id("host", "WKS-OFITZGERALD") == "host:WKS-OFITZGERALD"


def test_summarize_context_no_activity(monkeypatch):
    monkeypatch.setattr(cg, "_submit", lambda gclient, query, bindings: [0])

    result = cg.summarize_context(gclient=object(), entity_type="host", value="WKS-X", hops=2)

    assert result == "No graph activity found for host:WKS-X."


def test_summarize_context_formats_related_activity(monkeypatch):
    node_id = "host:WKS-1"
    ip_id = "ip:10.0.0.5"

    responses = iter(
        [
            [1],  # existence check: g.V(nid).count()
            [node_id, ip_id],  # neighborhood BFS ids
            [  # node values
                {"id": node_id, "value": "WKS-1"},
                {"id": ip_id, "value": "10.0.0.5"},
            ],
            [  # edges
                {
                    "src": node_id,
                    "dst": ip_id,
                    "relation": "has_ip",
                    "alert_id": "ALERT-9",
                    "alert_type": "lateral_movement",
                    "timestamp": "2026-01-01T00:00:00",
                }
            ],
        ]
    )
    monkeypatch.setattr(cg, "_submit", lambda gclient, query, bindings: next(responses))

    result = cg.summarize_context(gclient=object(), entity_type="host", value="WKS-1", hops=2)

    assert "Related activity within 2 hop(s) of host:WKS-1:" in result
    assert "WKS-1 --has_ip--> 10.0.0.5 (lateral_movement, ALERT-9)" in result


def test_summarize_context_sorts_edges_by_timestamp(monkeypatch):
    node_id = "host:WKS-1"
    other_id = "host:WKS-2"

    responses = iter(
        [
            [1],
            [node_id, other_id],
            [{"id": node_id, "value": "WKS-1"}, {"id": other_id, "value": "WKS-2"}],
            [
                {
                    "src": node_id,
                    "dst": other_id,
                    "relation": "connected_to",
                    "alert_id": "ALERT-LATE",
                    "alert_type": "lateral_movement",
                    "timestamp": "2026-02-01T00:00:00",
                },
                {
                    "src": node_id,
                    "dst": other_id,
                    "relation": "connected_to",
                    "alert_id": "ALERT-EARLY",
                    "alert_type": "lateral_movement",
                    "timestamp": "2026-01-01T00:00:00",
                },
            ],
        ]
    )
    monkeypatch.setattr(cg, "_submit", lambda gclient, query, bindings: next(responses))

    result = cg.summarize_context(gclient=object(), entity_type="host", value="WKS-1", hops=1)
    lines = [line for line in result.splitlines() if "ALERT-" in line]

    assert "ALERT-EARLY" in lines[0]
    assert "ALERT-LATE" in lines[1]
