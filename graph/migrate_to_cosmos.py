"""
One-time migration: loads the existing NetworkX entity graph
(graph/entity_graph.json — 192 nodes, 676 edges, built by entity_graph.py
from all 260 alerts) and upserts it into Azure Cosmos DB's Gremlin API, the
real graph database that agents/triage_graph.py queries at runtime via
graph/cosmos_graph.py.

Idempotent (checks before inserting), safe to re-run — e.g. after adding more
alerts and rebuilding entity_graph.json.

Requires the Cosmos DB Gremlin resource to already exist (see README "Graph
database setup") and COSMOS_GREMLIN_ENDPOINT / COSMOS_KEY / COSMOS_DATABASE /
COSMOS_GRAPH in .env.

Run: python graph/migrate_to_cosmos.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cosmos_graph import get_client  # noqa: E402
from entity_graph import load_graph  # noqa: E402


def _vertex_exists(gclient, node_id: str) -> bool:
    return gclient.submit("g.V(nid).count()", {"nid": node_id}).all().result()[0] > 0


def _upsert_vertex(gclient, node_id: str, node_type: str, value: str):
    if _vertex_exists(gclient, node_id):
        return
    gclient.submit(
        "g.addV(vlabel).property('id', vid).property('pk', pk).property('value', value)",
        {"vlabel": node_type, "vid": node_id, "pk": node_type, "value": value},
    ).all().result()


def _edge_exists(gclient, edge_id: str) -> bool:
    return gclient.submit("g.E(eid).count()", {"eid": edge_id}).all().result()[0] > 0


def _upsert_edge(gclient, edge_id: str, src: str, dst: str, relation: str,
                  alert_id: str, alert_type: str, timestamp: str):
    if _edge_exists(gclient, edge_id):
        return
    gclient.submit(
        "g.V(src).addE(elabel).to(g.V(dst))"
        ".property('id', eid).property('alert_id', aid)"
        ".property('alert_type', atype).property('timestamp', ts)",
        {
            "src": src, "dst": dst, "elabel": relation, "eid": edge_id,
            "aid": alert_id, "atype": alert_type, "ts": timestamp,
        },
    ).all().result()


def migrate():
    graph = load_graph()
    gclient = get_client()

    total_nodes = graph.number_of_nodes()
    total_edges = graph.number_of_edges()
    print(f"Migrating {total_nodes} nodes and {total_edges} edges to Cosmos DB...")

    for i, (node_id, attrs) in enumerate(graph.nodes(data=True), 1):
        _upsert_vertex(gclient, node_id, attrs["type"], attrs["value"])
        if i % 50 == 0 or i == total_nodes:
            print(f"  vertices: {i}/{total_nodes}")

    for i, (u, v, attrs) in enumerate(graph.edges(data=True), 1):
        edge_id = f"{attrs['alert_id']}-{attrs['relation']}"
        _upsert_edge(gclient, edge_id, u, v, attrs["relation"],
                     attrs["alert_id"], attrs["alert_type"], attrs["timestamp"])
        if i % 100 == 0 or i == total_edges:
            print(f"  edges: {i}/{total_edges}")

    gclient.close()
    print("Migration complete.")


if __name__ == "__main__":
    migrate()
