"""
Gremlin-backed equivalent of entity_graph.py's context-expansion API — same
summarize_context() output shape, but querying Azure Cosmos DB for Apache
Gremlin (a real graph database) instead of an in-memory NetworkX graph, so
agents/triage_graph.py hits an actual graph database at query time rather
than a JSON file loaded into memory.

Schema (populated by migrate_to_cosmos.py from graph/entity_graph.json):
  vertex: id = "{type}:{value}" (e.g. "host:WKS-OFITZGERALD"), label = type
          (host/user/ip/process), properties: value, pk (= type — see
          partition-key note below).
  edge:   id = "{alert_id}-{relation}" (unique since one alert contributes at
          most one edge per relation), label = relation (associated_with/
          has_ip/connected_to/executed), properties: alert_id, alert_type,
          timestamp.

Partition key: entity type (host/user/ip/process, via the `pk` vertex
property). With only ~200 vertices this graph is far too small for
partitioning to matter for performance — the choice here is about having a
defensible one: queries are always anchored on a specific host or user, and
every edge crosses a type boundary (host->ip, host->process, user->host), so
no partitioning scheme avoids cross-partition traversal for this access
pattern. Grouping by type at least keeps each partition semantically
coherent and is easy to reason about.

Requires COSMOS_GREMLIN_ENDPOINT / COSMOS_KEY / COSMOS_DATABASE / COSMOS_GRAPH
in .env — see README "Graph database setup" for how to provision the Cosmos
DB (Gremlin API) account these point at.
"""

import os

from dotenv import load_dotenv
from gremlin_python.driver import client, serializer

load_dotenv()

COSMOS_GREMLIN_ENDPOINT = os.environ["COSMOS_GREMLIN_ENDPOINT"]
COSMOS_KEY = os.environ["COSMOS_KEY"]
COSMOS_DATABASE = os.environ["COSMOS_DATABASE"]
COSMOS_GRAPH = os.environ["COSMOS_GRAPH"]


def get_client() -> client.Client:
    """A Gremlin client connected to the Cosmos DB graph. Long-lived — callers
    should hold one client for the process lifetime rather than reconnecting
    per query (same pattern as the Azure Search/OpenAI clients elsewhere in
    this project)."""
    return client.Client(
        COSMOS_GREMLIN_ENDPOINT,
        "g",
        username=f"/dbs/{COSMOS_DATABASE}/colls/{COSMOS_GRAPH}",
        password=COSMOS_KEY,
        message_serializer=serializer.GraphSONSerializersV2d0(),
    )


def _node_id(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value}"


def _submit(gclient: client.Client, query: str, bindings: dict):
    return gclient.submit(query, bindings).all().result()


def _neighborhood_ids(gclient: client.Client, node_id: str, hops: int) -> set[str]:
    """Node ids within `hops` of node_id, ignoring edge direction — the
    Gremlin equivalent of nx.ego_graph(graph, node_id, radius=hops,
    undirected=True), via a visited-set BFS.

    `hops` is inlined as a literal rather than a bound parameter: Cosmos DB's
    Gremlin implementation rejects a bound variable in `.times()`. Safe here
    since `hops` is always an internal int (GRAPH_CONTEXT_HOPS), never
    user-supplied text."""
    query = (
        "g.V(nid).aggregate('seen')"
        f".repeat(both().dedup().where(without('seen')).aggregate('seen')).times({int(hops)})"
        ".cap('seen').unfold().id()"
    )
    ids = _submit(gclient, query, {"nid": node_id})
    return set(ids) | {node_id}


def _node_values(gclient: client.Client, node_ids: list[str]) -> dict[str, str]:
    # g.V(ids) with a plain id list isn't accepted by Cosmos's Gremlin dialect
    # on a partitioned graph (it wants composite [pk, id] pairs) — hasId(within(...))
    # is the standard workaround.
    query = "g.V().hasId(within(ids)).project('id', 'value').by(id).by('value')"
    rows = _submit(gclient, query, {"ids": node_ids})
    return {row["id"]: row["value"] for row in rows}


def _neighborhood_edges(gclient: client.Client, node_ids: list[str]) -> list[dict]:
    """Edges where both endpoints are in node_ids — the Gremlin equivalent of
    graph.subgraph(nearby.nodes).edges(data=True)."""
    query = (
        "g.V().hasId(within(ids)).bothE().dedup()"
        ".where(otherV().hasId(within(ids)))"
        ".project('src', 'dst', 'relation', 'alert_id', 'alert_type', 'timestamp')"
        ".by(outV().id()).by(inV().id()).by(label)"
        ".by('alert_id').by('alert_type').by('timestamp')"
    )
    return _submit(gclient, query, {"ids": node_ids})


def summarize_context(gclient: client.Client, entity_type: str, value: str, hops: int = 1) -> str:
    """Human/LLM-readable summary of an entity's related alerts, for
    injecting into a triage prompt as correlated-activity context. Same
    output format as entity_graph.summarize_context()."""
    node_id = _node_id(entity_type, value)
    if _submit(gclient, "g.V(nid).count()", {"nid": node_id})[0] == 0:
        return f"No graph activity found for {entity_type}:{value}."

    neighborhood = _neighborhood_ids(gclient, node_id, hops)
    node_ids = list(neighborhood)
    values = _node_values(gclient, node_ids)
    edges = _neighborhood_edges(gclient, node_ids)
    edges.sort(key=lambda e: e["timestamp"])

    lines = [f"Related activity within {hops} hop(s) of {entity_type}:{value}:"]
    for edge in edges:
        u_label, v_label = values[edge["src"]], values[edge["dst"]]
        lines.append(
            f"  - [{edge['timestamp']}] {u_label} --{edge['relation']}--> {v_label} "
            f"({edge['alert_type']}, {edge['alert_id']})"
        )
    return "\n".join(lines)
