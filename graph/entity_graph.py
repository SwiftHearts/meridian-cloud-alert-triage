"""
Builds an entity relationship graph from Meridian Cloud alerts, linking
users, hosts, IPs, and processes so a single alert can be expanded into
its broader context (what else has this host/user/IP touched recently).

Every alert contributes up to four typed edges:
  user  --associated_with--> host       (who was active on this host)
  host  --has_ip-->          source_ip  (host's own network identity)
  host  --connected_to-->    dest_ip    (outbound / lateral-movement target)
  host  --executed-->        process

Because a dest_ip in one alert is often the same address a different host
reports as its own source_ip elsewhere, the shared ip node is what links
otherwise-unrelated alerts into a single investigation path (e.g. lateral
movement from host A to host B, followed by a separate suspicious-process
alert on host B).

Intended as a graph-lookup tool for the Phase 4 multi-agent orchestration
layer (context expansion for a given alert), and usable standalone for ad
hoc investigation. No external services required — pure NetworkX over
data/raw_alerts.json.

Run: python graph/entity_graph.py
"""

import json
from collections import defaultdict
from pathlib import Path

import networkx as nx

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
GRAPH_DIR = Path(__file__).resolve().parent
ALERTS_PATH = DATA_DIR / "raw_alerts.json"
GRAPH_PATH = GRAPH_DIR / "entity_graph.json"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

# Helper functions for building a directed multigraph of entities and their relationships 
# from alert data.
def _node_id(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value}"

# Add an entity node to the graph if it doesn't already exist, and return its node ID.
def _add_entity(graph: nx.MultiDiGraph, entity_type: str, value) -> str | None:
    if not value:
        return None
    node_id = _node_id(entity_type, value)
    if node_id not in graph:
        graph.add_node(node_id, type=entity_type, value=value)
    return node_id

# Add a directed edge between two entity nodes in the graph, with metadata about the alert that 
# connects them. Graph stores nodes and edges. Di means directed, Multi means multiple edges 
# can exist between the same pair of nodes (e.g., multiple alerts linking the same user and host).
def _add_relationship(graph: nx.MultiDiGraph, src_id: str, dst_id: str, relation: str, alert: dict):
    graph.add_edge(
        src_id, dst_id,
        relation=relation,
        alert_id=alert["alert_id"],
        alert_type=alert["alert_type"],
        timestamp=alert["timestamp"],
    )

# Build the entity relationship graph from a list of alerts, extracting relevant entities and
# adding them to the graph along with their relationships. Each alert contributes up to four edges
# linking users, hosts, IPs, and processes.
def build_graph(alerts: list[dict]) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()

    # For each alert, extract relevant entities (user, host, source IP, destination IP, 
    # process) and add them to the graph. 
    for alert in alerts:
        host_id = _add_entity(graph, "host", alert.get("host"))
        user_id = _add_entity(graph, "user", alert.get("user"))
        src_ip_id = _add_entity(graph, "ip", alert.get("source_ip"))
        dst_ip_id = _add_entity(graph, "ip", alert.get("dest_ip"))
        process_id = _add_entity(graph, "process", alert.get("process"))

        # Add edges between entities based on the relationships defined in the alert. Each edge is
        # labeled with the type of relationship and metadata about the alert that connects them.
        if user_id and host_id:
            _add_relationship(graph, user_id, host_id, "associated_with", alert)
        if host_id and src_ip_id:
            _add_relationship(graph, host_id, src_ip_id, "has_ip", alert)
        if host_id and dst_ip_id:
            _add_relationship(graph, host_id, dst_ip_id, "connected_to", alert)
        if host_id and process_id:
            _add_relationship(graph, host_id, process_id, "executed", alert)

    return graph

# Convert the JSON into python objects, then build the graph.
def load_alerts(path: Path = ALERTS_PATH) -> list[dict]:
    return json.loads(path.read_text())

# Save the graph to a JSON compatible file in node-link format
def save_graph(graph: nx.MultiDiGraph, path: Path = GRAPH_PATH):
    path.write_text(json.dumps(nx.node_link_data(graph), indent=2))

# Load the graph from a JSON file in node-link format. Reads the file, 
# parses the JSON, and reconstructs the NetworkX graph object.
def load_graph(path: Path = GRAPH_PATH) -> nx.MultiDiGraph:
    return nx.node_link_graph(json.loads(path.read_text()))


# ---------------------------------------------------------------------------
# Context expansion — used to pull related activity for a given alert
# ---------------------------------------------------------------------------
# Query the graph 

# Given an entity type and value (e.g., host:host1), return a subgraph of all nodes and edges
# within a certain number of hops, ignoring edge direction. This allows for exploration of related
# activity in the graph, such as other alerts involving the same host or user.
def entity_context(graph: nx.MultiDiGraph, entity_type: str, value: str, hops: int = 1) -> nx.MultiDiGraph:
    """Subgraph of nodes/edges within `hops` of the given entity, ignoring
    edge direction (a shared ip/host/process links alerts either way)."""
    node_id = _node_id(entity_type, value)
    # If the entity node doesn't exist in the graph, return an empty graph. Otherwise, use NetworkX's 
    # ego_graph function to get all nodes within the specified number of hops, and return the 
    # subgraph containing those nodes.
    if node_id not in graph:
        return nx.MultiDiGraph()
    nearby = nx.ego_graph(graph, node_id, radius=hops, undirected=True)
    return graph.subgraph(nearby.nodes)

# Create a human-readable summary of an entity's related alerts, for injecting into a triage 
# prompt as correlated-activity context. This function generates a textual representation 
# of the subgraph around the specified entity, listing all related activity within the given 
# number of hops.
def summarize_context(graph: nx.MultiDiGraph, entity_type: str, value: str, hops: int = 1) -> str:
    """Human/LLM-readable summary of an entity's related alerts, for
    injecting into a triage prompt as correlated-activity context."""
    node_id = _node_id(entity_type, value)
    if node_id not in graph:
        return f"No graph activity found for {entity_type}:{value}."

    # Get the subgraph of nodes and edges within the specified number of hops
    sub = entity_context(graph, entity_type, value, hops=hops)
    # Sort edges by timestamp for a chronological summary of related activity. Each edge represents
    # a relationship between two entities, and the summary includes the timestamp, source and
    # destination entities, the type of relationship, and the alert metadata.
    # e: edge tuple (u, v, d) where u and v are node IDs and d is the edge data dictionary
    edges = sorted(sub.edges(data=True), key=lambda e: e[2]["timestamp"])

    lines = [f"Related activity within {hops} hop(s) of {entity_type}:{value}:"]
    # For each edge in the sorted list, extract the source (u) and destination (v) nodes, and 
    # the dictionary (d) containing the relationship type, and the alert metadata.
    for u, v, d in edges:
        # Return only the values (e.g., host1, user1) rather than the full key:value node IDs 
        # (e.g., host:host1, user:user1)
        u_label, v_label = graph.nodes[u]["value"], graph.nodes[v]["value"]
        lines.append(
            f"  - [{d['timestamp']}] {u_label} --{d['relation']}--> {v_label} "
            f"({d['alert_type']}, {d['alert_id']})"
        )
    return "\n".join(lines)

# Main function to build the entity graph from raw alerts, save it to a file, and print a summary
# of the graph's structure, including the number of nodes and edges, and a breakdown of
# nodes by type and edges by relation. This function is executed when the script is run directly
def main():
    alerts = load_alerts()
    graph = build_graph(alerts)
    save_graph(graph)

    nodes_by_type = defaultdict(int)
    # Count the number of nodes of each type in the graph (e.g., host, user, ip, process) and store
    # the counts in a dictionary. This provides a summary of the graph's composition.
    for _, attrs in graph.nodes(data=True):
        nodes_by_type[attrs["type"]] += 1

    edges_by_relation = defaultdict(int)
    # Count the number of edges of each relation type in the graph (e.g., associated_with, has_ip, 
    # connected_to, executed) and store the counts in a dictionary. This provides a summary of
    # the graph's relationships.
    for _, _, attrs in graph.edges(data=True):
        edges_by_relation[attrs["relation"]] += 1

    print(f"Built graph from {len(alerts)} alerts: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges.")
    print(f"Nodes by type: {dict(nodes_by_type)}")
    print(f"Edges by relation: {dict(edges_by_relation)}")
    print(f"Saved to {GRAPH_PATH}")

# Run main() only if this script is executed directly, not when imported as a module.
if __name__ == "__main__":
    main()
