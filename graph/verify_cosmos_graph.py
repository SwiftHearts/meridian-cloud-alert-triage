"""
Sanity-checks the Cosmos DB graph after a run of migrate_to_cosmos.py: prints
vertex/edge counts and runs one sample context-expansion query, the same way
ingestion/verify_index.py checks the Search index and graph/inspect_graph.py
checks the NetworkX graph.

Run: python graph/verify_cosmos_graph.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cosmos_graph import get_client, summarize_context  # noqa: E402


def main():
    gclient = get_client()

    vertex_count = gclient.submit("g.V().count()").all().result()[0]
    edge_count = gclient.submit("g.E().count()").all().result()[0]
    print(f"Cosmos DB graph: {vertex_count} vertices, {edge_count} edges.")

    by_label = gclient.submit("g.V().groupCount().by(label)").all().result()[0]
    print(f"Vertices by type: {by_label}")

    by_relation = gclient.submit("g.E().groupCount().by(label)").all().result()[0]
    print(f"Edges by relation: {by_relation}")

    sample_host = gclient.submit("g.V().hasLabel('host').limit(1).values('value')").all().result()
    if sample_host:
        host = sample_host[0]
        print(f"\nSample context expansion for host:{host} (2 hops):")
        print(summarize_context(gclient, "host", host, hops=2))
    else:
        print("\nNo host vertices found — did migrate_to_cosmos.py run?")

    gclient.close()


if __name__ == "__main__":
    main()
