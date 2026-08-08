"""
Chunks the playbooks + MITRE ATT&CK subset, embeds them with Azure OpenAI
(text-embedding-3-small), and indexes them into Azure AI Search.

Scoped to a single named index (AZURE_SEARCH_INDEX_NAME, default
"meridian-cloud-security-index") inside a shared/free-tier Search service.
This script only ever creates/updates/queries that one index — it never
touches any other index (e.g. the Sterling Law contracts index) that may
live in the same service.

Requires a .env file (see .env.example) with:
  AZURE_SEARCH_ENDPOINT, AZURE_SEARCH_API_KEY, AZURE_SEARCH_INDEX_NAME
  AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_API_VERSION,
  AZURE_OPENAI_EMBEDDING_DEPLOYMENT, AZURE_OPENAI_EMBEDDING_DIMENSIONS

Run: python ingestion/index_to_azure_search.py
"""

import json
import os
import re
from pathlib import Path

from dotenv import load_dotenv
from openai import AzureOpenAI
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SimpleField,
    SearchableField,
    SearchField,
    SearchFieldDataType,
    VectorSearch,
    HnswAlgorithmConfiguration,
    VectorSearchProfile,
)

load_dotenv()

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SEARCH_ENDPOINT = os.environ["AZURE_SEARCH_ENDPOINT"]
SEARCH_API_KEY = os.environ["AZURE_SEARCH_API_KEY"]
SEARCH_INDEX_NAME = os.environ.get("AZURE_SEARCH_INDEX_NAME", "meridian-cloud-security-index")

OPENAI_ENDPOINT = os.environ["AZURE_OPENAI_ENDPOINT"]
OPENAI_API_KEY = os.environ["AZURE_OPENAI_API_KEY"]
OPENAI_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01")
EMBEDDING_DEPLOYMENT = os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-3-small")
EMBEDDING_DIMENSIONS = int(os.environ.get("AZURE_OPENAI_EMBEDDING_DIMENSIONS", "1536"))

# Playbook filename -> the alert_type(s) it covers, for retrieval filtering.
PLAYBOOK_ALERT_TYPES = {
    "general-triage-checklist.md": ["anomalous_login", "suspicious_process",
                                     "unusual_outbound_network", "privilege_escalation",
                                     "lateral_movement"],
    "failed-anomalous-logins.md": ["anomalous_login"],
    "suspicious-process-execution.md": ["suspicious_process"],
    "unusual-outbound-network-traffic.md": ["unusual_outbound_network"],
    "privilege-escalation.md": ["privilege_escalation"],
    "lateral-movement.md": ["lateral_movement"],
}


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def chunk_playbook(path: Path):
    """Split a playbook into one chunk per '## ' section, prefixed with the
    playbook title so each chunk retains standalone context."""
    text = path.read_text()
    title_match = re.match(r"# (.+)", text)
    title = title_match.group(1).strip() if title_match else path.stem

    sections = re.split(r"\n(?=## )", text)
    chunks = []
    for section in sections:
        section = section.strip()
        if not section or section.startswith("# "):
            continue
        heading_match = re.match(r"## (.+)", section)
        heading = heading_match.group(1).strip() if heading_match else "Overview"
        content = f"{title}\n\n{section}"
        chunks.append({
            "id": f"{path.stem}__{re.sub(r'[^a-z0-9]+', '-', heading.lower()).strip('-')}",
            "content": content,
            "source": "playbook",
            "doc_title": title,
            "section_title": heading,
            "alert_types": PLAYBOOK_ALERT_TYPES.get(path.name, []),
            "technique_id": None,
        })
    return chunks


def chunk_attack_techniques(path: Path):
    techniques = json.loads(path.read_text())
    chunks = []
    for t in techniques:
        content = (
            f"MITRE ATT&CK {t['technique_id']} — {t['name']}\n"
            f"Tactic(s): {t['tactic']}\n\n"
            f"{t['description']}"
        )
        chunks.append({
            "id": f"attack__{t['technique_id'].replace('.', '-')}",
            "content": content,
            "source": "mitre_attack",
            "doc_title": f"{t['technique_id']} {t['name']}",
            "section_title": t["tactic"],
            "alert_types": t["alert_types"],
            "technique_id": t["technique_id"],
        })
    return chunks


def build_chunks():
    chunks = []
    for playbook_path in sorted((DATA_DIR / "playbooks").glob("*.md")):
        chunks.extend(chunk_playbook(playbook_path))
    chunks.extend(chunk_attack_techniques(DATA_DIR / "mitre_attack.json"))
    return chunks


# ---------------------------------------------------------------------------
# Embedding
# ---------------------------------------------------------------------------

def embed_chunks(chunks, client: AzureOpenAI, batch_size: int = 16):
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        response = client.embeddings.create(
            model=EMBEDDING_DEPLOYMENT,
            input=[c["content"] for c in batch],
        )
        for chunk, item in zip(batch, response.data):
            chunk["content_vector"] = item.embedding
    return chunks


# ---------------------------------------------------------------------------
# Azure AI Search index management
# ---------------------------------------------------------------------------

def ensure_index(index_client: SearchIndexClient):
    fields = [
        SimpleField(name="id", type=SearchFieldDataType.String, key=True),
        SearchableField(name="content", type=SearchFieldDataType.String),
        SimpleField(name="source", type=SearchFieldDataType.String, filterable=True, facetable=True),
        SearchableField(name="doc_title", type=SearchFieldDataType.String, filterable=True),
        SearchableField(name="section_title", type=SearchFieldDataType.String, filterable=True),
        SimpleField(
            name="alert_types",
            type=SearchFieldDataType.Collection(SearchFieldDataType.String),
            filterable=True,
            facetable=True,
        ),
        SimpleField(name="technique_id", type=SearchFieldDataType.String, filterable=True, facetable=True),
        SearchField(
            name="content_vector",
            type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
            searchable=True,
            vector_search_dimensions=EMBEDDING_DIMENSIONS,
            vector_search_profile_name="default-hnsw-profile",
        ),
    ]

    vector_search = VectorSearch(
        algorithms=[HnswAlgorithmConfiguration(name="default-hnsw")],
        profiles=[VectorSearchProfile(name="default-hnsw-profile", algorithm_configuration_name="default-hnsw")],
    )

    index = SearchIndex(name=SEARCH_INDEX_NAME, fields=fields, vector_search=vector_search)
    index_client.create_or_update_index(index)
    print(f"Index '{SEARCH_INDEX_NAME}' ready (created or updated; other indexes in this service untouched).")


def upload_chunks(search_client: SearchClient, chunks):
    # Azure AI Search documents can't contain None for a filterable string field.
    docs = []
    for c in chunks:
        doc = dict(c)
        if doc.get("technique_id") is None:
            doc["technique_id"] = ""
        docs.append(doc)

    batch_size = 100
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        result = search_client.upload_documents(documents=batch)
        failed = [r for r in result if not r.succeeded]
        if failed:
            raise RuntimeError(f"Failed to upload {len(failed)} documents: {failed[:3]}")
    print(f"Uploaded {len(docs)} chunks to '{SEARCH_INDEX_NAME}'.")


def main():
    chunks = build_chunks()
    print(f"Built {len(chunks)} chunks ({sum(1 for c in chunks if c['source'] == 'playbook')} from playbooks, "
          f"{sum(1 for c in chunks if c['source'] == 'mitre_attack')} from ATT&CK).")

    openai_client = AzureOpenAI(
        azure_endpoint=OPENAI_ENDPOINT,
        api_key=OPENAI_API_KEY,
        api_version=OPENAI_API_VERSION,
    )
    embed_chunks(chunks, openai_client)
    print(f"Embedded all chunks with deployment '{EMBEDDING_DEPLOYMENT}' ({EMBEDDING_DIMENSIONS} dims).")

    index_client = SearchIndexClient(SEARCH_ENDPOINT, AzureKeyCredential(SEARCH_API_KEY))
    ensure_index(index_client)

    search_client = SearchClient(SEARCH_ENDPOINT, SEARCH_INDEX_NAME, AzureKeyCredential(SEARCH_API_KEY))
    upload_chunks(search_client, chunks)


if __name__ == "__main__":
    main()
