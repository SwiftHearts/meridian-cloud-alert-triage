"""
Chunks the playbooks + MITRE ATT&CK subset, embeds them with Azure OpenAI
(text-embedding-3-small), and indexes them into Azure AI Search.

Scoped to a single named index (AZURE_SEARCH_INDEX_NAME, default
"meridian-cloud-security-index") inside a shared/free-tier Search service.
This script only ever creates/updates/queries that one index — it never
touches any other index (e.g. the Sterling Law contracts index) that may
live in the same service.

Requires an .env file (see .env.example) with:
  AZURE_SEARCH_ENDPOINT, AZURE_SEARCH_API_KEY, AZURE_SEARCH_INDEX_NAME
  AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_API_VERSION,
  AZURE_OPENAI_EMBEDDING_DEPLOYMENT, AZURE_OPENAI_EMBEDDING_DIMENSIONS

Run: python ingestion/index_to_azure_search.py
"""

import json
# Regex: recognize markdown and clean strings
import re
from pathlib import Path

from dotenv import load_dotenv

# Access OpenAI embedding models via Azure OpenAI
from openai import AzureOpenAI
from azure.core.credentials import AzureKeyCredential
# Search documents
from azure.search.documents import SearchClient
# Search index management
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
EMBEDDING_DIMENSIONS = int(os.environ.get("AZURE_OPENAI_EMBEDDING_DIMENSIONS", "1536")) # Convert to int

# Playbook filename -> the alert_type(s) it covers, for retrieval filtering.
# Assign documents to alert types 
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

# Path to a playbook markdown file 
def chunk_playbook(path: Path):
    """Split a playbook into one chunk per '## ' section, prefixed with the
    playbook title so each chunk retains standalone context."""
    # Read the text into a string
    text = path.read_text()
    # If the title starts with # extract everything after it 
    title_match = re.match(r"# (.+)", text)
    # If no title, use the filename stem as the title
    title = title_match.group(1).strip() if title_match else path.stem

    # Split the text into sections at each '## ' heading
    sections = re.split(r"\n(?=## )", text)
    chunks = []
    for section in sections:
        # Strip whitespace and skip empty sections or sections starting with '# ' (the title)
        section = section.strip()
        if not section or section.startswith("# "):
            continue
        # Extract the heading from the section (the first line after '## ')
        heading_match = re.match(r"## (.+)", section)
        # The heading is the first line after '## ', or "Overview" if no heading is found
        heading = heading_match.group(1).strip() if heading_match else "Overview"
        content = f"{title}\n\n{section}"
        chunks.append({
            # Create a unique ID for the chunk: by combining the playbook filename stem and 
            # the heading, lowercased and with non-alphanumeric characters replaced by hyphens
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
    # Read the MITRE ATT&CK techniques JSON file and convert to python dictionary
    techniques = json.loads(path.read_text())
    # List of dictionaries, each representing a chunk for a technique, with the following keys:
    # - id: unique identifier for the chunk, based on the technique ID
    # - content: the text content of the chunk, including the technique ID, name, tactic(s), and description
    # - source: the source of the chunk, which is "mitre_attack" for all chunks in this function
    # - doc_title: the title of the document, which is the technique ID and name
    # - section_title: the tactic(s) associated with the technique
    # - alert_types: the alert types associated with the technique,
    #   which is an empty list for all chunks in this function
    # - technique_id: the technique ID, which is used for filtering in Azure AI Search
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
    # Search all playbook files and sort alphabetically 
    for playbook_path in sorted((DATA_DIR / "playbooks").glob("*.md")):
        # Extend to avoid nested lists, and chunk each playbook into sections
        chunks.extend(chunk_playbook(playbook_path))
    # Search the MITRE ATT&CK techniques JSON file and chunk it
    chunks.extend(chunk_attack_techniques(DATA_DIR / "mitre_attack.json"))
    return chunks


# ---------------------------------------------------------------------------
# Embedding
# ---------------------------------------------------------------------------
# Turn the text content of each chunk into a vector embedding using Azure OpenAI embeddings API.
# 16 chunks per batch
def embed_chunks(chunks, client: AzureOpenAI, batch_size: int = 16):
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        response = client.embeddings.create(
            model=EMBEDDING_DEPLOYMENT,
            # For every dictionary chunk "c" in the batch, extract the "content" field 
            # and pass it as a list to the embeddings API
            input=[c["content"] for c in batch],
        )
        # Pair each chunk with its corresponding embedding from the response and add it to the chunk dictionary
        for chunk, item in zip(batch, response.data):
            chunk["content_vector"] = item.embedding
    return chunks


# ---------------------------------------------------------------------------
# Azure AI Search index management
# ---------------------------------------------------------------------------

# Azure AI Search schema
def ensure_index(index_client: SearchIndexClient):
    fields = [
        SimpleField(name="id", type=SearchFieldDataType.String, key=True),
        SearchableField(name="content", type=SearchFieldDataType.String),
        # Facetable: search results are grouped by unique fields
        SimpleField(name="source", type=SearchFieldDataType.String, filterable=True, facetable=True),
        SearchableField(name="doc_title", type=SearchFieldDataType.String, filterable=True),
        SearchableField(name="section_title", type=SearchFieldDataType.String, filterable=True),
        # Collection of strings: a chunk can be associated with multiple alert types, and we want to filter by any of them
        SimpleField(
            name="alert_types",
            type=SearchFieldDataType.Collection(SearchFieldDataType.String),
            filterable=True,
            facetable=True,
        ),
        
        SimpleField(name="technique_id", type=SearchFieldDataType.String, filterable=True, facetable=True),
        # Vector search field: the embedding vector for each chunk (list of floats), with 
        # the specified dimensions and HNSW profile for approximate nearest neighbor search
        SearchField(
            name="content_vector",
            type=SearchFieldDataType.Collection(SearchFieldDataType.Single),
            searchable=True,
            vector_search_dimensions=EMBEDDING_DIMENSIONS, # 1536 for text-embedding-3-small
            vector_search_profile_name="default-hnsw-profile",
        ),
    ]

    vector_search = VectorSearch(
        # HNSW (Hierarchical Navigable Small World) algorithm configuration for approximate nearest neighbor search
        algorithms=[HnswAlgorithmConfiguration(name="default-hnsw")],
        profiles=[VectorSearchProfile(name="default-hnsw-profile", algorithm_configuration_name="default-hnsw")],
    )

    # Create or update the index with the specified fields and vector search configuration
    index = SearchIndex(name=SEARCH_INDEX_NAME, fields=fields, vector_search=vector_search)
    index_client.create_or_update_index(index)
    print(f"Index '{SEARCH_INDEX_NAME}' ready (created or updated; other indexes in this service untouched).")


def upload_chunks(search_client: SearchClient, chunks):
    # Azure AI Search documents can't contain None for a filterable string field.
    docs = []
    for c in chunks:
        # Makes a shallow copy of the chunk dictionary to avoid modifying the original
        doc = dict(c)
        if doc.get("technique_id") is None:
            doc["technique_id"] = ""
        docs.append(doc)

    # Upload documents in batches up to 100.
    batch_size = 100
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        # Upload the batch of documents to the Azure AI Search index and check for any failures
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

# Run the main function if this script is executed directly (not imported as a module)
if __name__ == "__main__":
    main()
