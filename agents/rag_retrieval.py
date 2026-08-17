"""
Retrieves playbook / MITRE ATT&CK guidance for a single alert from the
Azure AI Search index built in Phase 2 (index_to_azure_search.py).

Embeds the alert's raw_description with the same embedding deployment used
at indexing time, runs a vector search restricted to that alert_type via
the `alert_types` collection field, and returns the top matching chunks.

Requires the same .env vars as ingestion/index_to_azure_search.py.
"""

import os

from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

SEARCH_ENDPOINT = os.environ["AZURE_SEARCH_ENDPOINT"]
SEARCH_API_KEY = os.environ["AZURE_SEARCH_API_KEY"]
SEARCH_INDEX_NAME = os.environ.get("AZURE_SEARCH_INDEX_NAME", "meridian-cloud-security-index")

OPENAI_ENDPOINT = os.environ["AZURE_OPENAI_ENDPOINT"]
OPENAI_API_KEY = os.environ["AZURE_OPENAI_API_KEY"]
OPENAI_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01")
EMBEDDING_DEPLOYMENT = os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-3-small")

# Initialize clients for Azure Search and Azure OpenAI
_search_client = SearchClient(SEARCH_ENDPOINT, SEARCH_INDEX_NAME, AzureKeyCredential(SEARCH_API_KEY))
_openai_client = AzureOpenAI(
    azure_endpoint=OPENAI_ENDPOINT,
    api_key=OPENAI_API_KEY,
    api_version=OPENAI_API_VERSION,
)

# Embed the alert's raw description
def retrieve_playbook_guidance(alert: dict, k: int = 3) -> list[dict]:
    """Top-k playbook/ATT&CK chunks relevant to this alert's type and description."""
    embedding = _openai_client.embeddings.create(
        model=EMBEDDING_DEPLOYMENT,
        # The alert's raw_description is embedded to create a vector representation for 
        # similarity search.
        input=[alert["raw_description"]],
    ).data[0].embedding

    # Perform a vector search in the Azure Search index using the alert's embedding, filtering 
    # by alert type, and retrieving the top-k relevant chunks.
    vector_query = VectorizedQuery(vector=embedding, k_nearest_neighbors=k, fields="content_vector")
    results = _search_client.search(
        # Don't use keyword search text; rely solely on the vector similarity and alert type filter.
        search_text=None,
        vector_queries=[vector_query],
        filter=f"alert_types/any(t: t eq '{alert['alert_type']}')",
        select=["content", "doc_title", "section_title", "source", "technique_id"],
        top=k,
    )
    return [
        {
            "content": r["content"],
            "doc_title": r["doc_title"],
            "section_title": r["section_title"],
            "source": r["source"],
            "technique_id": r["technique_id"] or None,
        }
        for r in results
    ]
