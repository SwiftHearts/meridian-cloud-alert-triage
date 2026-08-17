"""
Checks the Meridian Cloud index after a run of index_to_azure_search.py:
prints the document count and runs one sample vector search query.

Requires the same .env vars as index_to_azure_search.py.

Run: python ingestion/verify_index.py
"""
# Read environment variables from .env file and set them in os.environ
import os

# Load environment variables from a .env file into the environment
from dotenv import load_dotenv
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery
from openai import AzureOpenAI

load_dotenv()

SEARCH_ENDPOINT = os.environ["AZURE_SEARCH_ENDPOINT"]
SEARCH_API_KEY = os.environ["AZURE_SEARCH_API_KEY"]
# The name of the Azure AI Search index to verify; defaults to "meridian-cloud-security-index" if not set in the environment
SEARCH_INDEX_NAME = os.environ.get("AZURE_SEARCH_INDEX_NAME", "meridian-cloud-security-index")

OPENAI_ENDPOINT = os.environ["AZURE_OPENAI_ENDPOINT"]
OPENAI_API_KEY = os.environ["AZURE_OPENAI_API_KEY"]
OPENAI_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01")
EMBEDDING_DEPLOYMENT = os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-3-small")

SAMPLE_QUERY = "suspicious process execution triage steps"

# Main function to verify the Azure AI Search index by checking document count and performing a sample vector search query
def main():
    # Create a SearchClient to interact with the Azure AI Search index
    search_client = SearchClient(SEARCH_ENDPOINT, SEARCH_INDEX_NAME, AzureKeyCredential(SEARCH_API_KEY))

    # Get the total number of documents in the specified Azure AI Search index
    count = search_client.get_document_count()
    print(f"Index '{SEARCH_INDEX_NAME}' contains {count} documents.")

    # Create an AzureOpenAI client to generate embeddings for the sample query
    openai_client = AzureOpenAI(
        azure_endpoint=OPENAI_ENDPOINT,
        api_key=OPENAI_API_KEY,
        api_version=OPENAI_API_VERSION,
    )
    # Create an embedding for the sample query using the specified embedding deployment
    embedding = openai_client.embeddings.create(
        model=EMBEDDING_DEPLOYMENT,
        input=[SAMPLE_QUERY],
    # Retrieve the first embedding vector from the response
    ).data[0].embedding

    # Create a vectorized query using the generated embedding, requesting the 3 nearest neighbors and selecting specific fields to return
    vector_query = VectorizedQuery(vector=embedding, k_nearest_neighbors=3, fields="content_vector")
    # Perform the vector search query (not keyword search) against the Azure AI Search index, retrieving the top matches based on the embedding
    results = search_client.search(search_text=None, vector_queries=[vector_query], select=["doc_title", "section_title", "source"])

    print(f"\nTop matches for: {SAMPLE_QUERY!r}")
    for r in results:
        print(f"  - [{r['source']}] {r['doc_title']} — {r['section_title']}")


if __name__ == "__main__":
    main()
