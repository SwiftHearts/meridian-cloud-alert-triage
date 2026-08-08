"""
Shared test setup.

agents/triage_graph.py, graph/cosmos_graph.py, and agents/rag_retrieval.py
all read Azure credentials from os.environ at import time, and
triage_graph.py additionally constructs real AzureChatOpenAI / Cosmos
Gremlin client objects at import time. None of those constructors make
network calls (verified by hand before writing this suite), so setting fake
credentials here — before any test module imports project code — is enough
to make the whole suite run hermetically: no real .env file, no live Azure
access, no network. That matters once this runs in CI without secrets.

os.environ.setdefault() rather than a hard set: if these are already set in
the environment, leave them, but since this module runs before any project
code calls load_dotenv() (whose default override=False never overwrites an
already-set var), setting the fakes first guarantees tests never silently
depend on — or hit — real Azure resources.
"""

import os

_FAKE_ENV = {
    "AZURE_OPENAI_ENDPOINT": "https://fake-openai.openai.azure.com/",
    "AZURE_OPENAI_API_KEY": "fake-openai-key",
    "AZURE_OPENAI_API_VERSION": "2024-06-01",
    "AZURE_OPENAI_CHAT_DEPLOYMENT": "fake-chat-deployment",
    "AZURE_OPENAI_EMBEDDING_DEPLOYMENT": "fake-embedding-deployment",
    "AZURE_SEARCH_ENDPOINT": "https://fake-search.search.windows.net",
    "AZURE_SEARCH_API_KEY": "fake-search-key",
    "AZURE_SEARCH_INDEX_NAME": "fake-index",
    "COSMOS_GREMLIN_ENDPOINT": "wss://fake-cosmos.gremlin.cosmos.azure.com:443/",
    "COSMOS_KEY": "fake-cosmos-key",
    "COSMOS_DATABASE": "fake-db",
    "COSMOS_GRAPH": "fake-graph",
}
for _key, _value in _FAKE_ENV.items():
    os.environ.setdefault(_key, _value)
