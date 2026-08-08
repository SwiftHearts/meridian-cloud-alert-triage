"""
Multi-agent triage pipeline (LangGraph) that turns one raw alert into a
reviewed verdict, using both prior phases as tools rather than raw context
dumps:

  gather_context -> analyst -> reviewer -> [revise -> analyst] -> finalize

- gather_context: pulls playbook/ATT&CK guidance (Phase 2 RAG,
  rag_retrieval.py) and related-entity activity (Phase 3 graph,
  graph/entity_graph.py) for this alert. No LLM call.
- analyst: proposes a label/severity/rationale, grounded in that context.
- reviewer: a second LLM call that checks the analyst's verdict against the
  same context and either approves it or sends it back with feedback.
  Catches cases like a verdict that ignores graph-revealed correlation
  (e.g. the same host also had a suspicious-process alert this week).
- One revision round max, then finalize regardless — avoids infinite loops
  on a stubborn disagreement.

Requires the same .env vars as ingestion/index_to_azure_search.py, plus
AZURE_OPENAI_CHAT_DEPLOYMENT for the analyst/reviewer LLM.
"""

import json
import os # Read environment variables from .env file 
import sys # Python import-path
from pathlib import Path
from typing import Literal, Optional, TypedDict

from dotenv import load_dotenv # Load environment variables from .env file
from langchain_openai import AzureChatOpenAI # LangChain wrapper for Azure OpenAI chat models
from langgraph.graph import END, START, StateGraph # LangGraph state graph framework

# Pydantic is used for data validation and to transform LLM output into structured output with 
# defined schemas. It ensures that the data returned by the LLMs conforms to expected types 
# and formats, making it easier to work with downstream in the triage process.
from pydantic import BaseModel # Data validation and transform LLM output to structured output

load_dotenv()

# Add the "graph" directory to the Python import path so we can import entity_graph.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "graph"))
from entity_graph import load_graph, summarize_context  # noqa: E402

# Add the "rag_retrieval" directory to the Python import path so we can import rag_retrieval.py
from rag_retrieval import retrieve_playbook_guidance

CHAT_DEPLOYMENT = os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT"]

# Connection to Azure OpenAI chat model, using environment variables for endpoint, 
# API key, and deployment name
_llm = AzureChatOpenAI(
    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_API_KEY"],
    api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01"),
    azure_deployment=CHAT_DEPLOYMENT,
)
# Load the entity graph from the graph module, which contains relationships between 
# entities (hosts, users, IPs, processes) and alerts
_entity_graph = load_graph()

# Look up to 2 relationships away from the alert's host in the entity graph
GRAPH_CONTEXT_HOPS = 2

# Limit the number of revision rounds to avoid infinite loops in case of disagreement 
# between analyst and reviewer
MAX_REVISIONS = 1


# ---------------------------------------------------------------------------
# Structured LLM outputs
# ---------------------------------------------------------------------------

# What the analyst outputs: a label, severity, rationale, and recommended actions. 
class AnalystVerdict(BaseModel):
    label: Literal["false_positive", "needs_investigation", "true_positive"]
    severity: Literal["low", "medium", "high", "critical"]
    rationale: str
    # A list of recommended actions for the SOC team to take based on the analyst's 
    # assessment of the alert.
    recommended_actions: list[str]

# The reviewer outputs a simple approval boolean and optional feedback string.
class ReviewResult(BaseModel):
    approved: bool
    feedback: str  # empty string when approved

# Outputs from the LLMs are structured according to the above Pydantic models.
_analyst_llm = _llm.with_structured_output(AnalystVerdict)
_reviewer_llm = _llm.with_structured_output(ReviewResult)


# ---------------------------------------------------------------------------
# Graph state
# ---------------------------------------------------------------------------

# TriageState is a TypedDict (dictionary with fixed keys with specific value types) 
# that defines the structure of the state passed between nodes in the triage graph.
class TriageState(TypedDict):
    alert: dict

    # Context gathered from the playbook/ATT&CK guidance and the entity graph for this alert.
    playbook_context: list[dict]
    graph_context: str

    # The analyst's verdict, which is optional because it may not be present if the analyst 
    # has not yet made a decision.
    analyst_verdict: Optional[dict]
    review_feedback: Optional[str]
    revision_count: int
    final_verdict: Optional[dict]

# Formats the playbook context into a human-readable string for inclusion in prompts to the LLMs.
def _format_playbook_context(chunks: list[dict]) -> str:
    if not chunks:
        return "No matching playbook/ATT&CK guidance found."

    # Format each chunk with its source, document title, section title, technique ID (if present), 
    # and content, and join them with double newlines.
    return "\n\n".join(
        f"[{c['source']}] {c['doc_title']} — {c['section_title']}"
        + (f" ({c['technique_id']})" if c["technique_id"] else "")
        + f"\n{c['content']}"
        for c in chunks
    )


# ---------------------------------------------------------------------------
# LangGraph Nodes
# ---------------------------------------------------------------------------

# Gather context for the current state alert: playbook guidance and entity graph context.
def gather_context(state: TriageState) -> dict:
    alert = state["alert"] # Raw alert data that triggered the triage process

    # Utilize the RAG retrieval module to get relevant playbook guidance for the alert.
    playbook_context = retrieve_playbook_guidance(alert)

    # Ask NetworkX to summarize the entity graph context for the alert's host
    graph_context = summarize_context(_entity_graph, "host", alert["host"], hops=GRAPH_CONTEXT_HOPS)
    return {"playbook_context": playbook_context, "graph_context": graph_context}

# Analyst node(agent): generates a verdict based on the alert, playbook guidance, and entity graph context.
def analyst_node(state: TriageState) -> dict:
    alert = state["alert"]
    # Check if this is a revision round by looking for review feedback in the state.
    feedback = state.get("review_feedback") 
    # If feedback is present, it indicates that the analyst is revising their verdict 
    # based on the reviewer's comments.
    is_revision = feedback is not None

    prompt = f"""You are a SOC triage analyst for Meridian Cloud. Classify the alert below.

Alert:
{json.dumps(alert, indent=2)}

Relevant playbook / MITRE ATT&CK guidance:
{_format_playbook_context(state["playbook_context"])}

Related activity for this alert's host, from the entity graph (other alerts \
touching the same host, user, IPs, or processes — use this to catch \
correlation a single alert can't show on its own):
{state["graph_context"]}
"""
    # If this is a revision round, include the reviewer's feedback in the prompt so the analyst
    if is_revision:
        prompt += f"\nA reviewer rejected your previous verdict with this feedback — revise accordingly:\n{feedback}\n"

    # Use the Azure OpenAI chat model to generate a structured verdict based on the prompt.
    verdict = _analyst_llm.invoke(prompt)
    return {
        # Store the analyst's verdict in the state, converting it to a dictionary for serialization.
        "analyst_verdict": verdict.model_dump(),
        # Increment the revision count if this is a revision round, otherwise keep it the same.
        "revision_count": state.get("revision_count", 0) + (1 if is_revision else 0),
    }

# Reviewer node(agent): checks the analyst's verdict against the alert, playbook guidance, 
# and entity graph context.
def reviewer_node(state: TriageState) -> dict:
    prompt = f"""You are a second-opinion reviewer for SOC alert triage. Check whether \
the analyst's verdict below is well-supported by the alert, the playbook \
guidance, and the entity-graph context. Reject only for a real gap — e.g. \
the label contradicts the evidence, the severity doesn't match the \
guidance, or the graph context reveals a correlation (like the same host \
having other recent suspicious alerts) that the verdict ignored. Approve \
otherwise; do not nitpick phrasing.

Alert:
{json.dumps(state["alert"], indent=2)}

Playbook / ATT&CK guidance:
{_format_playbook_context(state["playbook_context"])}

Entity graph context:
{state["graph_context"]}

Analyst verdict:
{json.dumps(state["analyst_verdict"], indent=2)}
"""
    # Use the Azure OpenAI chat model to generate a structured review result based on the prompt.
    result = _reviewer_llm.invoke(prompt)
    # Store the review feedback in the state, setting it to None if the verdict was approved,
    # or to the reviewer's feedback if it was rejected.
    return {"review_feedback": None if result.approved else result.feedback}

# Directs the flow of the graph after the reviewer node, based on whether the verdict was 
# approved or rejected.
def route_after_review(state: TriageState) -> str:
    if state["review_feedback"] is None:
        return "finalize"
    if state["revision_count"] >= MAX_REVISIONS:
        return "finalize"
    # If the verdict was rejected and the maximum number of revisions has not been reached, 
    # route back to the analyst node for revision.
    return "revise"

# Finalize node(agent): compiles the final verdict, including whether it was reviewed,
# any reviewer feedback, and the number of revisions made.
def finalize_node(state: TriageState) -> dict:
    verdict = dict(state["analyst_verdict"])
    verdict["reviewed"] = state.get("review_feedback") is None
    if state.get("review_feedback"):
        verdict["reviewer_note"] = state["review_feedback"]
    verdict["revision_count"] = state.get("revision_count", 0)
    return {"final_verdict": verdict}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

# Build the triage graph by defining nodes and edges, including conditional routing 
# based on review feedback.
def build_graph():
    graph = StateGraph(TriageState)
    graph.add_node("gather_context", gather_context)
    graph.add_node("analyst", analyst_node)
    graph.add_node("reviewer", reviewer_node)
    graph.add_node("finalize", finalize_node)

    graph.add_edge(START, "gather_context")
    graph.add_edge("gather_context", "analyst")
    graph.add_edge("analyst", "reviewer")

    # Add conditional edges from the reviewer node to either finalize or back to analyst for revision,
    # based on the review feedback and revision count.
    graph.add_conditional_edges("reviewer", route_after_review, {"finalize": "finalize", "revise": "analyst"})
    graph.add_edge("finalize", END)

    return graph.compile()


_compiled_graph = build_graph()

# Public API for triaging an alert, returning the full state including context and final verdict.
def run_triage(alert: dict) -> TriageState:
    """Full pipeline state (context + verdict) — for callers that want to
    show their work, e.g. the Streamlit UI."""
    return _compiled_graph.invoke({"alert": alert, "revision_count": 0})

# Public API for triaging an alert, returning only the final verdict.
def triage_alert(alert: dict) -> dict:
    return run_triage(alert)["final_verdict"]
