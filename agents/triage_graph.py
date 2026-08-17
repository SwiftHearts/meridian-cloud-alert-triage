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
import logging
import os  # Read environment variables from .env file
import sys  # Python import-path
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Literal, Optional, TypedDict

from dotenv import load_dotenv  # Load environment variables from .env file
from langchain_openai import AzureChatOpenAI  # LangChain wrapper for Azure OpenAI chat models
from langgraph.graph import END, START, StateGraph  # LangGraph state graph framework

# Pydantic is used for data validation and to transform LLM output into structured output with 
# defined schemas. It ensures that the data returned by the LLMs conforms to expected types 
# and formats, making it easier to work with downstream in the triage process.
from pydantic import BaseModel  # Data validation and transform LLM output to structured output

load_dotenv()

# Create logger for this module to log messages, warnings, and errors. 
logger = logging.getLogger(__name__)

# Add the "graph" directory to the Python import path so we can import cosmos_graph.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "graph"))

# Import the Gremlin client and context summarization function from cosmos_graph.py, which allows
# us to query the Azure Cosmos DB graph for related entity activity.
# noqa: E402 (ignore import not at top of file, needed to show where graph is added to path first)
from cosmos_graph import get_client, summarize_context  

# Add the "rag_retrieval" directory to the Python import path so we can import rag_retrieval.py
from rag_retrieval import retrieve_playbook_guidance

CHAT_DEPLOYMENT = os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT"]

# Look for an environment variable called LLM_TIMEOUT_SECONDS. If it doesn’t exist, use 30.
# Don’t wait longer than this time for the LLM request before treating it as timed out.
LLM_TIMEOUT_SECONDS = float(os.environ.get("LLM_TIMEOUT_SECONDS", 30))

# Look for an environment variable called LLM_MAX_RETRIES. If it doesn’t exist, use 2.
# Retry the LLM request this many times (plus the initial attempt) on transient failures 
LLM_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", 2))

# Connection to Azure OpenAI chat model, using environment variables for endpoint,
# API key, and deployment name
_llm = AzureChatOpenAI(
    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_API_KEY"],
    api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01"),
    azure_deployment=CHAT_DEPLOYMENT,
    timeout=LLM_TIMEOUT_SECONDS,
    max_retries=LLM_MAX_RETRIES,
)
# Connect to the Cosmos DB Gremlin graph, which holds relationships between
# entities (hosts, users, IPs, processes) and alerts
_graph_client = get_client()

# Look up to 2 connections away from the alert's host in the entity graph
GRAPH_CONTEXT_HOPS = 2

# Limit the number of revision rounds to avoid infinite loops in case of disagreement
# between analyst and reviewer
MAX_REVISIONS = 1

# Hard deadline of 8 seconds for the two context lookups (RAG playbook retrieval, Cosmos
# graph query) that feed the analyst prompt. 
CONTEXT_LOOKUP_TIMEOUT_SECONDS = float(os.environ.get("CONTEXT_LOOKUP_TIMEOUT_SECONDS", 8))

# ThreadPoolExecutor is used to run the context lookups in parallel, allowing for concurrent execution of tasks.
# Allow up to 2 threads to run context lookups concurrently, which is useful for the two independent lookups (RAG and graph) 
_context_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="triage-context")

# Structure to run a function with positional and keyword arguments, with a timeout. 
def _run_with_deadline(fn, *args, timeout: float, **kwargs):
    """Run fn(*args, **kwargs) in the context executor, bounded by timeout.
    Raises concurrent.futures.TimeoutError (or whatever fn raised) on
    failure; a slow call that later completes keeps running in the
    background but its result is discarded by the caller."""

    # Submit the function to the thread pool executor 
    future: Future = _context_executor.submit(fn, *args, **kwargs)

    # Wait for the result with a timeout. 
    return future.result(timeout=timeout)


# ---------------------------------------------------------------------------
# Structured LLM outputs
# ---------------------------------------------------------------------------

# Analyst output: label, severity, rationale, and recommended actions. 
class AnalystVerdict(BaseModel):
    label: Literal["false_positive", "needs_investigation", "true_positive"]
    severity: Literal["low", "medium", "high", "critical"]
    rationale: str
    # A list of recommended actions for the SOC team to take based on the analyst's 
    # assessment of the alert.
    recommended_actions: list[str]

# Reviewer output: approval boolean and optional feedback string.
class ReviewResult(BaseModel):
    approved: bool
    feedback: str  # empty string when analyst's verdict approved

# Outputs from the LLMs are structured according to the above Pydantic models.
# with_structured_output() is LangChain's chat model method that wraps the LLM to validate 
# and transform its output into the defined schema.
_analyst_llm = _llm.with_structured_output(AnalystVerdict)
_reviewer_llm = _llm.with_structured_output(ReviewResult)


# ---------------------------------------------------------------------------
# Graph state
# ---------------------------------------------------------------------------

# TriageState is a TypedDict (dictionary with fixed keys with specific value types) 
# that defines the structure of the state passed between nodes in the triage graph.
# This ensures all categories required are included, for validation & consistency
class TriageState(TypedDict):
    alert: dict

    # Context gathered from the playbook/ATT&CK guidance.
    playbook_context: list[dict]
    # Context gathered from the entity graph.
    graph_context: str

    # Optional fields that may be added during the triage process, including the analyst's verdict,
    # any feedback from the reviewer, the number of revisions made, and the final verdict.
    analyst_verdict: Optional[dict]
    review_feedback: Optional[str]
    revision_count: int
    final_verdict: Optional[dict]

   # Tracks which components of the triage process failed or were unavailable, allowing the 
   # system to continue to operate in a degraded mode rather than failing completely. For example, if 
   # the analyst LLM fails, the system can still provide a fallback verdict and continue to the 
   # reviewer or finalize step.
    degraded: list[str]

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
# Each lookup is independent and best-effort — a slow/failed Azure Search or
# Cosmos DB call degrades just that piece of context rather than the whole
# triage run, since the analyst/reviewer prompts already handle a "no
# guidance found" style placeholder.

# Function to gather context, the state will have the format of TriageState, a dictionary,
# which includes the alert, playbook context, graph context, and any degraded components.
def gather_context(state: TriageState) -> dict:
    # Get the raw alert data from the state, which is the input to the triage process.
    alert = state["alert"] 
    # Initialize a list to track which components of the context gathering process failed or were unavailable.
    degraded = list(state.get("degraded", []))

    # Try to retrieve the playbook guidance witin the specified timeout restrictions
    try:
        playbook_context = _run_with_deadline(
            retrieve_playbook_guidance, alert, timeout=CONTEXT_LOOKUP_TIMEOUT_SECONDS
        )
    # If it fails, log a warning
    except Exception:
        logger.warning(
            "Playbook retrieval failed or timed out for alert %s", alert.get("alert_id"), exc_info=True
        )
        # Nothing returned for the playbook context
        playbook_context = []
        degraded.append("playbook_context")

    # Try to run summarize_context wrapped in _run_with_deadline to ensure it respects the timeout restrictions
    try:
        graph_context = _run_with_deadline(
            summarize_context,
            # Object used to communicate with Azure graph database
            _graph_client,
            # Start from 'host' entity
            "host",
            # Host value
            alert["host"],
            # Number of connections away
            hops=GRAPH_CONTEXT_HOPS,
            timeout=CONTEXT_LOOKUP_TIMEOUT_SECONDS,
        )
    except Exception:
        logger.warning(
            "Graph context lookup failed or timed out for alert %s", alert.get("alert_id"), exc_info=True
        )
        graph_context = "Graph context unavailable (lookup timed out or failed)."
        degraded.append("graph_context")

    return {"playbook_context": playbook_context, "graph_context": graph_context, "degraded": degraded}

# Analyst node(agent): generates a verdict based on the alert, playbook guidance, and entity graph context.
# Follow the structure of the TriageState class and return a dictionary
def analyst_node(state: TriageState) -> dict:
    alert = state["alert"]
    # Check if this is a revision round by looking for review feedback in the state.
    feedback = state.get("review_feedback") 
    # Set is_revision to true if there is feedback
    is_revision = feedback is not None

    # Prompt to send to the Analyst Agent
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
    # If this is a revision round, include the reviewer's feedback in the prompt 
    if is_revision:
        prompt += f"\nA reviewer rejected your previous verdict with this feedback — revise accordingly:\n{feedback}\n"

   # Retrieve the 'degraded' list or use an empty list
    degraded = list(state.get("degraded", []))
    try:
        # Try to run the analyst llm
        verdict = _analyst_llm.invoke(prompt)
        # Convert the pydantic object into a python dictionary
        verdict_dict = verdict.model_dump()
    except Exception:
        logger.error(
            # Include the alert ID
            "Analyst LLM call failed for alert %s after retries", alert.get("alert_id"), exc_info=True
        )
        # Fallback analyst verdict converted into a python dictionary
        verdict_dict = AnalystVerdict(
            label="needs_investigation",
            severity="medium",
            rationale="Automated analysis unavailable (LLM call failed after retries) — flagged for manual SOC review.",
            recommended_actions=["Manually triage this alert; automated triage is currently unavailable."],
        ).model_dump()
        # Append to the 'degraded' list
        degraded.append("analyst")

    return {
        # Store the analyst's verdict in the state
        "analyst_verdict": verdict_dict,
        # Get 'revision_count' or set to 0, add 1 if it's a revision, otherwise 0
        "revision_count": state.get("revision_count", 0) + (1 if is_revision else 0),
        "degraded": degraded,
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
    # Get the 'degraded' list or return an empty list
    degraded = list(state.get("degraded", []))
    try:
        # Try calling the reviewer LLM Agent
        result = _reviewer_llm.invoke(prompt)
        # No feedback if the result is approved otherwise include feedback
        review_feedback = None if result.approved else result.feedback
    except Exception:
        # Record the error in the application logs
        logger.error("Reviewer LLM call failed for alert %s after retries", exc_info=True)
        review_feedback = None
        degraded.append("reviewer")

   # Return the review feedback and the degraded list to the state
    return {"review_feedback": review_feedback, "degraded": degraded}

# Directs the flow of the graph after the analyst node. 
def route_after_analyst(state: TriageState) -> str:
# Check whether analyst appeared in the degraded list, if so route to finalize, 
# otherwise route to reviewer
    if "analyst" in state.get("degraded", []):
        return "finalize"
    return "reviewer"

# Directs the flow of the graph after the reviewer node, based on whether the verdict was
# approved or rejected.
def route_after_review(state: TriageState) -> str:
    # If the reviewer LLM failed or was unavailable, finalize the verdict
    if state["review_feedback"] is None:
        return "finalize"
        # If the number of revisions is greater than or equal to the maximum allowed revisions, 
        # finalize the verdict
    if state["revision_count"] >= MAX_REVISIONS:
        return "finalize"
    # If the verdict was rejected and the maximum number of revisions has not been reached, 
    # route back to the analyst node for revision.
    return "revise"

# Finalize node(agent): compiles the final verdict, including whether it was reviewed,
# any reviewer feedback, and the number of revisions made.
def finalize_node(state: TriageState) -> dict:
    # Retrieve the analyst's verdict from the state & convert it to a dictionary
    verdict = dict(state["analyst_verdict"])
    # Retrieve the list of degraded components from the state, defaulting to an empty list if not present
    degraded = state.get("degraded", [])
    # Determine if the reviewer ran successfully by checking if "reviewer" and "analyst" are not in the degraded list
    reviewer_ran = "reviewer" not in degraded and "analyst" not in degraded

    # Verdict is considered reviewed if the reviewer ran successfully and there is no review feedback 
    verdict["reviewed"] = reviewer_ran and state.get("review_feedback") is None
    if state.get("review_feedback"):
        verdict["reviewer_note"] = state["review_feedback"]
    elif "reviewer" in degraded:
        verdict["reviewer_note"] = (
            "Second-opinion review unavailable (LLM call failed) — verdict not independently checked."
        )
    # Get the revision count from the state, defaulting to 0 if not present
    verdict["revision_count"] = state.get("revision_count", 0)
    if degraded:
        verdict["degraded_components"] = degraded
    return {"final_verdict": verdict}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

# Build the triage graph by defining nodes and edges, including conditional routing 
# based on review feedback.
def build_graph():
    graph = StateGraph(TriageState)
    # Add the nodes and give them corresponding names
    graph.add_node("gather_context", gather_context)
    graph.add_node("analyst", analyst_node)
    graph.add_node("reviewer", reviewer_node)
    graph.add_node("finalize", finalize_node)

    # Add edges to define the flow of the graph, starting from the START node to gather_context, 
    # then to analyst
    graph.add_edge(START, "gather_context")
    graph.add_edge("gather_context", "analyst")

    # Add conditional edges from the analyst node to either the reviewer, or straight to
    # finalize if the analyst LLM failed and produced a fallback verdict (nothing to review).
    graph.add_conditional_edges("analyst", route_after_analyst, {"reviewer": "reviewer", "finalize": "finalize"})

    # Add conditional edges from the reviewer node to either finalize or back to analyst for revision,
    # based on the review feedback and revision count.
    graph.add_conditional_edges("reviewer", route_after_review, {"finalize": "finalize", "revise": "analyst"})
    graph.add_edge("finalize", END)

    return graph.compile()

# Run the build_graph function & store it as _compiled_graph, which is the compiled version of 
# the triage graph that can be invoked with an alert.
_compiled_graph = build_graph()

# Take this alert, create the initial state, run the entire LangGraph workflow, and give back the completed state.
def run_triage(alert: dict) -> TriageState:
    """Full pipeline state (context + verdict) — for callers that want to
    show their work, e.g. the Streamlit UI."""
    return _compiled_graph.invoke({"alert": alert, "revision_count": 0, "degraded": []})

# Wrap run_triage, returning only the final verdict.
def triage_alert(alert: dict) -> dict:
    return run_triage(alert)["final_verdict"]
