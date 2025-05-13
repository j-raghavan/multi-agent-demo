"""
This is the main file for the multi-agent system.
Updated to work with CrowdStrike SIEM data with MITRE ATT&CK focused analysis
and parallel worker execution with voting-based consensus.
"""

import os
import json
import gzip
from typing import List, Dict, Any, TypedDict, Annotated
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langsmith import traceable
import argparse
import random
from collections import deque

from agents.planner import Planner
from agents.worker_factory import WorkerFactory
from agents.critique import Critique
from agents.judge import Judge


# Load environment variables
load_dotenv()

# Global counter for tracking iterations
ITERATION_COUNT = 0

class AgentState(TypedDict):
    human_input: str
    log_content: str
    plan: str
    worker_definitions: List[Dict[str, str]]
    worker1_output: Dict[str, Any]
    worker2_output: Dict[str, Any]
    worker3_output: Dict[str, Any]
    worker4_output: Dict[str, Any]
    worker5_output: Dict[str, Any]
    critique_output: Dict[str, Any]
    final_judgment: Dict[str, Any]
    max_iterations: int
    workers_to_revise: List[int]  # Track which workers need revision
    iteration_count: int  # Track iteration count in state


# Lets create the log analysis graph
@traceable(name="create_log_analysis_graph")
def create_log_analysis_graph():
    # Initialize OpenAI LLM
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.0)

    # Initialize our agents
    planner = Planner(llm)
    worker_factory = WorkerFactory(llm)
    critique = Critique(llm)
    judge = Judge(llm)

    # Build the graph with typed state
    workflow = StateGraph(AgentState)

    # Debug wrapper for state tracking
    def debug_node(name, func):
        def wrapped(state):
            print(f"\n>>> {name} START")
            result = func(state)
            print(f"<<< {name} END")
            return result
        return wrapped

    # Add planner node with debug wrapper
    workflow.add_node("planner", debug_node("PLANNER", planner))
    
    # Define worker creation with debug wrappers
    def create_worker(num):
        def worker_func(state):
            worker_defs = state.get("worker_definitions", [])
            if len(worker_defs) >= num:
                worker_def = worker_defs[num - 1]
                return worker_factory.create_worker(num, worker_def["role"], worker_def["tasks"])(state)
            return {
                f"worker{num}_output": {"role": "Default", "analysis": "No specific role defined."}
            }
        return debug_node(f"WORKER-{num}", worker_func)

    # Add all 5 worker nodes for parallel execution
    for i in range(1, 6):
        workflow.add_node(f"worker{i}", create_worker(i))
    
    # Add critique and judge nodes
    workflow.add_node("critique", debug_node("CRITIQUE", critique))
    workflow.add_node("judge", debug_node("JUDGE", judge))

    # Define edges for parallel execution
    # Planner to all workers in parallel
    for i in range(1, 6):
        workflow.add_edge("planner", f"worker{i}")
    
    # All workers to critique in parallel
    for i in range(1, 6):
        workflow.add_edge(f"worker{i}", "critique")
    
    # Critique directly to judge (no revision loop)
    workflow.add_edge("critique", "judge")
    
    # Judge is the final node
    workflow.add_edge("judge", END)

    # Set the entry point
    workflow.set_entry_point("planner")

    return workflow.compile()


def read_crowdstrike_data(file_path: str, max_events: int = 50) -> str:
    """
    Read and parse CrowdStrike SIEM data from a file, either compressed or uncompressed.
    Returns a string with JSON-formatted data for the agents to analyze.
    Randomly samples max_events from the file instead of taking the first max_events.

    Args:
        file_path: Path to the CrowdStrike SIEM data file
        max_events: Maximum number of events to include (to prevent context overflow)

    Returns:
        String with formatted CrowdStrike data
    """
    events = deque(maxlen=max_events)
    total_events = 0

    # Check if file is gzipped
    is_gzipped = file_path.endswith('.gz')

    # Open appropriate file handler
    if is_gzipped:
        opener = gzip.open
        mode = 'rt'  # text mode for gzip
    else:
        opener = open
        mode = 'r'

    try:
        with opener(file_path, mode) as file:
            # First pass: count total events and collect random sample
            for line in file:
                if line.strip():  # Skip empty lines
                    try:
                        event = json.loads(line)
                        total_events += 1
                        
                        # Reservoir sampling algorithm
                        # For the first max_events, add them directly
                        if total_events <= max_events:
                            events.append(event)
                        else:
                            # For subsequent events, randomly replace existing events
                            # with probability max_events/total_events
                            if random.random() < max_events / total_events:
                                # Randomly select an event to replace
                                events[random.randrange(max_events)] = event
                    except json.JSONDecodeError:
                        print(f"Warning: Could not parse line as JSON: {line[:100]}...")
                        continue

        print(f"Total events in file: {total_events}")
        print(f"Randomly sampled {len(events)} events")

    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return f"Error reading CrowdStrike data: {e}"

    # Convert the events to a well-formatted JSON string
    return json.dumps(list(events), indent=2)


@traceable(name="log_analysis_multi_agent")
def run_log_analysis(human_input: str, log_file: str, max_events: int = 50, max_iterations: int = 3):
    """
    Run the log analysis multi-agent system on CrowdStrike SIEM data.

    Args:
        human_input: User query for analysis
        log_file: Path to the CrowdStrike SIEM data file
        max_events: Maximum number of events to include in the analysis
        max_iterations: Maximum number of planning iterations before forcing completion
    """
    global ITERATION_COUNT
    
    # Reset the global iteration counter for new runs
    ITERATION_COUNT = 0
    
    # Read and parse the CrowdStrike data
    log_content = read_crowdstrike_data(log_file, max_events)

    # Create initial state with max_iterations
    initial_state = {
        "human_input": human_input,
        "log_content": log_content,
        "max_iterations": max_iterations,
        "workers_to_revise": [],  # Initialize empty list of workers to revise
        "iteration_count": 0      # Initialize iteration count in state
    }

    # Print initial state for debugging
    print(f"Initial state: global ITERATION_COUNT={ITERATION_COUNT}, max_iterations={max_iterations}")

    log_analysis_graph = create_log_analysis_graph()

    # Get the final result
    result = log_analysis_graph.invoke(initial_state)

    # Print final state for debugging
    print(f"\n=== ANALYSIS COMPLETE ===")
    print(f"Final iteration count: {ITERATION_COUNT}")

    # Add the iteration count to the result
    result["iteration_count"] = ITERATION_COUNT
    
    return result

def main():
    parser = argparse.ArgumentParser(description="CrowdStrike Falcon Log Anomaly Detection")
    parser.add_argument("--query", type=str, required=True, help="Security investigation request")
    parser.add_argument("--log-file", type=str, help="Path to CrowdStrike Falcon log file")
    parser.add_argument("--max-events", type=int, default=50, help="Maximum number of events to analyze")
    parser.add_argument("--max-iterations", type=int, default=3, help="Maximum number of analysis iterations")
    
    args = parser.parse_args()
    
    # Run the analysis
    result = run_log_analysis(args.query, args.log_file, args.max_events, args.max_iterations)
    
    # Print the final result
    print("\n===== CrowdStrike Falcon Anomaly Detection Results =====\n")
    print(f"Investigation Request: {args.query}\n")
    print(f"Analysis Plan:\n{result['plan']}\n")
    
    # Print worker results
    for i in range(1, 6):  # Now supporting 5 workers
        worker_key = f"worker{i}_output"
        if worker_key in result:
            print(f"Specialist {i} ({result[worker_key]['role']}):\n")
            print(f"{result[worker_key]['analysis']}\n")
    
    # Print critique and judge results
    print(f"Consensus Analysis (with voting):\n{result['critique_output']['assessment']}\n")
    print(f"Final Verdict and Remediation:\n{result['final_judgment']['evaluation']}\n")


if __name__ == "__main__":
    main()