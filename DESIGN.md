# Security Log Analysis System Implementation

## Overview

This document details the implementation of a multi-agent system for analyzing CrowdStrike Falcon logs, focusing on security anomaly detection using a parallel execution model with voting-based consensus.

## System Architecture

### Core Components

1. **Planner Agent** (`agents/planner.py`)
   - Analyzes security investigation requests
   - Creates detailed analysis plans
   - Selects 5 specialized worker agents for parallel execution
   - Uses exact role names from predefined MITRE ATT&CK-aligned specialties

2. **Worker Factory** (`agents/worker_factory.py`)
   - Creates specialized security workers
   - Implements role validation and mapping
   - Supports 10 MITRE ATT&CK-aligned roles:
     - Initial Access Specialist
     - Execution Specialist
     - Persistence Specialist
     - Privilege Escalation Specialist
     - Defense Evasion Specialist
     - Credential Access Specialist
     - Discovery Specialist
     - Lateral Movement Specialist
     - Collection Specialist
     - Exfiltration Specialist

3. **Critique Agent** (`agents/critique.py`)
   - Implements voting-based consensus mechanism
   - Reviews findings from all workers
   - Identifies consensus among specialists
   - Evaluates evidence strength
   - Categorizes findings by confidence levels:
     - High Confidence (3+ specialists agree)
     - Medium Confidence (2 specialists agree)
     - Low Confidence (single specialist)

4. **Judge Agent** (`agents/judge.py`)
   - Provides final assessment
   - Delivers actionable recommendations
   - Creates training examples in LangSmith
   - Outputs structured verdict with:
     - Clear incident determination
     - MITRE ATT&CK classification
     - Specific remediation commands
     - Next steps

### Workflow Implementation

The system uses LangGraph for workflow management, implemented in `main.py`:

```python
# Graph Structure
planner -> [worker1, worker2, worker3, worker4, worker5] -> critique -> judge -> END
```

1. **Parallel Execution**
   - Planner creates analysis plan and worker definitions
   - All 5 workers execute in parallel
   - Each worker focuses on their specialized role
   - No sequential dependencies between workers

2. **Voting-Based Consensus**
   - Critique agent receives all worker outputs
   - Implements voting mechanism for findings
   - No feedback loop to workers
   - Direct progression to judge after consensus

3. **State Management**
   ```python
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
   ```

## Implementation Details

### 1. Planner Implementation

The planner uses a structured prompt to:
- Interpret security investigation requests
- Create detailed analysis plans
- Select appropriate worker roles
- Format output consistently

Key features:
- Role validation against known specialties
- Markdown formatting removal
- Clear task definition for each worker
- Log type consideration (DetectionSummaryEvents, FirewallMatchEvents, etc.)

### 2. Worker Implementation

Each worker is created with:
- Specialized role-based prompts
- MITRE ATT&CK-aligned focus areas
- Specific log type analysis
- Evidence-based reporting

Worker output format:
```python
{
    "role": str,  # Validated role name
    "analysis": str  # Structured analysis with evidence
}
```

### 3. Critique Implementation

The critique agent implements a voting mechanism:
1. Reviews all worker outputs
2. Identifies consensus findings
3. Evaluates evidence quality
4. Assigns confidence levels
5. Provides summary statistics

Output format:
```
CONSENSUS FINDINGS (BY CONFIDENCE):
HIGH CONFIDENCE (3+ specialists agree):
- Finding 1: [Description]
  * Evidence from Worker X: [Log entry]
  * MITRE ATT&CK: [Tactic/technique]
  * Recommended Action: [Command]

SUMMARY:
- Total findings: [number]
- High confidence findings: [number]
- Medium confidence findings: [number]
- Low confidence findings: [number]
```

### 4. Judge Implementation

The judge provides final assessment with:
1. Clear verdict on security incidents
2. MITRE ATT&CK classification
3. Specific remediation commands
4. Next steps for investigation

Output format:
```
VERDICT: [Incident determination]
SUMMARY: [Findings explanation]
ATTACK CLASSIFICATION: [MITRE ATT&CK details]
REMEDIATION COMMANDS:
```
[Executable commands]
```
NEXT STEPS: [Additional recommendations]
```

## Usage

### Command Line Interface

```bash
python main.py --query "YOUR QUERY" --log-file path/to/logs.json.gz
```

Optional parameters:
- `--max-events`: Maximum events to analyze (default: 50)
- `--max-iterations`: Maximum analysis iterations (default: 3)

### Example Queries

1. General security analysis:
   ```bash
   python main.py --query "What security issues are present in these logs?"
   ```

2. Anomaly detection:
   ```bash
   python main.py --query "Identify any unusual activity in these logs"
   ```

3. MITRE ATT&CK analysis:
   ```bash
   python main.py --query "What MITRE ATT&CK techniques are observed?"
   ```

## Current Limitations

1. No feedback loop from critique to workers
2. Fixed number of workers (5)
3. No persistent storage of analysis results
4. Limited to single log file analysis
5. No real-time analysis capabilities

## Future Enhancements

1. Implement worker memory for retaining insights
2. Add visualization capabilities
3. Support multiple log file analysis
4. Implement real-time analysis
5. Add persistent storage for historical comparison
6. Create web interface for easier interaction
7. Add automated alerting based on findings

## Dependencies

- langchain==0.1.8
- langchain-openai==0.0.5
- langgraph==0.0.21
- langsmith==0.0.72
- openai==1.12.0
- pydantic==2.5.2
- python-dotenv==1.0.0

## Testing

The system includes test cases in `tests/` directory:
- `test_full_workflow.py`: End-to-end workflow tests
- `test_voting.py`: Voting mechanism tests
- Sample log files for testing

## Environment Setup

1. Create `.env` file with:
   ```
   OPENAI_API_KEY=your_api_key
   LANGCHAIN_API_KEY=your_langsmith_key
   ```

2. Install dependencies:
   ```bash
   poetry install
   ```

3. Run tests:
   ```bash
   python -m pytest tests/
   ``` 
