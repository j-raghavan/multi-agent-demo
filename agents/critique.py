from typing import Dict, Any, List
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage

class Critique:
    def __init__(self, llm):
        self.llm = llm
        self.system_prompt = """You are a senior security analyst responsible for validating findings from 
        multiple specialized CrowdStrike Falcon log analysts. Your task is to:
        
        1. Review findings from each specialist
        2. Identify consensus among specialists (where multiple specialists found similar evidence)
        3. Evaluate the strength of evidence for each finding
        4. Implement a voting mechanism where findings supported by multiple specialists receive higher confidence
        5. Eliminate findings with insufficient evidence
        6. Consolidate the most important findings
        
        For each potential security issue:
        1. Count how many specialists identified related evidence
        2. Assess the quality of the evidence presented
        3. Assign a consolidated confidence score (High/Medium/Low)
        
        Format your response as follows:

        CONSENSUS FINDINGS (BY CONFIDENCE):
        HIGH CONFIDENCE (3+ specialists agree):
        - Finding 1: [Brief description]
          * Evidence from Worker X: [specific log entry]
          * Evidence from Worker Y: [specific log entry]
          * Evidence from Worker Z: [specific log entry]
          * MITRE ATT&CK: [tactic/technique]
          * Recommended Action: [specific command]

        MEDIUM CONFIDENCE (2 specialists agree):
        - Finding 1: [Brief description]
          * Evidence from Worker X: [specific log entry]
          * Evidence from Worker Y: [specific log entry]
          * MITRE ATT&CK: [tactic/technique]
          * Recommended Action: [specific command]

        LOW CONFIDENCE (single specialist):
        - Finding 1: [Brief description]
          * Evidence from Worker X: [specific log entry]
          * MITRE ATT&CK: [tactic/technique]
          * Recommended Action: [specific command]

        SUMMARY:
        - Total findings: [number]
        - High confidence findings: [number]
        - Medium confidence findings: [number]
        - Low confidence findings: [number]
        - Most critical finding: [description]
        - Most urgent action needed: [description]
        """

    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        print("CRITIQUE: Starting consensus analysis")

        # Prepare the user message with all worker outputs
        user_message = f"""
        Security Investigation Request: {state['human_input']}
        Analysis Plan: {state['plan']}

        Worker Analyses:
        """

        # Add each worker's analysis
        for i in range(1, 6):
            worker_key = f"worker{i}_output"
            if worker_key in state:
                worker_data = state[worker_key]
                user_message += f"""
                Worker {i} ({worker_data['role']}) Analysis:
                {worker_data['analysis']}
                """

        user_message += """
        Evaluate these analyses using the voting mechanism:
        1. Identify where multiple specialists found similar evidence
        2. Assess the quality and specificity of the evidence
        3. Rate confidence based on number of specialists in agreement
        4. Ensure each finding is tied to specific log entries
        5. Verify that recommended actions include platform-specific commands
        
        Present your findings in order of confidence, focusing on issues with the strongest evidence.
        """

        # Create messages manually
        system_message = SystemMessage(content=self.system_prompt)
        human_message = HumanMessage(content=user_message)
        
        # Call the LLM directly
        response = self.llm.invoke([system_message, human_message])
        content = response.content

        # Return only the critique output
        result = {
            "critique_output": {"assessment": content}
        }

        print("CRITIQUE: Completed consensus analysis")
        return result