from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage
from langsmith import Client

class Judge:
    def __init__(self, llm):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are the final decision-maker in a CrowdStrike Falcon log analysis 
            investigation. Your role is to:
            
            1. Determine if there was a security incident based on the evidence
            2. Deliver a clear verdict on the nature and severity of any security issues
            3. Provide a concise summary of the attack or suspicious activity
            4. Recommend SPECIFIC, ACTIONABLE remediation steps
            
            For remediation, provide exact CrowdStrike Falcon commands, system commands, or 
            PowerShell/Bash scripts that the security team can execute. Be as specific as possible.
            
            Format your response as:
            
            VERDICT: [Clear statement on whether a security incident occurred]
            
            SUMMARY: [Concise explanation of the findings]
            
            ATTACK CLASSIFICATION: [MITRE ATT&CK tactics and techniques identified]
            
            REMEDIATION COMMANDS:
            ```
            [Exact commands to execute]
            ```
            
            NEXT STEPS: [Additional investigation recommendations]
            """),
            ("user", """
            Security Investigation Request: {human_input}
            
            CrowdStrike Falcon Analysis:
            
            Original Plan:
            {plan}
            
            Consolidated Findings (with voting results):
            {critique_assessment}
            
            Based on this analysis, provide your final verdict and actionable remediation steps.
            Focus on:
            1. Clear determination of whether a security incident occurred
            2. Specific MITRE ATT&CK tactics and techniques involved
            3. Exact, executable commands for remediation
            4. Additional investigation steps needed
            """)
        ])
        self.chain = self.prompt | self.llm

    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        # Generate response
        response = self.chain.invoke({
            "human_input": state["human_input"],
            "plan": state["plan"],
            "critique_assessment": state["critique_output"]["assessment"]
        })
        
        # Create training example in LangSmith
        try:
            client = Client()
            
            # Prepare worker outputs for training example
            worker_outputs = []
            for i in range(1, 6):  # Support 5 workers
                worker_key = f"worker{i}_output"
                if worker_key in state:
                    worker_outputs.append({
                        "role": state[worker_key]["role"],
                        "analysis": state[worker_key]["analysis"]
                    })
            
            client.create_example(
                inputs={
                    "human_input": state["human_input"],
                    "plan": state["plan"],
                    "worker_outputs": worker_outputs,
                    "critique": state["critique_output"]["assessment"]
                },
                outputs={
                    "judgment": response.content
                },
                dataset_name="crowdstrike_detection_training_examples"
            )
        except Exception as e:
            print(f"Failed to create LangSmith example: {e}")
        
        # Return the final judgment
        return {
            "final_judgment": {"evaluation": response.content}
        }