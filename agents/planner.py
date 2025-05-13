from typing import Dict, Any, List, TypedDict
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

class PlannerOutput(TypedDict):
    plan: str
    worker_definitions: List[Dict[str, str]]

class Planner:
    """
    Agent that creates a detailed plan based on user input for CrowdStrike log analysis,
    focusing on MITRE ATT&CK tactics and techniques.
    """

    def __init__(self, llm: ChatOpenAI):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a security planning agent specialized in CrowdStrike Falcon log analysis.
            
            Your task is to:
            1. Interpret a security investigation request
            2. Create a detailed plan for analyzing CrowdStrike Falcon logs
            3. Select the most appropriate specialized worker agents for parallel analysis
            
            For each task, select 5 workers from these EXACT security specialties (use these exact names):
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
            
            CrowdStrike log types to consider:
            - DetectionSummaryEvents: Security incidents and MITRE info
            - FirewallMatchEvents: Network traffic triggers
            - NetworkConnectionEvents: All network connections
            - ProcessRollupEvents: Process execution details
            - RegistryEvents: Windows registry operations
            - AuthActivityAuditEvents: Authentication events
            - DnsRequestEvents: DNS lookups made by systems
            
            Format your response EXACTLY as follows (do not use markdown formatting):
            PLAN: [detailed plan for Falcon log analysis]
            
            WORKERS:
            1. Initial Access Specialist: [specific focus areas and tasks]
            2. Execution Specialist: [specific focus areas and tasks]
            3. Persistence Specialist: [specific focus areas and tasks]
            4. Privilege Escalation Specialist: [specific focus areas and tasks]
            5. Defense Evasion Specialist: [specific focus areas and tasks]
            
            IMPORTANT: Use the EXACT role names as listed above. Do not modify them or add any formatting.
            """),
            ("user", """
            Security Investigation Request: {human_input}
            
            CrowdStrike Log Preview: {log_content}
            
            Create a detailed investigation plan and select the 5 most relevant worker specialists for parallel analysis.
            For each worker, specify:
            1. Their MITRE ATT&CK focus areas
            2. Specific log types they should analyze
            3. Types of evidence they should look for
            4. Platform-specific commands they should provide (Windows, Linux, macOS)
            
            Remember to use the EXACT role names as provided in the system prompt.
            """)
        ])
        self.chain = self.prompt | self.llm

    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the planner agent.
        """
        human_input = state["human_input"]
        log_content = state.get("log_content", "")

        # Generate response
        response = self.chain.invoke({
            "human_input": human_input,
            "log_content": log_content
        })
        content = response.content

        # Parse the response to extract plan and worker definitions
        plan_section = ""
        workers_section = []
        
        # Parsing logic
        if "PLAN:" in content and "WORKERS:" in content:
            plan_section = content.split("PLAN:")[1].split("WORKERS:")[0].strip()
            workers_raw = content.split("WORKERS:")[1].strip()
            
            # Parse worker definitions with more robust pattern
            import re
            # Updated pattern to better handle role extraction and remove markdown
            worker_pattern = r'(\d+)\.\s*([^:]+?)(?:\s*:\s*|\s+)(.*?)(?=\d+\.\s*[^:]+:|$)'
            matches = re.findall(worker_pattern, workers_raw, re.DOTALL)
            
            for _, role, tasks in matches:
                # Clean up role and tasks - remove any markdown formatting
                role = re.sub(r'\*+', '', role.strip())  # Remove asterisks
                tasks = re.sub(r'\*+', '', tasks.strip())  # Remove asterisks
                
                # Validate role against known roles
                valid_roles = [
                    "Initial Access Specialist",
                    "Execution Specialist",
                    "Persistence Specialist",
                    "Privilege Escalation Specialist",
                    "Defense Evasion Specialist",
                    "Credential Access Specialist",
                    "Discovery Specialist",
                    "Lateral Movement Specialist",
                    "Collection Specialist",
                    "Exfiltration Specialist"
                ]
                
                # If role doesn't match exactly, try to find the closest match
                if role not in valid_roles:
                    # Try to find a role that contains the given role name
                    for valid_role in valid_roles:
                        if role.lower() in valid_role.lower():
                            role = valid_role
                            print(f"PLANNER: Mapped '{role}' to valid role")
                            break
                    else:
                        # If no match found, use a default role
                        print(f"PLANNER: Warning - Unknown role '{role}', using default role")
                        role = "Discovery Specialist"  # Default role
                
                workers_section.append({
                    "role": role,
                    "tasks": tasks
                })
                
                print(f"PLANNER: Added worker with role '{role}' and tasks: {tasks[:100]}...")
        
        # Create result preserving original state where appropriate
        result = {}
        
        # Copy all state except worker-related fields
        for key, value in state.items():
            if key not in ["plan", "worker_definitions", "worker1_output", "worker2_output", "worker3_output", 
                          "worker4_output", "worker5_output", "critique_output"]:
                result[key] = value
        
        # Add new plan and worker definitions
        result["plan"] = plan_section
        result["worker_definitions"] = workers_section

        print(f"PLANNER: Generated new plan with {len(workers_section)} worker definitions")
        print("Worker roles assigned:")
        for i, worker in enumerate(workers_section, 1):
            print(f"  Worker {i}: {worker['role']}")

        return result