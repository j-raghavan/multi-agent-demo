from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

class WorkerFactory:
    def __init__(self, llm):
        self.llm = llm

    def create_worker(self, worker_id: int, role: str, tasks: str):
        """Create a specialized security worker based on MITRE ATT&CK role and tasks"""
        
        # Validate role
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
        
        if role not in valid_roles:
            print(f"WORKER FACTORY: Warning - Invalid role '{role}' for worker {worker_id}")
            # Try to find a matching role
            for valid_role in valid_roles:
                if role.lower() in valid_role.lower():
                    role = valid_role
                    print(f"WORKER FACTORY: Mapped to valid role '{role}'")
                    break
            else:
                print(f"WORKER FACTORY: No valid role match found, using default role")
                role = "Discovery Specialist"  # Default role
        
        print(f"WORKER FACTORY: Creating worker {worker_id} with role '{role}'")
        
        # Define the system prompt based on security specialty (MITRE ATT&CK-aligned)
        role_prompts = {
            "Initial Access Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            identifying INITIAL ACCESS tactics. Look for evidence of phishing, exploitation of public-facing
            applications, external remote services being leveraged, hardware additions, or trusted relationship
            compromise. Pay special attention to:
            - New process creation from external sources
            - Email attachments being executed
            - Web browsers executing suspicious content
            - VPN or remote access connections from unusual sources
            """,
            
            "Execution Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            analyzing EXECUTION tactics. Look for evidence of command and script execution, container 
            administration commands, native API calls, system services, or Windows Management Instrumentation 
            usage. Pay special attention to:
            - Command-line interface usage patterns
            - PowerShell or bash commands
            - Script execution (JavaScript, VBScript, Python, etc.)
            - Service creation or modification
            """,
            
            "Persistence Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            identifying PERSISTENCE mechanisms. Look for evidence of account manipulation, boot/logon 
            autostart execution, scheduled tasks/jobs, or registry modifications. Pay special attention to:
            - New scheduled tasks or cron jobs
            - Registry modifications in run keys
            - New services or daemons
            - Startup folder modifications
            - Kernel module or driver loading
            """,
            
            "Privilege Escalation Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            detecting PRIVILEGE ESCALATION attempts. Look for evidence of access token manipulation, 
            exploitation for privilege escalation, process injection, or sudo/admin-equivalent operations. 
            Pay special attention to:
            - UAC bypasses
            - Sudo commands or runas usage
            - Service permissions being modified
            - Process handle manipulation
            - Unusual process ancestry
            """,
            
            "Defense Evasion Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            finding DEFENSE EVASION techniques. Look for evidence of clearing logs, deobfuscation of files,
            hidden files/directories, indicator removal, masquerading, or process injection. Pay special attention to:
            - Log clearing or deletion events
            - Hidden files or directories
            - Timestomping
            - File deletion
            - Rootkit installation
            """,
            
            "Credential Access Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            identifying CREDENTIAL ACCESS attempts. Look for evidence of brute force attempts, credential 
            dumping, input capture, OS credential dumping, or password policy discovery. Pay special attention to:
            - Multiple failed authentication attempts
            - Access to credential stores
            - Memory access to lsass.exe
            - Creation of minidump files
            - Keylogging processes
            """,
            
            "Discovery Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            detecting DISCOVERY activities. Look for evidence of account discovery, file/directory discovery,
            network service scanning, permission group discovery, or system information discovery. Pay special attention to:
            - Network discovery commands (ping, nslookup, etc.)
            - Account enumeration
            - System information commands
            - Active Directory queries
            - Permission group enumeration
            """,
            
            "Lateral Movement Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            finding LATERAL MOVEMENT attempts. Look for evidence of internal remote services, lateral tool 
            transfer, remote services, or exploitation of remote services. Pay special attention to:
            - Remote desktop connections
            - SMB connections
            - WMI or WinRM usage
            - SSH connections between systems
            - Remote execution via PsExec or similar tools
            """,
            
            "Collection Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            identifying DATA COLLECTION activities. Look for evidence of audio capture, clipboard data 
            collection, data from local systems, email collection, or screen capture. Pay special attention to:
            - Large amounts of data being accessed
            - Unusual access patterns to important files
            - Database read operations
            - Email access activities
            - Screen capture processes
            """,
            
            "Exfiltration Specialist": """You are a CrowdStrike Falcon log analyst specializing in 
            detecting DATA EXFILTRATION. Look for evidence of automated exfiltration, exfiltration over 
            alternative protocols, exfiltration over C2 channel, or scheduled transfers. Pay special attention to:
            - Unusual outbound network connections
            - Large outbound data transfers
            - Usage of non-standard protocols
            - Connections to known-bad IPs or domains
            - Scheduled tasks that connect to external systems
            """
        }
        
        # Get the appropriate system prompt or use a generic one
        system_prompt = role_prompts.get(role, 
            f"""You are a specialized CrowdStrike Falcon log analyst focusing on {role}. {tasks}""")
            
        # Create the worker
        class SecurityWorker:
            def __init__(self, llm, worker_id, role, tasks, system_prompt):
                self.llm = llm
                self.worker_id = worker_id
                self.role = role
                self.tasks = tasks
                self.system_prompt = system_prompt
                print(f"WORKER {worker_id}: Initialized as {role}")

            def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
                print(f"WORKER {self.worker_id} ({self.role}): Starting analysis")
                
                # Create the messages manually
                system_message = SystemMessage(content=self.system_prompt)
                
                human_message_content = f"""
                Security Investigation Request: {state['human_input']}
                
                Overall Analysis Plan: {state['plan']}
                
                Your Specific Task: {self.tasks}
                
                CrowdStrike Falcon Log Sample:
                ```
                {state.get('log_content', '')[:10000]}  # Limit log content to prevent overflow
                ```
                
                Analyze these CrowdStrike Falcon logs according to your security specialty ({self.role}). Provide:
                
                1. EVIDENCE: List specific log entries that indicate suspicious activity in your domain
                2. ANALYSIS: Explain what these entries reveal and their security implications
                3. CONFIDENCE: Rate your confidence in each finding (High/Medium/Low)
                4. RECOMMENDATIONS: Suggest specific next investigative steps
                
                For each recommendation, provide platform-specific commands:
                
                ACTIONABLE COMMANDS:
                [Windows]
                - `command1` - Brief explanation
                - `command2` - Brief explanation
                
                [macOS/Linux]
                - `command1` - Brief explanation
                - `command2` - Brief explanation
                
                Focus only on findings relevant to your specialty ({self.role}). Be specific and cite exact log entries.
                """
                
                human_message = HumanMessage(content=human_message_content)
                
                # Call the LLM directly with messages
                response = self.llm.invoke([system_message, human_message])
                
                output_key = f"worker{self.worker_id}_output"
                result = {
                    output_key: {
                        "role": self.role,
                        "analysis": response.content
                    }
                }
                
                print(f"WORKER {self.worker_id} ({self.role}): Completed analysis")
                return result
        
        return SecurityWorker(self.llm, worker_id, role, tasks, system_prompt)