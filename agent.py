import json
import requests
import re
import base64

class SecurityInvestigationAgent:
    """
    An AI agent to investigate security alerts, generate KQL, 
    and produce a final report.
    """
    def __init__(self, ollama_url, model_name):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.findings = []
        self.kql_queries = []
        print(f"Agent initialized with model: {self.model_name}")

    def _call_llm(self, prompt, system_message=""):
        """Helper function to call the Ollama API."""
        full_prompt = f"{system_message}\n\n---PROMPT---\n{prompt}"
        payload = {
            "model": self.model_name,
            "prompt": full_prompt,
            "stream": False
        }
        try:
            response = requests.post(self.ollama_url, json=payload, timeout=120)
            response.raise_for_status() # incase smething went wrong
            return response.json()['response'].strip()
        except requests.exceptions.RequestException as e:
            print(f"Error calling Ollama: {e}")
            return f"Error: Could not get response from LLM. {e}"

    def decode_base64(self, encoded_string):
        """Utility to decode Base64 strings, handling PowerShell encoding."""
        try:
            # PowerShell -enc flag uses UTF-16LE
            decoded_bytes = base64.b64decode(encoded_string)
            return decoded_bytes.decode('utf-16-le')
        except Exception as e:
            print(f"Base64 decode error: {e}")
            return f"[Could not decode: {encoded_string[:20]}...]"

    def triage_and_plan(self, alert):
        """
        Uses LLM to analyze the alert, assess severity, 
        and create an investigation plan.
        """
        print("\n--- 1. Triage and Planning ---")
        
        # Try to decode the command line for better context
        if " -enc " in alert['details']['command_line']:
            encoded_part = alert['details']['command_line'].split(' -enc ')[1].split(' ')[0]
            decoded_command = self.decode_base64(encoded_part)
            alert['details']['decoded_command'] = decoded_command
            print(f"Decoded command: {decoded_command}")
            self.findings.append(f"Decoded Base64 command: {decoded_command}")

        system_prompt = (
            "You are a Senior SOC Analyst. Your task is to analyze a security alert "
            "and create a concise, step-by-step investigation plan. "
            "Provide *only* the numbered list of steps."
        )
        
        prompt = (
            f"Analyze the following alert and create an investigation plan:\n\n"
            f"{json.dumps(alert, indent=2)}\n\n"
            "Investigation Plan:"
        )
        
        plan_response = self._call_llm(prompt, system_prompt)
        
        # Simple parsing of the numbered list
        plan = [step.strip() for step in re.findall(r'^\d+\.\s*(.*)', plan_response, re.MULTILINE)]
        
        if not plan:
            print("LLM failed to generate a structured plan. Using a default plan.")
            plan = [
                "Analyze the user's activity timeline around the alert time.",
                "Investigate the parent process 'outlook.exe' for suspicious child processes.",
                "Look for network connections from powershell.exe on the user's host.",
                "Check for other process executions by the user 'jdoe@company.com'."
            ]

        print("Investigation Plan:")
        for step in plan:
            print(f"- {step}")
            
        return plan

    def execute_plan(self, alert, plan):
        """
        Iterates through the plan, generates KQL, and mocks findings.
        """
        print("\n--- 2. Plan Execution (Generating KQL & Mocking Findings) ---")
        
        alert_entity = alert['entity']
        
        for i, step in enumerate(plan):
            print(f"\nExecuting Step: {step}")
            kql = self.generate_kql(alert, step)
            self.kql_queries.append(kql)
            print(f"Generated KQL:\n{kql}")
            
            # --- MOCKING FINDINGS ---
            # In a real system, you'd run the KQL here.
            # We will "mock" a finding for this step.
            mock_finding = self._get_mock_finding(step, alert_entity)
            if mock_finding:
                print(f"Mock Finding: {mock_finding}")
                self.findings.append(f"Step: {step} | Finding: {mock_finding}")
            

    def generate_kql(self, alert, step):
        """Uses LLM to generate a KQL query for a specific investigation step."""
        system_prompt = (
            "You are a KQL query expert. Given an investigation step and alert context, "
            "write the *only* the KQL query. Do not include any other text or explanation. "
            "Use a 1-hour time window around the alert timestamp."
        )
        
        timestamp = alert['timestamp']
        username = alert['entity']['username']
        ip = alert['entity']['ip']
        process = alert['details']['process']
        parent_process = alert['details']['parent_process']
        
        prompt = (
            f"Alert Timestamp: {timestamp}\n"
            f"Username: {username}\n"
            f"IP: {ip}\n"
            f"Process: {process}\n"
            f"Parent Process: {parent_process}\n\n"
            f"Investigation Step: {step}\n\n"
            f"KQL Query:"
        )
        
        kql_query = self._call_llm(prompt, system_prompt)
        
        # Basic cleanup in case the small LLM adds extra text (happmed when playing with deepseekr1:1.5b)
        if "```" in kql_query:
            kql_query = kql_query.split("```")[1].replace("kql", "").strip()
            
        return kql_query

    def _get_mock_finding(self, step, entity):
        """Provides predefined mock data for simulated investigation."""
        step_lower = step.lower()
        if "user activity" in step_lower or "timeline" in step_lower:
            return f"User {entity['username']} logged in from IP {entity['ip']} at 14:20Z."
        if "process" in step_lower and "user" in step_lower:
            return f"User {entity['username']} also executed 'whoami.exe' at 14:24:01Z."
        if "network" in step_lower or "connection" in step_lower:
            return (
                f"Process 'powershell.exe' (PID 4567) made an outbound connection "
                f"to IP 8.8.4.4 over port 53 (DNS) and 1.2.3.4 over port 443."
            )
        if "parent process" in step_lower or "outlook" in step_lower:
            return "'outlook.exe' (PID 2345) spawned 'powershell.exe' (PID 4567)."
        return None

    def generate_report(self, alert):
        """Uses LLM to synthesize all findings into a final report."""
        print("\n--- 3. Report Generation ---")
        
        system_prompt = (
            "You are a SOC Manager. Synthesize the following alert data and investigation "
            "findings into a structured investigation report. "
            "Assign MITRE ATT&CK techniques based on the findings. "
            "Provide clear remediation actions."
        )
        
        prompt = (
            "Please generate a full investigation report.\n\n"
            f"Original Alert:\n{json.dumps(alert, indent=2)}\n\n"
            "Investigation Findings:\n"
        )
        for f in self.findings:
            prompt += f"- {f}\n"
            
        prompt += "\n\nStructured Investigation Report:"
        
        report = self._call_llm(prompt, system_prompt)
        print(report)
        return report

    def investigate(self, alert):
        """Main orchestration function."""
        print(f"--- Starting Investigation for Alert: {alert['alert_id']} ---")
        
        # 1. Triage and Plan
        plan = self.triage_and_plan(alert)
        
        # 2. Execute Plan (and mock findings)
        self.execute_plan(alert, plan)
        
        # 3. Generate Final Report
        report = self.generate_report(alert)
        
        print("\n--- Investigation Complete ---")
        return report, self.kql_queries, self.findings