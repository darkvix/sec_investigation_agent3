import networkx as nx

class ThreatGraph:
    """
    Builds and queries a knowledge graph for threat intelligence 
    using NetworkX.
    """
    
    # --- Schema Definition (as comments) ---
    # Entities (Nodes):
    #   - User (e.g., 'jdoe@company.com', {'type': 'User'})
    #   - Host (e.g., 'DESKTOP-JDOE', {'type': 'Host'})
    #   - IP (e.g., '192.168.1.105', {'type': 'IP'})
    #   - Process (e.g., 'powershell.exe', {'type': 'Process'})
    #   - Alert (e.g., 'ALT-2024-10891', {'type': 'Alert'})
    #   - MITRE_Technique (e.g., 'T1059.001', {'type': 'MITRE_Technique'})
    #
    # Relationships (Edges):
    #   - triggered (Alert -> User)
    #   - executed_on (User -> Process, Process -> Host)
    #   - parent_of (Process -> Process)
    #   - communicates_with (Process -> IP)
    #   - associated_with (Host -> IP, Host -> User)
    #   - maps_to (Alert -> MITRE_Technique)
    #   - sent_email_to (IP -> User) - *for complex query*
    # ----------------------------------------
    
    def __init__(self):
        self.graph = nx.Graph()
        print(f"\n Knowledge Graph initialized.")

    def add_node(self, node_id, node_type, **attrs):
        """Adds or updates a node in the graph."""
        if node_id not in self.graph:
            self.graph.add_node(node_id, type=node_type, **attrs)
        else:
            # Update existing node's attributes if needed
            nx.set_node_attributes(self.graph, {node_id: {"type": node_type, **attrs}})

    def add_edge(self, node1, node2, relationship):
        """Adds a relationship (edge) between two nodes."""
        if node1 in self.graph and node2 in self.graph:
            self.graph.add_edge(node1, node2, relationship=relationship)
        else:
            print(f"Warning: Could not create edge. Node not found.")

    def build_from_investigation(self, alert, findings):
        """Populates the graph based on alert and findings."""
        print("--- Building Knowledge Graph from Investigation ---")
        
        # From Alert
        alert_id = alert['alert_id']
        user = alert['entity']['username']
        host_ip = alert['entity']['ip']
        process = alert['details']['process']
        parent_process = alert['details']['parent_process']
        
        # Add primary nodes from alert
        self.add_node(alert_id, 'Alert', title=alert['title'])
        self.add_node(user, 'User')
        self.add_node(host_ip, 'IP', status='Internal') # Assume internal
        self.add_node(process, 'Process')
        self.add_node(parent_process, 'Process')
        
        # Add primary relationships from alert
        self.add_edge(alert_id, user, 'triggered_on')
        self.add_edge(user, process, 'executed')
        self.add_edge(parent_process, process, 'parent_of')
        
        # From Mock Findings (simulating real data)
        for f in findings:
            if "whoami.exe" in f:
                self.add_node('whoami.exe', 'Process')
                self.add_edge(user, 'whoami.exe', 'executed')
            if "1.2.3.4" in f:
                self.add_node('1.2.3.4', 'IP', status='Suspicious')
                self.add_edge(process, '1.2.3.4', 'communicates_with')
                
        # Add mock MITRE mapping (from report)
        self.add_node('T1059.001', 'MITRE_Technique', name='PowerShell')
        self.add_edge(alert_id, 'T1059.001', 'maps_to')
        
        print("Graph populated with investigation data.")

    def demonstrate_complex_query(self):
        """
        Shows: "All processes executed by users who received emails 
        from suspicious IPs in the last 7 days"
        """
        print("\n--- Demonstrating Graph-Enhanced Investigation Query ---")
        
        # 1. First, we must "seed" the graph with this extra data
        print("Seeding graph with new intel...")
        self.add_node('bad.actor.ip', 'IP', status='Suspicious')
        self.add_node('another_user@company.com', 'User')
        self.add_node('malicious_downloader.exe', 'Process')
        
        # This is the key relationship: email log data
        self.add_edge('bad.actor.ip', 'another_user@company.com', 'sent_email_to')
        # This is the process execution data
        self.add_edge('another_user@company.com', 'malicious_downloader.exe', 'executed')
        
        # 2. Now, run the query
        print('Query: "Find all processes executed by users who received emails from suspicious IPs"')
        suspicious_ips = {n for n, d in self.graph.nodes(data=True) if d.get('type') == 'IP' and d.get('status') == 'Suspicious'}
        
        compromised_users = set()
        for ip in suspicious_ips:
            for neighbor in self.graph.neighbors(ip):
                if self.graph.get_edge_data(ip, neighbor)['relationship'] == 'sent_email_to':
                    if self.graph.nodes[neighbor].get('type') == 'User':
                        compromised_users.add(neighbor)
                        
        print(f"Found users who received email from suspicious IPs: {compromised_users}")
        
        suspicious_processes = set()
        for user in compromised_users:
            for neighbor in self.graph.neighbors(user):
                if self.graph.get_edge_data(user, neighbor)['relationship'] == 'executed':
                    if self.graph.nodes[neighbor].get('type') == 'Process':
                        suspicious_processes.add(neighbor)

        print(f"Found processes executed by those users: {suspicious_processes}")
        return suspicious_processes