import json
import networkx as nx
from agent import SecurityInvestigationAgent
from knowledge_graph import ThreatGraph
import matplotlib.pyplot as plt

# --- Configuration ---

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
# OLLAMA_MODEL = "deepseek-r1:1.5b" # the perfromace was verybad such small model not recommended 
OLLAMA_MODEL = "mistral:7b" #expriemnt with different model here


SAMPLE_ALERT = {
  "alert_id": "ALT-2024-10891",
  "title": "Suspicious PowerShell Execution",
  "severity": "High",
  "timestamp": "2024-11-06T14:23:45Z",
  "entity": {
    "type": "user",
    "username": "jdoe@company.com",
    "ip": "192.168.1.105"
  },
  "details": {
    "process": "powershell.exe",
    "command_line": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A...",
    "parent_process": "outlook.exe"
  }
}


if __name__ == "__main__":
    
    #---- Agent investigation part ----
    agent = SecurityInvestigationAgent(OLLAMA_ENDPOINT, OLLAMA_MODEL)
    
    # Run the full invetigation
    report, kql_queries, findings = agent.investigate(SAMPLE_ALERT)
    
    print("\n\n" + "="*80)
    print("DELIVERABLES - PART 1")
    print("="*80)
    
    # Save KQL queries to file
    with open("sample_kql_queries.txt", "w") as f:
        f.write("### Example KQL Queries Generated ###\n")
        for i, kql in enumerate(kql_queries):
            f.write(f"\n--- Query {i+1} ---\n")
            f.write(kql + "\n")
    print("\n Sample KQL queries saved to 'sample_kql_queries.txt'")

    # Save report to file
    with open("sample_report.txt", "w") as f:
        f.write("### Sample Investigation Report ###\n\n")
        f.write(report)
    print(" Sample investigation report saved to 'sample_report.txt'")


    # ---- Knowledge Graph Analysis Part ----
    
    print("\n\n" + "="*80)
    print("DELIVERABLES - PART 2")
    print("="*80)
    
    kg = ThreatGraph()
    
    # Populate graph from Part 1
    kg.build_from_investigation(SAMPLE_ALERT, findings)
    
    print("\n### Graph Neighbors Example ###")
    user_node = SAMPLE_ALERT['entity']['username']
    print(f"Neighbors of '{user_node}':")
    for neighbor in kg.graph.neighbors(user_node):
        edge_data = kg.graph.get_edge_data(user_node, neighbor)
        print(f"  - [{edge_data['relationship']}] -> {neighbor}")

    print("\n### Graph Path Finding Example ###")
    try:
        path = nx.shortest_path(kg.graph, source='outlook.exe', target='1.2.3.4')
        print(f"Shortest path from 'outlook.exe' to '1.2.3.4':\n  {' -> '.join(path)}")
    except nx.NetworkXNoPath:
        print("No path found between 'outlook.exe' and '1.2.3.4'")
        
    # Run and display the complex query
    kg.demonstrate_complex_query()
    
    print("\n\n### How Knowledge Graphs Enhance Agentic SOC Investigations ###")
    print("""
    A Knowledge Graph (KG) acts as the 'brain' or 'long-term memory' for an AI agent, 
    transforming it from a simple data-fetcher into a true investigator.

    1.  **Contextual Awareness:** An LLM agent alone only knows what's in its prompt. 
        A KG provides immediate, rich context. The agent can query the graph for 
        'what else is related to this IP?' and instantly see 5 other alerts, 
        2 other users, and its known-malicious status—information that would 
        require dozens of separate, slow log queries otherwise.

    2.  **Bridging Data Silos:** As demonstrated in the complex query, KGs connect 
        disparate data sources. An agent can find a path from an 'Email' log 
        (IP -> User) to a 'Process' log (User -> Process) without manually 
        correlating timestamps. This allows it to identify complex attack 
        chains, like spear-phishing leading to code execution, which are 
        nearly impossible to spot with linear queries.

    3.  **Improved Agent Decisions:** With a KG, the agent's 'plan' becomes dynamic. 
        If it adds a new finding and the graph reveals that finding is 
        connected to a critical asset, the agent can *immediately* escalate 
        the alert severity and change its next steps, moving from 'investigation' 
        to 'containment' without human intervention.
    """)


#plotting part 
print("\n\n" + "="*80)
print("DELIVERABLE: Knowledge Graph Plot")
print("="*80)

color_map = []
for node in kg.graph:
    node_type = kg.graph.nodes[node].get('type')
    if node_type == 'User':
        color_map.append('blue')
    elif node_type == 'Process':
        color_map.append('red')
    elif node_type == 'IP':
        color_map.append('orange')
    elif node_type == 'Alert':
        color_map.append('yellow')
    elif node_type == 'MITRE_Technique':
        color_map.append('green')
    else:
        color_map.append('grey')

plt.figure(figsize=(12, 10))

#Draw 
nx.draw(kg.graph, 
        node_color=color_map, 
        with_labels=True, 
        font_weight='bold', 
        node_size=800, 
        font_size=8,
        alpha=0.8)

plt.savefig("knowledge_graph.png", format="PNG", dpi=300)
print("Knowledge Graph plot saved to 'knowledge_graph.png'") #can replace with plt.show()

