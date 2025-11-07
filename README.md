# AI Security Investigation Agent & Knowledge Graph

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project is a prototype of an autonomous AI agent designed to investigate security alerts from a simulated SOC (Security Operations Center) environment. It uses a local LLM (via Ollama) to reason, plan, and act on alerts, and a Knowledge Graph to build a persistent contextual memory of threats.

---

## Core Features

* **🤖 Autonomous Triage & Planning:** Ingests a JSON security alert and uses an LLM to create a step-by-step investigation plan.
* **⚙️ Dynamic Query Generation:** Translates the investigation plan into KQL (Kusto Query Language) queries to "search" for evidence.
* **📊 Structured Report Generation:** Synthesizes all findings into a professional investigation report, complete with an executive summary, timeline, and **MITRE ATT&CK** technique mapping.
* **🧠 Persistent Memory:** Uses a `networkx` Knowledge Graph to store relationships between entities (users, IPs, processes) from investigations.
* **🔍 Graph-Enhanced Analysis:** Can run complex queries on the Knowledge Graph to find hidden attack paths (e.g., *find all processes executed by users who received emails from a suspicious IP*).

---

## Technology Stack

* **Python 3.9+**
* **Ollama:** For running local LLMs (e.g., `mistral:7b`, `llama3:8b`).
* **`requests`:** For all API communication with the Ollama server.
* **`networkx`:** For building, managing, and querying the in-memory Knowledge Graph.
* **`matplotlib`:** For visualizing the final Knowledge Graph.

---

## 🏛️ Architecture Walkthrough

I designed this agent based on a **"Perceive -> Think -> Act"** autonomous loop. The core "intelligence" is not hard-coded; instead, the agent's Python code acts as an *orchestrator*, delegating all reasoning to an LLM at key decision points.

### Part 1: The Agent's "Plan & Execute" Loop (`agent.py`)

The agent's logic is a chain of three distinct LLM calls, each with a different "persona" and goal:

1.  **🧠 THINK (Strategic): `triage_and_plan()`**
    * **Persona:** "Senior SOC Analyst"
    * **Goal:** To break down a complex problem ("Investigate this alert") into a simple, step-by-step checklist.
    * **Process:** The agent sends the raw `alert.json` to the LLM and asks, "What's the plan?" The LLM's response *becomes* the agent's plan.

2.  **🧠 THINK (Tactical): `generate_kql()`**
    * **Persona:** "KQL Query Expert"
    * **Goal:** To translate a single human-readable plan step into a machine-readable tool query.
    * **Process:** The agent loops through the plan from Step 1. For each step (e.g., "Find user's network activity"), it asks the LLM, "How do I do this one thing in KQL?" This is how the agent "decides" which tool to use.

3.  **🧠 THINK (Synthesis): `generate_report()`**
    * **Persona:** "SOC Manager"
    * **Goal:** To synthesize all the raw findings into a high-level, human-readable report.
    * **Process:** After the loop, the agent has a list of (mocked) findings. It sends this full list to the LLM and asks, "What does all this mean?" The LLM performs the high-level reasoning, connecting `whoami.exe` to **MITRE T1033 (System Owner/User Discovery)** and generating remediation actions.

### Part 2: The Knowledge Graph as the "Brain" (`knowledge_graph.py`)

The LLM is a powerful *processor*, but it's stateless (it has no memory). The Knowledge Graph (KG) solves this by acting as the agent's **persistent, contextual "brain."**

* **Role:** After an investigation, the `build_from_investigation()` function populates the graph with all the entities (Users, IPs, Processes) and their relationships (`executed`, `communicates_with`).
* **Enhancement:** When a *new* alert comes in, the agent can query the KG first. If it sees a familiar IP, it instantly knows the history of that IP and its connection to other alerts and users. This allows the agent to make far more intelligent and context-aware decisions, as demonstrated by the `demonstrate_complex_query()` function.

---

## 🚀 Setup & Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/darkvix/sec_investigation_agent3.git
    cd sec_investigation_agent3
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install and Run Ollama:**
    * [Download and install Ollama](https://ollama.com/) on your machine.
    * Run the Ollama server in a separate terminal:
        ```bash
        ollama serve
        ```

4.  **Pull an LLM Model (Hardware-Dependent):**
    * This agent's "thinking" quality is highly dependent on the model.
    * **Recommended (7B+ Model):** Requires **~6GB+ of VRAM**.
        ```bash
        ollama pull mistral:7b
        ```
    * *After pulling, make sure to update the `OLLAMA_MODEL` variable in `main.py` to match the model you downloaded (e.g., `"mistral:7b"`).*

---

## 💻 How to Run

With the Ollama server running, execute the main script from your terminal:

```bash
python3 main.py
