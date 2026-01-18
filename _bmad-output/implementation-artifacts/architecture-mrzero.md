# Architecture Design Document (ADD): MrZero
**Version:** 1.0
**Date:** January 16, 2026
**Based on PRD Version:** 1.0

## 1. Introduction
This document defines the technical architecture for **MrZero**, a local, command-line interface (CLI) tool for autonomous vulnerability research and exploitation. It details the system components, data flow, agent interactions, and technology choices required to implement the functional requirements outlined in the Product Requirements Document (PRD).

## 2. System Overview
MrZero operates as a modular, agent-driven system orchestrated by a state graph. The architecture is layered to separate user interaction, workflow orchestration, intelligence (agents), data persistence, and external tool execution.

### 2.1 High-Level Architecture Diagram
```mermaid
graph TD
    User[User (CLI)] <--> Interface[Presentation Layer (Typer/Rich)]
    Interface <--> Orchestrator[Orchestration Layer (LangGraph)]
    
    subgraph "Data Persistence Layer"
        SQLite[(SQLite DB)]
        VectorDB[(Vector DB - Chroma/FAISS)]
    end
    
    Orchestrator <--> SQLite
    Orchestrator <--> VectorDB
    
    subgraph "Agent Layer"
        Mapper[MrZeroMapper]
        Hunter[MrZeroVulnHunter]
        Verifier[MrZeroVerifier]
        EnvBuilder[MrZeroEnvBuilder]
        Exploit[MrZeroExploitBuilder]
        Reporter[MrZeroConclusion]
    end
    
    Orchestrator --> Mapper
    Orchestrator --> Hunter
    Orchestrator --> Verifier
    Orchestrator --> EnvBuilder
    Orchestrator --> Exploit
    Orchestrator --> Reporter
    
    Hunter <--> Loop((Feedback Loop))
    Verifier <--> Loop
    
    subgraph "Tooling Layer (MCP)"
        SAST[SAST Tools (CodeQL, Semgrep)]
        Dynamic[Dynamic Tools (GDB, Pwntools)]
        Build[Build Tools (Docker, Make)]
    end
    
    Agent Layer --> Tooling Layer
```

## 3. Core Components

### 3.1 Presentation Layer (CLI)
*   **Technology:** Python, `Typer` (for command parsing), `Rich` (for TUI/Progress bars).
*   **Responsibilities:**
    *   Parse commands (`scan`, `config`).
    *   Display real-time status of the active agent.
    *   Handle User Input in **HITL (Human-in-the-Loop)** mode.
    *   Render Markdown reports in terminal.

### 3.2 Orchestration Layer (LangGraph)
*   **Technology:** `LangGraph`.
*   **Responsibilities:**
    *   Define the directed cyclic graph of agent states.
    *   Manage transitions between agents (e.g., Mapper -> Hunter).
    *   Handle "Suspend/Resume" functionality by serializing graph state to SQLite.
    *   Route context between agents.

### 3.3 Data Persistence Layer
The system uses a dual-database strategy for state management and semantic understanding.

#### 3.3.1 SQLite (Structured State & Caching)
*   **Purpose:** Session resumption, tool output caching, and structured finding storage.
*   **Schema Concepts:**
    *   `Sessions`: Stores LangGraph checkpoints.
    *   `ToolCache`: `hash(tool + args)` -> `output` (Prevents redundant execution).
    *   `Findings`: Relational mapping of vulnerabilities (File, Line, Severity, Status).

#### 3.3.2 Vector Database (RAG)
*   **Technology:** ChromaDB or FAISS.
*   **Purpose:** Semantic Code Search.
*   **Workflow:**
    *   Ingestion: Mapper chunks code files and generates embeddings.
    *   Retrieval: Agents query for "authentication logic" or "input sanitization" instead of strict regex.

### 3.4 Tooling Integration (MCP)
*   **Protocol:** Model Context Protocol (MCP).
*   **Strategy:** All external tools (SAST, Debuggers) are wrapped as MCP servers. This standardizes the input/output format for LLMs, making the architecture LLM-agnostic.

## 4. Agent Detailed Design

### 4.1 MrZeroMapper (Attack Surface Surveyor)
*   **Type:** Static Analysis.
*   **Input:** Project Root Directory.
*   **Process:**
    1.  **Fingerprint:** Use `Linguist` to detect languages.
    2.  **Dependency Tree:** Parse package files (package.json, requirements.txt).
    3.  **Endpoint Discovery:** Use `Joern`/`CodeQL` to map routes.
*   **Output:** `attack_surface_map.json` (stored in SQLite/Context).

### 4.2 Hunter-Verifier Cycle
A cyclical graph node designed to maximize True Positives (TP) and minimize False Positives (FP).

#### **MrZeroVulnHunter**
*   **Role:** Generator.
*   **Logic:** Queries VectorDB for high-risk patterns. Executes SAST tools (`CodeQL`, `Slither`, etc.).
*   **Output:** Batch of candidate vulnerabilities.

#### **MrZeroVerifier**
*   **Role:** Filter.
*   **Logic:**
    *   **Taint Analysis:** Traces data flow from Source to Sink.
    *   **Dead Code Check:** Verifies if the vulnerable path is reachable.
*   **Decision:** "Confirmed" or "False Positive".
*   **Loop Condition:** If TP < 3 and Iterations < 3, return to Hunter with feedback (e.g., "Ignore X pattern").

### 4.3 MrZeroEnvBuilder (Environment Architect)
*   **Role:** DevOps / Environment Setup.
*   **Process:**
    1.  **Heuristic Analysis:** Read `Dockerfile`, `Makefile`.
    2.  **Build Loop:** Attempt build -> Parse Error -> Fix -> Retry (Max 5 attempts).
    3.  **Fallback:** If build fails, isolate vulnerable binary/function into a minimal harness.
*   **Output:** Connection Tuple (IP, Port, PID) or `manual_setup_guide.md`.

### 4.4 MrZeroExploitBuilder (The Weaponizer)
*   **Role:** Dynamic Analysis & Exploitation.
*   **Prerequisite:** Active Connection from EnvBuilder.
*   **Process:**
    1.  **Fuzzing/Connection:** Verify interaction with target.
    2.  **Crash Generation:** Create PoC (SegFault / Unexpected Behavior).
    3.  **Exploit Dev:** Use `pwntools`/`ROPgadget` to construct payload.
    4.  **HITL Check:** "Crash confirmed. Proceed to RCE?"
*   **Tools:** `GDB` (Linux), `WinDbg` (Windows), `Frida` (Instrumentation).
*   **Output:** `exploit.py` and execution report.

### 4.5 MrZeroConclusion (The Reporter)
*   **Role:** Aggregator.
*   **Process:** Query SQLite for all confirmed findings, environment details, and exploit paths.
*   **Output:** Final Markdown Report.

## 5. Security & Safety
*   **Local Execution:** All analysis happens on the user's machine. No code is uploaded to cloud services unless an external LLM API is explicitly configured.
*   **Sandboxing:** MrZeroEnvBuilder attempts to containerize targets (Docker) to prevent accidental host damage during exploitation.
*   **Permissions:** Tool runs with user privileges; does not require root unless specific debuggers (like system-wide tracing) are requested and approved by the user.

## 6. Directory Structure
```text
mrzero/
├── cli/                # Typer/Click entry points
├── core/
│   ├── orchestration/  # LangGraph definitions
│   ├── memory/         # SQLite & VectorDB managers
│   └── mcp/            # MCP Client implementation
├── agents/
│   ├── mapper/
│   ├── hunter/
│   ├── verifier/
│   ├── builder/
│   └── exploiter/
└── tools/              # Wrappers for external binaries
```
