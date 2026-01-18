# Product Requirements Document (PRD): MrZero
**Version:** 1.0
**Type:** Autonomous AI Bug Bounty CLI
**Date:** January 15, 2026

## 1. Executive Summary
**MrZero** is a local, command-line interface (CLI) tool designed to autonomously analyze codebases for security vulnerabilities, setup reproduction environments, and generate weaponized exploits. It leverages a multi-agent AI architecture (LLM-agnostic) to mimic the workflow of a human security researcher.

The system operates in two modes:
1.  **YOLO (Autonomous):** The AI makes all decisions end-to-end.
2.  **HITL (Human-in-the-Loop):** The AI pauses at critical decision points to request user validation or guidance.

## 2. Technical Architecture & Data Strategy

### 2.1 Core Framework
*   **Interface:** Python-based CLI (using `Typer` or `Click` with `Rich` for TUI).
*   **Orchestration:** `LangGraph` for stateful, cyclical agent workflows.
*   **Communication:** Model Context Protocol (MCP) to standardize tool interactions.

### 2.2 Data Persistence Strategy
MrZero utilizes a dual-database approach to ensure efficiency, context-retention, and state management.

#### **Why SQLite? (Structured State & Caching)**
We require a relational database (SQLite) for three critical reasons:
1.  **Resume Capability:** Exploitation can take hours. If the user quits the CLI, SQLite stores the exact state of the `LangGraph` nodes, allowing the session to resume exactly where it left off.
2.  **Tool Output Caching (Deduplication):** Before running a heavy tool (e.g., CodeQL), the system checks SQLite for a hash of the target file + tool arguments. If a record exists, it retrieves the previous result instead of burning CPU/Time re-running the analysis.
3.  **Structured Reporting:** It maps findings to file paths and line numbers relationally, making the final report generation robust and queryable.

#### **Why VectorDB? (Semantic Code Understanding)**
We require a Vector Database (e.g., ChromaDB or FAISS) for **RAG (Retrieval Augmented Generation)**:
1.  **Code Understanding:** Standard regex (grep) cannot find "logic that handles user privileges" if specific keywords aren't used. By embedding the codebase into vectors, agents can perform semantic searches (e.g., "Find all input sanitization functions") to understand context before launching exploits.
2.  **Library Linking:** For the EnvBuilder, the agent needs to semantically match import errors to relevant code blocks across the entire project structure.

---

## 3. Agent Specifications

### 3.1 Agent 1: MrZeroMapper (Attack Surface Surveyor)
**Goal:** Map the code structure, identify technologies, and list potential entry points.
**Mode:** Static Analysis Only.

*   **Toolkit (Strict):**
    *   `Opengrep` (Semgrep OSS)
    *   `CodeQL` (Discovery queries only)
    *   `Gitleaks`
    *   `Microsoft Application Inspector`
    *   `Github Linguist`
    *   `Joern`
    *   `Bearer`
    *   `Tree-sitter`
*   **Workflow:**
    1.  Ingest target directory.
    2.  Identify languages (Linguist) and framework (App Inspector).
    3.  Map API routes, unauthenticated endpoints, and data flows (Joern/CodeQL).
*   **Output:** `attack_surface_map.json`

### 3.2 Agent 2 & Agent X Loop: The Hunter-Verifier Cycle
**Goal:** Identification of True Positive vulnerabilities via Static Analysis (SAST).
**Structure:** A feedback loop between **MrZeroVulnHunter** and **MrZeroVerifier**.

#### **MrZeroVulnHunter**
*   **Role:** Candidate generator.
*   **Method:** Static Analysis & SAST (No dynamic execution).
*   **Toolkit (Strict):**
    *   `Opengrep`
    *   `CodeQL`
    *   `Joern`
    *   `Infer`
    *   `Gitleaks`
    *   `Slither` (Smart Contracts)
    *   `Trivy`
    *   `Binwalk`
    *   `MCP Servers`: IDA Pro / Ghidra / BinaryNinja (Disassembly view only).

#### **MrZeroVerifier**
*   **Role:** False Positive (FP) filter.
*   **Toolkit:** Same as MrZeroVulnHunter.

#### **The Loop Workflow:**
1.  **Hunter** scans mapped surface and identifies a batch of potential vulnerabilities.
2.  **Hunter** assigns priority scores based on the **Prioritization Matrix** (see Section 3.3).
3.  **Verifier** analyzes the batch. It traces data flow (Taint Analysis) to see if inputs are sanitized or if code paths are dead.
4.  **Verifier** marks findings as `Confirmed` or `False Positive`.
5.  **Hunter** receives feedback:
    *   Removes FPs.
    *   If count < 3 TP (True Positives), iterates search again with new queries.
6.  **Exit Conditions:**
    *   **Success:** 3 confirmed True Positives found (Agent *may* continue if targets are easy, but 3 is the "soft stop").
    *   **Exhaustion:** 3 full iterations of the Hunter-Verifier loop completed.
*   **Output:** `confirmed_vulnerabilities.json`

### 3.3 Prioritization Matrix
| Score | Severity | Vulnerability Types |
| :--- | :--- | :--- |
| **90-100** | **Critical** | RCE, Smart Contract Reentrancy, Private Key Leakage, Command Injection, SQLi (Blind/Union), Auth Bypass, Flash Loan/Price Oracle Manipulation |
| **70-89** | **High** | LPE, SSRF, Insecure Deserialization, XXE, Path Traversal/LFI, IDOR (Admin level), XSS (Stored) |
| **40-69** | **Medium** | Reflected XSS, DoS, Subdomain Takeover, CSRF, DDoS, Race Conditions (Web), Gas Limit Griefing |
| **20-39** | **Low** | Open Redirect, CRLF Injection |

### 3.4 Agent 3: MrZeroEnvBuilder (The Environment Architect)
**Goal:** Create a reproducible testing environment (Docker/VM).

*   **Input:** Source code + `confirmed_vulnerabilities.json`.
*   **Logic:**
    1.  Analyze project structure (Makefiles, Dockerfiles, Requirements).
    2.  **Scenario A (Full Build):** Attempt to build the full OS/App.
    3.  **Scenario B (Mock/Harness):** If full build is impossible, extract the vulnerable function/binary and build a minimal harness (e.g., a Docker container running *only* the vulnerable `DHCP6relay` binary with mocked dependencies).
*   **Threshold:** Max **5 build attempts**.
*   **Failure Protocol:**
    *   If 5 attempts fail, generate `manual_setup_guide.md` detailing the complexity and step-by-step manual instructions for the user.
*   **Output:** Running Instance Connection Info (IP/Port/PID) OR Manual Guide.

### 3.5 Agent 4: MrZeroExploitBuilder (The Weaponizer)
**Goal:** Dynamic Analysis and Exploit Generation.

*   **Input:** `confirmed_vulnerabilities.json` + Environment Connection.
*   **Toolkit (Strict):**
    *   `pwntools`
    *   `ROPgadget`
    *   `MCP Servers`: Ghidra / IDA Pro / BinaryNinja
    *   `Metasploit Framework`
    *   `pwndbg-mcp` (Linux Debugging)
    *   `windbg-mcp` (Windows Debugging)
    *   `cheatengine-mcp` (Windows Memory Scanning)
    *   `MSFVenom`
    *   `Frida`
    *   `AFL++` / `WinAFL`
*   **Workflow:**
    1.  **Connect:** Attach debugger/fuzzer to the running environment.
    2.  **PoC:** Generate basic crash or proof (e.g., `alert(1)` or SegFault).
    3.  **Weaponize:** Convert PoC to exploit (e.g., ROP Chain, Reverse Shell).
    4.  **HITL Interaction:** In HITL mode, ask user to validate steps (e.g., "I have triggered a crash. Proceed to ROP chain construction?").
*   **Output:** `exploit.py` / `exploit.c` and `exploit_report.md`.

### 3.6 Agent 5: MrZeroConclusion (The Reporter)
**Goal:** Final documentation.
**Output:** A consolidated **Markdown** report containing:
*   Executive Summary.
*   Attack Surface Map.
*   Vulnerability details (Location, Code Snippet, Severity Score).
*   Environment Setup Guide (or failure log).
*   Exploit Code and Validation Steps.

---

## 4. User Experience (UX)

### 4.1 CLI Commands
```bash
# Start a scan in autonomous mode
mrzero scan ./target_repo --mode yolo

# Start a scan with human supervision
mrzero scan ./target_repo --mode hitl

# Configure tool preferences (e.g., select Ghidra over IDA)
mrzero config tools
```

### 4.2 Tool Selection & Installation
*   **Onboarding:** Upon first run, MrZero checks for installed tools.
*   **Selection:** Users can prioritize tools (e.g., "Use Ghidra for disassembly, but if unavailable, fail").
*   **OS Awareness:**
    *   If OS == Windows: Enable Windbg, WinAFL, CheatEngine. Disable AFL++.
    *   If OS == Linux: Enable GDB, AFL++. Disable WinAFL.

## 5. Constraints & Assumptions
*   **MrZeroVulnHunter** is strictly Static Analysis. It cannot run the code.
*   **MrZeroExploitBuilder** is the only agent authorized to perform Dynamic Analysis.
*   **Performance:** Large repo analysis (Linux Kernel, Chromium) may take significant time; the CLI must handle long-running processes without hanging UI.
*   **Safety:** The tool runs locally. Users are responsible for network isolation when generating RCE exploits.
