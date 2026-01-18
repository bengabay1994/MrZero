---
stepsCompleted:
  - step-01-validate-prerequisites
inputDocuments:
  - _bmad-output/implementation-artifacts/prd-mrzero.md
  - _bmad-output/implementation-artifacts/architecture-mrzero.md
---

# MrZero - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for MrZero, decomposing the requirements from the PRD and Architecture requirements into implementable stories.

## Requirements Inventory

### Functional Requirements

FR1: CLI Interface - Provide a Python-based CLI using Typer or Click with Rich for TUI.
FR2: Orchestration - Use LangGraph for stateful, cyclical agent workflows.
FR3: Communication - Use Model Context Protocol (MCP) for tool interactions.
FR4: Data Persistence - Store session state, tool output cache, and findings in SQLite.
FR5: Code Understanding - Use VectorDB (Chroma/FAISS) for semantic code search (RAG).
FR6: Agent Mapper - Scan target directory to identify languages, frameworks, and map endpoints/data flows using specified tools (Linguist, App Inspector, Joern, CodeQL). Output `attack_surface_map.json`.
FR7: Agent Hunter - Generate vulnerability candidates using SAST tools (CodeQL, Semgrep, etc.) and assign priority scores.
FR8: Agent Verifier - Filter candidates using Taint Analysis and Dead Code Checks to confirm TPs or mark FPs.
FR9: Feedback Loop - Implement a feedback loop between Hunter and Verifier with exit conditions (3 TPs or 3 iterations).
FR10: Agent EnvBuilder - Analyze project structure and attempt to build a reproducible environment (Full or Mock) using Docker/VM. Max 5 attempts. Fallback to manual guide.
FR11: Agent ExploitBuilder - Connect to environment, perform dynamic analysis (Fuzzing/Debugging), generate PoC, and weaponize exploits.
FR12: Agent Conclusion - Generate a consolidated Markdown report with summary, map, vulnerabilities, setup guide, and exploit details.
FR13: Modes - Support 'YOLO' (Autonomous) and 'HITL' (Human-in-the-Loop) modes.
FR14: HITL Interaction - Pause for user validation at critical steps (e.g., exploit generation) in HITL mode.
FR15: CLI Commands - Support `scan` and `config` commands.
FR16: Tool Management - Check for installed tools, allow user prioritization, and handle OS-specific tool availability (Linux vs Windows).

### NonFunctional Requirements

NFR1: Resume Capability - System must be able to resume sessions from SQLite state after interruption.
NFR2: Efficiency - System must cache tool outputs to prevent redundant execution.
NFR3: Performance - CLI must handle long-running processes without hanging the UI.
NFR4: Safety - All analysis must run locally; exploits must be sandboxed or network isolated.
NFR5: Extensibility - Architecture must be LLM-agnostic via MCP.
NFR6: OS Compatibility - System must adapt tool usage based on the host OS (Linux vs Windows).

### Additional Requirements

- Architecture: Use `LangGraph` for orchestration.
- Architecture: Implement dual-database strategy (SQLite + VectorDB).
- Architecture: Wrap all external tools as MCP servers.
- Architecture: Follow specific directory structure (cli, core, agents, tools).
- Architecture: EnvBuilder must attempt to containerize targets (Docker).
- Architecture: Tool runs with user privileges, root only if requested.

### FR Coverage Map

{{requirements_coverage_map}}

## Epic List

{{epics_list}}

<!-- Repeat for each epic in epics_list (N = 1, 2, 3...) -->

## Epic {{N}}: {{epic_title_N}}

{{epic_goal_N}}

<!-- Repeat for each story (M = 1, 2, 3...) within epic N -->

### Story {{N}}.{{M}}: {{story_title_N_M}}

As a {{user_type}},
I want {{capability}},
So that {{value_benefit}}.

**Acceptance Criteria:**

<!-- for each AC on this story -->

**Given** {{precondition}}
**When** {{action}}
**Then** {{expected_outcome}}
**And** {{additional_criteria}}

<!-- End story repeat -->
