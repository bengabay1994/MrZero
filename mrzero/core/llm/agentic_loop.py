"""Tool-calling enabled agent execution loop.

This module provides the agentic loop that allows the LLM to dynamically
call tools during vulnerability analysis. This is more powerful than
pre-running all tools because the LLM can make intelligent decisions
about which tools to use based on what it discovers.

Key Flow:
1. LLM receives initial context (attack surface, code overview)
2. LLM decides which tools to call (e.g., scan specific files, run SAST)
3. Tool results are returned to LLM
4. LLM continues analysis, possibly calling more tools
5. LLM produces final vulnerability report

This implements a ReAct-style (Reasoning + Acting) pattern.
"""

from typing import Any

from mrzero.core.llm.providers import LLMMessage, LLMResponse, BaseLLMProvider
from mrzero.core.llm.tool_calling import ToolCall, ToolRegistry
from mrzero.core.llm.security_tools import create_security_tool_registry


class ToolCallingLoop:
    """Agentic loop that allows LLM to call tools during analysis.

    This implements a multi-turn conversation where the LLM can request
    tools to be executed and receive results back.
    """

    MAX_ITERATIONS = 10  # Prevent infinite loops

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        tool_registry: ToolRegistry | None = None,
        max_iterations: int | None = None,
    ) -> None:
        """Initialize the tool calling loop.

        Args:
            llm_provider: The LLM provider to use.
            tool_registry: Registry of available tools. If None, uses default security tools.
            max_iterations: Maximum number of tool-calling iterations.
        """
        self.llm = llm_provider
        self.registry = tool_registry or create_security_tool_registry()
        self.max_iterations = max_iterations or self.MAX_ITERATIONS

    async def run(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Run the tool-calling loop until completion.

        Args:
            system_prompt: System prompt for the LLM.
            user_prompt: Initial user prompt.
            temperature: LLM temperature.
            max_tokens: Maximum tokens per response.

        Returns:
            Tuple of (final_response, tool_call_history).
        """
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]

        # Get tool definitions in Bedrock format
        tools = self.registry.to_bedrock_format()

        tool_call_history: list[dict[str, Any]] = []
        iterations = 0
        last_response_content = ""

        while iterations < self.max_iterations:
            iterations += 1

            # Call LLM with tools
            response = await self.llm.chat_with_tools(
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            last_response_content = response.content

            # Check if LLM wants to call tools
            if response.tool_calls:
                # Execute all requested tools
                tool_results = []

                for tc_data in response.tool_calls:
                    tool_call = ToolCall(
                        id=tc_data["id"],
                        name=tc_data["name"],
                        arguments=tc_data["arguments"],
                    )

                    # Record tool call
                    tool_call_history.append(
                        {
                            "iteration": iterations,
                            "tool_call": {
                                "id": tool_call.id,
                                "name": tool_call.name,
                                "arguments": tool_call.arguments,
                            },
                        }
                    )

                    # Execute tool
                    result = await self.registry.execute(tool_call)
                    tool_results.append(result)

                    # Record result
                    tool_call_history[-1]["result"] = {
                        "success": result.success,
                        "output_preview": result.output[:500] if result.output else "",
                        "error": result.error,
                    }

                # Add assistant message with tool calls
                messages.append(
                    LLMMessage(
                        role="assistant",
                        content=response.content,
                        tool_calls=response.tool_calls,
                    )
                )

                # Add tool result messages
                for result in tool_results:
                    messages.append(
                        LLMMessage(
                            role="tool",
                            content=result.output if result.success else (result.error or "Error"),
                            tool_call_id=result.tool_call_id,
                        )
                    )

            else:
                # LLM is done, return final response
                return response.content, tool_call_history

        # Max iterations reached
        return last_response_content, tool_call_history


# System prompt for tool-calling vulnerability hunter
TOOL_CALLING_HUNTER_PROMPT = """You are MrZeroVulnHunter, an elite security researcher with access to security analysis tools.

## Your Mission
Analyze the target codebase to identify security vulnerabilities. You have access to tools that help you:
- Scan code for vulnerability patterns (opengrep_scan, gitleaks_scan)
- Search for specific code patterns (search_code)
- Read source files in detail (read_file)
- List files in the codebase (list_files)

## Your Approach
1. Start by understanding the codebase structure (use list_files)
2. Look for high-risk files (auth, database, API handlers)
3. Use SAST tools to get automated findings (opengrep_scan, gitleaks_scan)
4. Search for dangerous patterns (search_code with regex)
5. Read specific files to understand context and verify vulnerabilities
6. Report confirmed vulnerabilities with evidence

## Tool Usage Guidelines
- Use tools strategically - don't scan everything blindly
- Start with targeted searches for known vulnerability patterns
- Read file context before reporting a vulnerability
- Cross-reference findings from multiple sources

## Vulnerability Types to Look For
- **Injection**: SQL, Command, LDAP, XPath
- **XSS**: Stored, Reflected, DOM-based  
- **Authentication**: Weak passwords, session issues
- **Secrets**: Hardcoded credentials, API keys
- **Deserialization**: Pickle, YAML, JSON with type hints
- **SSRF**: URL fetching with user input
- **Path Traversal**: File operations with user input
- **RCE**: eval(), exec(), dynamic imports

## Severity Scoring
| Score | Severity | Examples |
|-------|----------|----------|
| 90-100 | CRITICAL | RCE, SQL Injection, Auth Bypass, Private Key Leak |
| 70-89 | HIGH | SSRF, XXE, Insecure Deserialization, Path Traversal |
| 40-69 | MEDIUM | XSS, CSRF, DoS |
| 20-39 | LOW | Open Redirect, Info Disclosure |

## Output Format
When you've finished your analysis, provide a JSON response:

```json
{
    "vulnerabilities": [
        {
            "title": "<descriptive title>",
            "vuln_type": "<sql_injection|command_injection|xss_stored|...>",
            "severity": "<critical|high|medium|low>",
            "score": <0-100>,
            "file_path": "<relative path>",
            "line_number": <line>,
            "code_snippet": "<vulnerable code>",
            "description": "<detailed description>",
            "attack_scenario": "<how to exploit>",
            "cwe_id": "<CWE-XXX>",
            "confidence": <0.0-1.0>
        }
    ],
    "analysis_summary": {
        "files_analyzed": <number>,
        "tools_used": ["<tool1>", "<tool2>"],
        "high_risk_areas": ["<area1>", "<area2>"]
    }
}
```

Now begin your analysis. Use your tools to thoroughly investigate the codebase."""


# System prompt for tool-calling vulnerability verifier
TOOL_CALLING_VERIFIER_PROMPT = """You are MrZeroVerifier, an elite security researcher specialized in vulnerability verification.

## Your Mission
You receive vulnerability candidates and must determine which are TRUE POSITIVES vs FALSE POSITIVES.
You have access to tools to help you investigate each candidate thoroughly.

## Available Tools
- **read_file**: Read source code files to understand context
- **search_code**: Search for related code patterns (sanitization, validation)
- **list_files**: Explore codebase structure

## Verification Methodology

For each vulnerability candidate, you MUST:

1. **Read the vulnerable code** (use read_file with appropriate line range)
   - Examine the exact code flagged as vulnerable
   - Look at surrounding context (20-30 lines before and after)

2. **Trace the data flow**
   - Identify the SOURCE: Where does the potentially malicious data originate?
   - Identify the SINK: What dangerous operation receives this data?
   - Check for sanitization between source and sink

3. **Search for protections** (use search_code)
   - Look for input validation functions
   - Look for sanitization/escaping functions
   - Check for framework-provided protections

4. **Assess exploitability**
   - Is this code reachable in production?
   - Can an attacker actually control the input?
   - Are there other security controls?

## Decision Criteria

**Mark as CONFIRMED when:**
- User-controlled input flows to dangerous sink WITHOUT sanitization
- Code is reachable in production
- Attacker can realistically exploit this

**Mark as FALSE POSITIVE when:**
- Input is properly sanitized before reaching sink
- Data is NOT user-controlled (hardcoded, internal)
- Framework provides automatic protection
- Code is in tests/examples/documentation
- Vulnerable code path is unreachable

## Output Format

After investigating all candidates, provide your verdict:

```json
{
    "verifications": [
        {
            "vuln_id": "<the vulnerability ID>",
            "verdict": "confirmed" | "false_positive",
            "confidence": <0.0 to 1.0>,
            "source": "<what is the data source>",
            "sink": "<what is the dangerous sink>",
            "sanitization_present": true | false,
            "sanitization_effective": true | false | null,
            "reasoning": "<detailed explanation>",
            "exploitability": "high" | "medium" | "low" | "none",
            "attack_scenario": "<if confirmed, how would attacker exploit>"
        }
    ],
    "summary": {
        "total_analyzed": <number>,
        "confirmed_count": <number>,
        "false_positive_count": <number>
    }
}
```

Be thorough - read the actual code before making decisions!"""


async def run_tool_calling_hunter(
    llm_provider: BaseLLMProvider,
    target_path: str,
    attack_surface_context: str = "",
    max_iterations: int = 10,
) -> tuple[str, list[dict[str, Any]]]:
    """Run the tool-calling vulnerability hunter.

    Args:
        llm_provider: The LLM provider to use.
        target_path: Path to the target codebase.
        attack_surface_context: Optional context from the mapper.
        max_iterations: Maximum tool calling iterations.

    Returns:
        Tuple of (final_response, tool_call_history).
    """
    loop = ToolCallingLoop(
        llm_provider=llm_provider,
        max_iterations=max_iterations,
    )

    user_prompt = f"""## Target Analysis Request

**Target Path**: {target_path}

{f"### Attack Surface Context" + chr(10) + attack_surface_context if attack_surface_context else "No prior attack surface analysis available."}

Please analyze this codebase for security vulnerabilities. Use your tools to:
1. First, list the files to understand the structure
2. Run SAST scans to get initial findings
3. Search for dangerous patterns
4. Read and verify potential vulnerabilities
5. Report your findings in the JSON format specified"""

    return await loop.run(
        system_prompt=TOOL_CALLING_HUNTER_PROMPT,
        user_prompt=user_prompt,
    )


async def run_tool_calling_verifier(
    llm_provider: BaseLLMProvider,
    target_path: str,
    candidates: list[dict[str, Any]],
    max_iterations: int = 8,
) -> tuple[str, list[dict[str, Any]]]:
    """Run the tool-calling vulnerability verifier.

    Args:
        llm_provider: The LLM provider to use.
        target_path: Path to the target codebase.
        candidates: List of vulnerability candidates to verify.
        max_iterations: Maximum tool calling iterations.

    Returns:
        Tuple of (final_response, tool_call_history).
    """
    loop = ToolCallingLoop(
        llm_provider=llm_provider,
        max_iterations=max_iterations,
    )

    # Format candidates for the prompt
    candidate_strs = []
    for i, c in enumerate(candidates, 1):
        candidate_strs.append(f"""### Candidate {i}: {c.get("id", f"VULN-{i}")}
- **Type**: {c.get("vuln_type", "unknown")}
- **File**: {c.get("file_path", "unknown")}
- **Line**: {c.get("line_number", 0)}
- **Severity**: {c.get("severity", "unknown")} (Score: {c.get("score", 50)})
- **Description**: {c.get("description", "No description")[:200]}
- **Code Snippet**: `{c.get("code_snippet", "N/A")[:150]}`
""")

    user_prompt = f"""## Vulnerability Verification Request

**Target Path**: {target_path}

## Candidates to Verify

{chr(10).join(candidate_strs)}

---

## Your Task

For each candidate above:
1. Use `read_file` to examine the vulnerable code and its context
2. Use `search_code` to find related sanitization/validation functions
3. Determine if it's a TRUE POSITIVE or FALSE POSITIVE
4. Provide your verdict in the JSON format specified

Start by reading the code for the first candidate."""

    return await loop.run(
        system_prompt=TOOL_CALLING_VERIFIER_PROMPT,
        user_prompt=user_prompt,
    )
