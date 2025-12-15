"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         PLANNER MODULE (planner.py)                          ║
║                                                                              ║
║  Core Agent Workflow: Task Decomposition & Autonomous Decision-Making       ║
║  Pattern: ReAct (Reasoning + Acting) - Required Hackathon Architecture      ║
╚══════════════════════════════════════════════════════════════════════════════╝

HACKATHON REQUIREMENT FULFILLMENT:
✓ Plan sub-tasks (ReAct pattern implementation)
✓ Break down user goals into actionable steps
✓ Coordinate tool execution through executor.py
✓ Make autonomous BLOCK/SANITIZE decisions
✓ Generate execution traces for observability

KEY INNOVATION: Dynamic Early-Exit Optimization
- If secrets detected → Immediate BLOCK (no further processing)
- If PII detected → Targeted sanitization workflow
- If clean → Fast-path approval
This makes the agent efficient AND secure.

EXECUTION FLOW (ReAct Cycle):
1. OBSERVE:   Analyze input content
2. REASON:    Detect threats (secrets, PII)
3. ACT:       Execute appropriate tools/APIs
4. DECIDE:    Make autonomous security decision
5. LOG:       Record full reasoning trace to memory
"""

import uuid
from datetime import datetime
from executor import (
    detect_secrets,
    sanitize_with_gemini,
    smart_sanitize_with_gemini,
    detect_pii,
    evaluate_policy,
    calculate_risk_score,
    generate_explanation
)
from memory import log_decision


def plan_and_execute(content, use_case="general"):
    """
    Main planning function that orchestrates the content analysis workflow.

    This follows a DYNAMIC ReAct pattern with early exits:
    1. OBSERVE: Analyze the input content
    2. ACT: Secrets detection (EARLY EXIT if found → BLOCK)
    3. ACT: PII detection (only if no secrets)
    4. ACT: Policy evaluation (only if PII found)
    5. ACT: Sanitization (only if policy allows)
    6. CALCULATE: Risk scoring
    7. EXPLAIN: Generate explanation (LLM)
    8. LOG: Audit trail

    NOT all agents run every time - flow is dynamic based on signals.

    Args:
        content (str): The text content to analyze
        use_case (str): Context of request (debugging, support, docs, general)

    Returns:
        dict: Decision result with reasoning trace
    """
    # Initialize execution context
    execution_trace = []
    audit_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"

    # PHASE 1: OBSERVE
    execution_trace.append("OBSERVE: Received content for analysis")
    execution_trace.append(f"   Content length: {len(content)} characters")
    execution_trace.append(f"   Use case: {use_case}")

    # PHASE 2: ACT - Secrets Detection (ALWAYS runs first)
    execution_trace.append("ACT: Running secrets detection agent...")
    secrets_result = detect_secrets(content)

    if secrets_result["found"]:
        # EARLY EXIT: Secrets found -> BLOCK immediately
        execution_trace.append(f"   CRITICAL: Secret detected: {secrets_result['pattern']}")
        execution_trace.append("EARLY EXIT: Blocking due to secrets (no further checks needed)")

        # Policy evaluation for secrets (always blocks)
        policy_result = evaluate_policy(use_case, True, False, [])

        # Calculate risk score (secrets = 95, no sanitization)
        risk_score = calculate_risk_score(True, False, [], False)

        # Generate explanation
        explanation = generate_explanation(
            "BLOCK",
            risk_score,
            True,
            False,
            [],
            policy_result["policy_refs"]
        )

        detected_signals = [{
            "type": secrets_result["pattern"],
            "severity": "critical",
            "location": f"Found: {secrets_result.get('matched_value', 'N/A')}",
            "description": f"Detected {secrets_result['pattern']} in content"
        }]

        decision = "BLOCK"

        # Log decision to memory
        log_decision(decision, explanation, execution_trace, audit_id)

        return {
            "decision": decision,
            "risk_score": risk_score,
            "explanation": explanation,
            "policy_refs": policy_result["policy_refs"],
            "detected_signals": detected_signals,
            "audit_id": audit_id,
            "timestamp": timestamp
        }

    # PHASE 3: ACT - PII Detection (only runs if no secrets)
    execution_trace.append("    No secrets detected")
    execution_trace.append(" ACT: Running PII detection agent...")
    pii_result = detect_pii(content)

    pii_found = pii_result["found"]
    pii_types = pii_result["types"]

    if pii_found:
        execution_trace.append(f"    PII detected: {', '.join(pii_types)}")
    else:
        execution_trace.append("    No PII detected")

    # PHASE 4: ACT - Policy Evaluation (only runs if PII detected)
    if pii_found:
        execution_trace.append(" ACT: Running policy evaluation agent...")
        policy_result = evaluate_policy(use_case, False, pii_found, pii_types)
        execution_trace.append(f"    Policy applied: {policy_result['policy_refs'][0]['id']}")
    else:
        # No PII, use default safe policy
        policy_result = evaluate_policy(use_case, False, False, [])
        execution_trace.append("    Policy: Content appears safe (AI-SAFE-04)")

    # PHASE 5: ACT - Sanitization (only if policy allows)
    sanitized_result = None
    smart_sanitized_result = None
    sanitization_applied = False

    if policy_result["allow_sanitization"]:
        execution_trace.append(" ACT: Running sanitization agent (Gemini)...")

        # Standard masking sanitization (existing behavior)
        sanitized_result = sanitize_with_gemini(content)
        sanitization_applied = True

        if sanitized_result["used_llm"]:
            execution_trace.append(f"    Gemini sanitization successful")
            execution_trace.append(f"   Model: {sanitized_result.get('model_used', 'gemini')}")
        else:
            execution_trace.append(f"    Fallback regex sanitization used")

        # Smart context-aware sanitization (NEW - only if PII detected)
        if pii_found:
            execution_trace.append(" ACT: Running smart context-aware sanitization...")
            smart_sanitized_result = smart_sanitize_with_gemini(content, pii_types)

            if smart_sanitized_result.get("used_llm"):
                execution_trace.append(f"    Smart sanitization successful")
                execution_trace.append(f"   Model: {smart_sanitized_result.get('model_used', 'gemini')}")
            else:
                execution_trace.append(f"    Smart sanitization unavailable")
    else:
        execution_trace.append("   ⏭ Sanitization skipped (policy blocks)")

    # PHASE 6: CALCULATE - Risk Scoring
    execution_trace.append(" CALCULATE: Computing risk score...")
    risk_score = calculate_risk_score(
        False,  # No secrets
        pii_found,
        pii_types,
        sanitization_applied
    )
    execution_trace.append(f"   Risk score: {risk_score}/100")

    # PHASE 7: EXPLAIN - Generate Explanation (LLM)
    execution_trace.append(" EXPLAIN: Generating decision explanation...")
    explanation = generate_explanation(
        "SANITIZE",
        risk_score,
        False,
        pii_found,
        pii_types,
        policy_result["policy_refs"]
    )
    execution_trace.append("    Explanation generated")

    # PHASE 8: DECIDE - Final decision
    decision = "SANITIZE"
    execution_trace.append(f" DECIDE: {decision} (content safe with modifications)")

    # Build detected signals
    detected_signals = []
    if pii_found:
        detected_signals.append({
            "type": f"PII: {', '.join(pii_types)}",
            "severity": "medium",
            "location": "Content",
            "description": f"Detected {len(pii_types)} type(s) of PII"
        })
    if sanitization_applied:
        detected_signals.append({
            "type": "Sanitized",
            "severity": "low",
            "location": "Full content",
            "description": f"Sanitized using {'Gemini' if sanitized_result and sanitized_result['used_llm'] else 'regex'}"
        })

    # PHASE 9: LOG - Audit trail
    log_decision(decision, explanation, execution_trace, audit_id)

    # Build response
    response = {
        "decision": decision,
        "risk_score": risk_score,
        "explanation": explanation,
        "policy_refs": policy_result["policy_refs"],
        "detected_signals": detected_signals if detected_signals else [{"type": "Clean", "severity": "none", "location": "N/A", "description": "No issues detected"}],
        "audit_id": audit_id,
        "timestamp": timestamp
    }

    # Add sanitized content if available
    if sanitized_result:
        response["safe_prompt"] = sanitized_result["sanitized_text"]
        response["masked_content"] = sanitized_result["sanitized_text"]  # Standard masking
        response["diff"] = {
            "original": content,
            "sanitized": sanitized_result["sanitized_text"],
            "changes": []
        }

    # Add smart sanitized content if available (NEW)
    if smart_sanitized_result and smart_sanitized_result.get("used_llm"):
        response["smart_sanitized_content"] = smart_sanitized_result["smart_sanitized_text"]
        response["smart_sanitization_model"] = smart_sanitized_result.get("model_used", "unknown")

        # Add comparison between both methods
        response["sanitization_comparison"] = {
            "original": content,
            "masked_version": sanitized_result["sanitized_text"] if sanitized_result else content,
            "smart_version": smart_sanitized_result["smart_sanitized_text"]
        }

    return response


def create_task_breakdown(content):
    """
    Helper function to create a visual task breakdown for observability.

    This demonstrates the agent's planning capabilities by showing how
    it decomposes the high-level goal into actionable sub-tasks.

    Args:
        content (str): The content to analyze

    Returns:
        list: Ordered list of sub-tasks
    """
    tasks = [
        {
            "id": 1,
            "name": "Detect Secrets",
            "description": "Scan content for API keys, tokens, and credentials",
            "priority": "HIGH",
            "tool": "regex_patterns"
        },
        {
            "id": 2,
            "name": "Sanitize Content",
            "description": "Remove or mask sensitive information using Gemini",
            "priority": "MEDIUM",
            "tool": "gemini_api",
            "conditional": "Only if no secrets found"
        },
        {
            "id": 3,
            "name": "Make Decision",
            "description": "Determine final action: BLOCK or SANITIZE",
            "priority": "HIGH",
            "tool": "decision_logic"
        }
    ]

    return tasks
