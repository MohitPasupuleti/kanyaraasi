"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        EXECUTOR MODULE (executor.py)                         ║
║                                                                              ║
║  Tool Execution & Google Gemini API Integration (REQUIRED)                  ║
║  7 Specialized Agents for Threat Detection & Content Sanitization           ║
╚══════════════════════════════════════════════════════════════════════════════╝

HACKATHON REQUIREMENT FULFILLMENT:
✓ Call tools and external APIs (Google Gemini - REQUIRED)
✓ Execute threat detection tools (regex-based agents)
✓ Implement fallback mechanisms for reliability
✓ Multi-model Gemini integration (4 models with fallback)

7 SPECIALIZED AGENTS:
1. Secrets Detection Agent     - Regex patterns for 9+ secret types
2. PII Detection Agent          - Email, phone, SSN detection
3. Policy Evaluation Agent      - Apply security policies
4. Risk Scoring Agent           - Calculate 0-100 risk scores
5. Sanitization Agent           - Gemini-powered masking
6. Smart Sanitization Agent     - Context-aware natural language rewriting (v2.0)
7. Explanation Agent            - LLM-powered decision reasoning

GEMINI API USAGE (Multiple Integration Points):
- sanitize_with_gemini()         : Standard PII masking
- smart_sanitize_with_gemini()   : Context-aware rewriting (INNOVATIVE)
- generate_explanation()         : Decision reasoning
- Multi-model fallback           : gemini-2.5-flash → 2.0-flash → flash-latest → pro-latest
"""

import os
import re
import google.generativeai as genai


def detect_secrets(text):
    """
    Execute secret detection tool using regex patterns.

    This tool scans for various types of sensitive information including
    API keys, tokens, credentials, and private keys.

    Args:
        text (str): The text to analyze for secrets

    Returns:
        dict: Detection result with 'found' boolean and pattern details
    """
    patterns = {
        "OpenAI API Key": r"sk-[a-zA-Z0-9]{20,}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        "Generic API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}",
        "Bearer Token": r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
        "Slack Token": r"xox[baprs]-[a-zA-Z0-9]{10,}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Password in URL": r"://([^:]+):([^@]+)@",
    }

    for pattern_name, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            matched_text = match.group(0)
            return {
                "found": True,
                "pattern": pattern_name,
                "matched_value": matched_text[:20] + "..." if len(matched_text) > 20 else matched_text
            }

    return {"found": False, "pattern": None}


def regex_sanitize(text):
    """
    Fallback sanitization using regex patterns.

    Used when Gemini API is unavailable or fails.

    Args:
        text (str): The text to sanitize

    Returns:
        str: Sanitized text with sensitive data masked
    """
    patterns = [
        (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REDACTED]'),
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]'),
        (r'(social\s+sec\w*\s+number\s+(?:is\s+)?)\S+', r'\1[SSN_REDACTED]'),
        (r'password\s*[=:]\s*["\']?([^"\'\s]+)["\']?', 'password=[REDACTED]'),
        (r'passwd\s*[=:]\s*["\']?([^"\'\s]+)["\']?', 'passwd=[REDACTED]'),
        (r'pwd\s*[=:]\s*["\']?([^"\'\s]+)["\']?', 'pwd=[REDACTED]'),
        (r'token\s*[=:]\s*["\']?([^"\'\s]+)["\']?', 'token=[REDACTED]'),
        (r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*', 'Bearer [TOKEN_REDACTED]'),
        (r'://([^:]+):([^@]+)@', '://[USER]:[PASSWORD]@'),
    ]

    sanitized = text
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized


def sanitize_with_gemini(text):
    """
    Execute Gemini API call for intelligent content sanitization.

    This is the core LLM integration for the hackathon. It uses Google's
    Gemini API to intelligently identify and mask sensitive information
    while preserving the original intent of the content.

    Multi-model fallback strategy:
    1. gemini-2.5-flash (fastest, latest)
    2. gemini-2.0-flash (stable)
    3. gemini-flash-latest (generic latest)
    4. gemini-pro-latest (most capable)
    5. Regex fallback (if all fail)

    Args:
        text (str): The text to sanitize

    Returns:
        dict: Sanitization result with 'sanitized_text', 'used_llm', and 'model_used'
    """
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        print("[EXECUTOR] No GEMINI_API_KEY found - using regex fallback")
        sanitized = regex_sanitize(text)
        return {
            "sanitized_text": sanitized,
            "used_llm": False,
            "model_used": "regex_fallback"
        }

    # Configure Gemini API
    genai.configure(api_key=api_key)

    # Try multiple models in order of preference (prioritize models with available quota)
    models_to_try = [
        'gemini-2.5-flash-lite',      # Has quota available
        'gemini-1.5-flash',            # Backup option
        'gemini-1.5-flash-8b',         # Another backup
        'gemini-flash-latest',         # Fallback
        'gemini-2.5-flash',            # May be rate limited
        'gemini-2.0-flash',            # May be rate limited
        'gemini-pro-latest'            # Last resort
    ]

    for model_name in models_to_try:
        try:
            model = genai.GenerativeModel(model_name)

            # Craft the sanitization prompt
            prompt = f"""You are a security-aware assistant.

Your task:
Rewrite the input text to REMOVE or MASK any sensitive information
such as API keys, secrets, tokens, passwords, private keys, emails,
phone numbers, or personally identifiable information (PII).

Rules:
- Preserve the original intent and meaning
- Replace sensitive data with placeholders like [REDACTED] or [EMAIL_MASKED]
- Do NOT add explanations or warnings
- Do NOT mention security policies
- Do NOT format the output with markdown
- Return ONLY the rewritten text

Input:
{text}"""

            # Call Gemini API
            response = model.generate_content(prompt)
            sanitized = regex_sanitize(response.text.strip())

            print(f"[EXECUTOR] Successfully used Gemini model: {model_name}")
            return {
                "sanitized_text": sanitized,
                "used_llm": True,
                "model_used": model_name
            }

        except Exception as e:
            print(f"[EXECUTOR] Model {model_name} failed: {str(e)[:100]}")
            continue

    # All Gemini models failed - use regex fallback
    print("[EXECUTOR] All Gemini models failed - using regex fallback")
    sanitized = regex_sanitize(text)
    return {
        "sanitized_text": sanitized,
        "used_llm": False,
        "model_used": "regex_fallback"
    }


def test_gemini_connection():
    """
    Test utility to verify Gemini API connectivity.

    Returns:
        dict: Connection test result
    """
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return {
            "success": False,
            "error": "GEMINI_API_KEY not found in environment"
        }

    try:
        genai.configure(api_key=api_key)
        # Use model with available quota
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content("Say 'Hello from Gemini!'")

        return {
            "success": True,
            "message": "Gemini API connection successful",
            "response": response.text.strip()
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def detect_pii(text):
    """
    AGENT 1: PII Detection Agent (Regex-based, NO LLM)

    Detects personally identifiable information including:
    - Email addresses
    - Phone numbers (US format)
    - Social Security Numbers (SSN)

    This agent is purely regex-based for speed and reliability.

    Args:
        text (str): The text to analyze for PII

    Returns:
        dict: Detection result with 'found' boolean and list of 'types'
    """
    pii_patterns = {
        "email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone": r'\b(\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    }

    found_types = []

    for pii_type, pattern in pii_patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            found_types.append(pii_type)

    lower_text = text.lower()
    if "social sec" in lower_text and "number" in lower_text:
        found_types.append("ssn_keyword")

    return {
        "found": len(found_types) > 0,
        "types": found_types
    }


def evaluate_policy(use_case, secrets_found, pii_found, pii_types):
    """
    AGENT 2: Policy Evaluation Agent

    Evaluates company security policies based on:
    - Use case context (debugging, support, docs, general)
    - Signals from secrets and PII detection agents

    Policy rules:
    - Secrets → ALWAYS block (AI-SEC-01)
    - PII in debugging/support → Allow with sanitization (AI-PII-02)
    - PII in docs/general → Allow with sanitization (AI-PII-03)
    - No sensitive data → Allow (AI-SAFE-04)

    Args:
        use_case (str): The context of the request
        secrets_found (bool): Whether secrets were detected
        pii_found (bool): Whether PII was detected
        pii_types (list): Types of PII found

    Returns:
        dict: Policy evaluation with 'allow_sanitization' and 'policy_refs'
    """
    policy_refs = []
    allow_sanitization = True

    # Rule 1: Secrets must never leave company systems
    if secrets_found:
        policy_refs.append({
            "id": "AI-SEC-01",
            "summary": "Secrets must not leave company systems"
        })
        allow_sanitization = False  # Block, don't sanitize

    # Rule 2: PII can be used with sanitization
    elif pii_found:
        if use_case in ["debugging", "support"]:
            policy_refs.append({
                "id": "AI-PII-02",
                "summary": "PII in debugging/support requires sanitization"
            })
        else:
            policy_refs.append({
                "id": "AI-PII-03",
                "summary": "PII in general use requires sanitization"
            })
        allow_sanitization = True

    # Rule 3: No sensitive data detected
    else:
        policy_refs.append({
            "id": "AI-SAFE-04",
            "summary": "Content appears safe for AI processing"
        })
        allow_sanitization = True

    return {
        "allow_sanitization": allow_sanitization,
        "policy_refs": policy_refs
    }


def calculate_risk_score(secrets_found, pii_found, pii_types, sanitization_applied):
    """
    AGENT 3: Risk Scoring Agent

    Calculates a risk score (0-100) based on aggregated signals:
    - Secrets detection: +95 (critical)
    - PII detection: +30 per type (email, phone, SSN)
    - Sanitization applied: -50 (mitigation)

    Score ranges:
    - 0-20: Low risk (safe)
    - 21-50: Medium risk (needs sanitization)
    - 51-100: High risk (block or heavily sanitize)

    Args:
        secrets_found (bool): Whether secrets were detected
        pii_found (bool): Whether PII was detected
        pii_types (list): Types of PII found
        sanitization_applied (bool): Whether content was sanitized

    Returns:
        int: Risk score from 0 to 100
    """
    score = 0

    # Critical: Secrets found
    if secrets_found:
        score += 95

    # High: PII found (30 points per type)
    if pii_found:
        score += len(pii_types) * 30

    # Mitigation: Sanitization applied
    if sanitization_applied:
        score -= 50

    # Ensure score stays within bounds
    score = max(0, min(100, score))

    return score


def smart_sanitize_with_gemini(text, pii_types):
    """
    Context-aware intelligent sanitization using Gemini.

    Instead of just masking PII with [EMAIL_REDACTED], this function uses
    Gemini to intelligently rewrite the text with natural language equivalents
    that preserve meaning while removing all sensitive data.

    Examples:
    - "Email sarah@acme.com" -> "Email the sales contact"
    - "John Smith (SSN: 123-45-6789)" -> "Customer (identifier redacted)"
    - "Call me at 555-0123" -> "You can reach them by phone"

    Args:
        text (str): The text to sanitize
        pii_types (list): Types of PII detected (email, phone, ssn)

    Returns:
        dict: Result with 'smart_sanitized_text', 'used_llm', and 'model_used'
    """
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        print("[EXECUTOR] No GEMINI_API_KEY found - cannot perform smart sanitization")
        return {
            "smart_sanitized_text": text,
            "used_llm": False,
            "model_used": "none",
            "error": "API key not configured"
        }

    # Configure Gemini API
    genai.configure(api_key=api_key)

    # Try multiple models in order of preference (prioritize models with available quota)
    models_to_try = [
        'gemini-2.5-flash-lite',      # Has quota available
        'gemini-1.5-flash',            # Backup option
        'gemini-1.5-flash-8b',         # Another backup
        'gemini-flash-latest',         # Fallback
        'gemini-2.5-flash',            # May be rate limited
        'gemini-2.0-flash',            # May be rate limited
        'gemini-pro-latest'            # Last resort
    ]

    pii_description = ', '.join(pii_types) if pii_types else 'sensitive data'

    for model_name in models_to_try:
        try:
            model = genai.GenerativeModel(model_name)

            # Craft the context-aware sanitization prompt
            prompt = f"""You are a privacy-preserving text rewriter.

Your task:
Rewrite the input text to REMOVE all personally identifiable information (PII) while preserving the meaning and making the text natural and useful.

PII types detected: {pii_description}

IMPORTANT RULES:
1. Replace PII with NATURAL LANGUAGE equivalents, NOT placeholders like [REDACTED]
2. Preserve the original meaning and context
3. Make the text flow naturally as if it was written that way originally
4. Use generic references (e.g., "the contact", "the customer", "the sales representative")
5. Return ONLY the rewritten text, NO explanations or notes
6. Do NOT use markdown formatting
7. Keep the same tone and style as the original

Examples of good transformations:
- "Email sarah.johnson@acme.com" → "Email the sales contact"
- "Contact John at 555-0123" → "Contact them by phone"
- "John Smith (SSN: 123-45-6789)" → "Customer (identifier redacted)"
- "Call me at 555-999-8888 or email test@example.com" → "You can reach them by phone or email"

Input text:
{text}

Rewritten text:"""

            # Call Gemini API
            response = model.generate_content(prompt)
            smart_sanitized = response.text.strip()

            # Remove any markdown or formatting
            smart_sanitized = re.sub(r'```.*?```', '', smart_sanitized, flags=re.DOTALL)
            smart_sanitized = re.sub(r'[*_]', '', smart_sanitized)
            smart_sanitized = smart_sanitized.strip()

            print(f"[EXECUTOR] Smart sanitization successful using: {model_name}")
            return {
                "smart_sanitized_text": smart_sanitized,
                "used_llm": True,
                "model_used": model_name
            }

        except Exception as e:
            print(f"[EXECUTOR] Model {model_name} failed for smart sanitization: {str(e)[:100]}")
            continue

    # All Gemini models failed - return original text
    print("[EXECUTOR] All Gemini models failed for smart sanitization")
    return {
        "smart_sanitized_text": text,
        "used_llm": False,
        "model_used": "failed",
        "error": "All models failed"
    }


def generate_explanation(decision, risk_score, secrets_found, pii_found, pii_types, policy_refs):
    """
    AGENT 4: Decision Explanation Agent (LLM-powered)

    Generates a plain-English explanation of why a decision was made.
    Uses Gemini to create clear, concise explanations.

    Rules:
    - 1-2 sentences maximum
    - Plain English, no markdown or bullets
    - Explains the "why" not the "what"
    - Called only at the very end

    Args:
        decision (str): The final decision (BLOCK or SANITIZE)
        risk_score (int): The calculated risk score
        secrets_found (bool): Whether secrets were detected
        pii_found (bool): Whether PII was detected
        pii_types (list): Types of PII found
        policy_refs (list): Applied policy references

    Returns:
        str: Plain-English explanation
    """
    api_key = os.getenv("GEMINI_API_KEY")

    # Fallback to simple explanation if no API key
    if not api_key:
        if secrets_found:
            return f"Content blocked because it contains secrets that could compromise security."
        elif pii_found:
            return f"Content sanitized to remove {', '.join(pii_types)} before AI processing."
        else:
            return "Content appears safe and can be processed without modifications."

    try:
        genai.configure(api_key=api_key)

        # Try models in order
        models_to_try = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-flash-latest']

        for model_name in models_to_try:
            try:
                model = genai.GenerativeModel(model_name)

                # Craft explanation prompt
                prompt = f"""Generate a 1-2 sentence plain-English explanation for this security decision.

Decision: {decision}
Risk Score: {risk_score}/100
Secrets Found: {secrets_found}
PII Found: {pii_found}
PII Types: {', '.join(pii_types) if pii_types else 'none'}
Policies: {', '.join([p['id'] for p in policy_refs])}

Rules:
- Write in plain English
- NO markdown, bullets, or formatting
- Explain WHY this decision was made
- Keep it to 1-2 sentences maximum
- Focus on the user's benefit

Output only the explanation text:"""

                response = model.generate_content(prompt)
                explanation = response.text.strip()

                # Remove any markdown or formatting that might have slipped through
                explanation = re.sub(r'[*_#\-\[\]]', '', explanation)

                return explanation

            except Exception:
                continue

        # Fallback if all models fail
        if secrets_found:
            return f"Content blocked because it contains secrets that could compromise security."
        elif pii_found:
            return f"Content sanitized to remove {', '.join(pii_types)} before AI processing."
        else:
            return "Content appears safe and can be processed without modifications."

    except Exception:
        # Ultimate fallback
        if secrets_found:
            return "Content blocked due to security risks."
        elif pii_found:
            return "Content sanitized for safety."
        else:
            return "Content is safe to process."
