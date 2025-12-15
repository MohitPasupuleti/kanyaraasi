"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    LeakLockAI - Agentic Security System                     ║
║                                                                              ║
║  An intelligent agent that autonomously analyzes content for security       ║
║  risks using Google Gemini API and the ReAct (Reasoning + Acting) pattern.  ║
║                                                                              ║
║  Agentic AI App Hackathon                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
    python main.py                    # Run FastAPI server (default)
    python main.py --cli              # Interactive CLI mode for testing
    python main.py --test             # Run automated test cases

ENDPOINTS:
    POST   /analyze                   # Analyze text content
    POST   /analyze-file              # Analyze uploaded files (multi-modal)
    GET    /health                    # Health check and configuration
    GET    /stats                     # Agent decision statistics
    GET    /history                   # Recent decision history
    GET    /docs                      # Interactive API documentation
"""

import sys
import os
from pathlib import Path

# Add src to path for module imports
sys.path.insert(0, str(Path(__file__).parent))

# FastAPI imports
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import tempfile
import os as os_module

# Agent modules (following hackathon architecture requirements)
from planner import plan_and_execute                # Planner module (ReAct pattern)
from memory import (                                  # Memory module (audit trail)
    init_memory,
    get_decision_statistics,
    retrieve_recent_decisions
)
from executor import test_gemini_connection          # Executor module (tool calls)
from extractors import process_file_securely         # File processing (multi-modal)


# ============================================================================
# INITIALIZATION
# ============================================================================

# Load environment variables (.env file)
load_dotenv()

# Initialize FastAPI application
app = FastAPI(
    title="LeakLockAI - Agentic Content Security System",
    description="Intelligent agent that detects secrets & PII, makes autonomous security decisions",
    version="2.0.0"  # v2.0 with Smart Sanitization
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class AnalyzeRequest(BaseModel):
    """
    Request model for text content analysis.

    Attributes:
        content (str): The text content to analyze for secrets and PII
    """
    content: str


# ============================================================================
# STARTUP EVENT - Initialize Agent System
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """
    Initialize the agent system on application startup.

    This follows the hackathon requirement for agent initialization:
    1. Initialize memory system (SQLite database)
    2. Test Gemini API connection (required hackathon API)
    3. Log startup status for observability
    """
    print("=" * 80)
    print("  LeakLockAI Agentic System Starting...")
    print("=" * 80)

    # Initialize memory module (audit trail for all decisions)
    init_memory()
    print("  [OK] Memory system initialized (SQLite database)")

    # Test Gemini API connection (REQUIRED for hackathon)
    test_result = test_gemini_connection()
    if test_result["success"]:
        print(f"  [OK] Gemini API connected: {test_result['response']}")
    else:
        print(f"  [WARNING] Gemini API warning: {test_result['error']}")
        print("    -> Agent will use fallback regex sanitization")

    print("=" * 80)
    print("  >> Agent ready to analyze content!")
    print("     API Docs: http://localhost:8000/docs")
    print("=" * 80)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """
    **MAIN ENDPOINT:** Analyze text content and make autonomous security decision.

    This demonstrates the core agentic workflow (hackathon requirement):
    1. Receive user input (content to analyze)
    2. Plan sub-tasks using ReAct pattern (planner.py)
    3. Execute tools and call Gemini API (executor.py)
    4. Make autonomous BLOCK or SANITIZE decision
    5. Log decision with full reasoning trace (memory.py)

    **Agent's Decision Process:**
    - Detects secrets (API keys, AWS credentials, private keys) → BLOCK
    - Detects PII (emails, phones, SSNs) → SANITIZE
    - Clean content → SANITIZE (no changes needed)

    Args:
        request (AnalyzeRequest): JSON payload with 'content' field

    Returns:
        dict: Autonomous decision with:
            - decision (str): "BLOCK" or "SANITIZE"
            - risk_score (int): 0-100 risk assessment
            - explanation (str): Human-readable reasoning
            - policy_refs (list): Applied security policies
            - detected_signals (list): What was found (secrets/PII)
            - masked_content (str): Standard sanitization
            - smart_sanitized_content (str): Context-aware rewrite (v2.0 feature)
            - sanitization_comparison (dict): Side-by-side comparison
            - audit_id (str): Unique ID for audit trail
    """
    print(f"\n[REQUEST] Content analysis ({len(request.content)} chars)")

    # Execute agent's autonomous decision-making workflow
    # This calls planner.py which orchestrates the entire ReAct cycle
    result = plan_and_execute(request.content)

    print(f"[DECISION] {result['decision']} (risk: {result['risk_score']}/100)")

    return result


@app.post("/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    use_case: str = Form("general")
):
    """
    **MULTI-MODAL ENDPOINT:** Analyze uploaded files for secrets and PII.

    Supported file types: Images (PNG/JPG), PDFs, Office docs (DOCX/XLSX/PPTX), Text

    **ZERO-LEAK SECURITY ARCHITECTURE** (Key Innovation):
    1. Save file to secure temp location
    2. Extract text LOCALLY (OCR for images, PyPDF2 for PDFs, python-docx for Office)
    3. Run LOCAL regex-based secrets detection (NO external API calls)
    4. If secrets found → BLOCK immediately (Gemini NEVER sees secrets)
    5. Run LOCAL PII detection with regex
    6. Sanitize PII locally FIRST using regex
    7. Only send pre-sanitized content to Gemini for refinement
    8. Clean up temp file

    This architecture GUARANTEES secrets never leave the infrastructure.

    Args:
        file (UploadFile): Uploaded file object
        use_case (str): Context - "debugging", "support", "docs", or "general"

    Returns:
        dict: Same as /analyze endpoint plus:
            - file_info (dict): Filename, size, extension
            - gemini_called (bool): Whether Gemini API was invoked
            - processing_method (str): "local_only", "local_then_gemini", etc.
    """
    print(f"\n[FILE] Upload received: {file.filename}")

    # Extract file extension for type validation
    file_extension = os_module.path.splitext(file.filename)[1].lower()
    print(f"       Type: {file_extension}")

    # Validate against supported file types
    supported_types = ['.png', '.jpg', '.jpeg', '.webp', '.pdf',
                      '.docx', '.xlsx', '.pptx', '.txt']

    if file_extension not in supported_types:
        print(f"[ERROR] Unsupported file type")
        return {
            "decision": "BLOCK",
            "risk_score": 50,
            "explanation": f"Unsupported file type: {file_extension}. "
                          f"Supported: {', '.join(supported_types)}",
            "file_info": {
                "filename": file.filename,
                "type": file_extension,
                "supported": False
            },
            "gemini_called": False,
            "processing_method": "unsupported"
        }

    # Process file securely with temp file cleanup
    temp_file = None
    try:
        # Create temporary file with correct extension
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as temp:
            content = await file.read()
            temp.write(content)
            temp_file = temp.name
            print(f"       Temp: {temp_file}")

        # Process file using ZERO-LEAK architecture (extractors.py)
        print(f"[SECURE] Processing with local-first approach...")
        result = process_file_securely(temp_file, file_extension, use_case)

        print(f"[RESULT] {result['decision']} (risk: {result['risk_score']}/100)")
        print(f"         Gemini called: {result.get('gemini_called', False)}")

        return result

    except Exception as e:
        print(f"[ERROR] Processing failed: {str(e)}")
        return {
            "decision": "BLOCK",
            "risk_score": 50,
            "explanation": f"File processing error: {str(e)}",
            "file_info": {
                "filename": file.filename,
                "type": file_extension
            },
            "gemini_called": False,
            "processing_method": "error"
        }

    finally:
        # Always clean up temporary files (security best practice)
        if temp_file and os_module.path.exists(temp_file):
            try:
                os_module.remove(temp_file)
                print(f"[CLEANUP] Temp file deleted")
            except Exception as e:
                print(f"[WARNING] Cleanup failed: {str(e)}")


@app.get("/health")
async def health():
    """
    Health check endpoint for monitoring and diagnostics.

    Returns:
        dict: System status and configuration
    """
    return {
        "status": "healthy",
        "agent": "LeakLockAI",
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
        "file_upload_enabled": True,
        "supported_file_types": [".png", ".jpg", ".jpeg", ".webp",
                                ".pdf", ".docx", ".xlsx", ".pptx", ".txt"]
    }


@app.get("/stats")
async def stats():
    """
    Get agent decision statistics from memory module.

    Returns:
        dict: Total decisions, block count, sanitize count, etc.
    """
    return get_decision_statistics()


@app.get("/history")
async def history(limit: int = 10):
    """
    Retrieve recent decision history with full reasoning traces.

    Args:
        limit (int): Maximum number of recent decisions to return

    Returns:
        list: Recent decision records with execution traces
    """
    return retrieve_recent_decisions(limit)


# ============================================================================
# CLI MODE - Interactive Testing
# ============================================================================

def run_cli_mode():
    """
    Run agent in interactive command-line interface mode.

    Useful for demonstrations and manual testing.
    """
    print("=" * 80)
    print("  LeakLockAI - Interactive CLI Mode")
    print("=" * 80)
    print("  Enter content to analyze (type 'quit' to exit)\n")

    init_memory()

    while True:
        try:
            print("\n" + "-" * 80)
            content = input("  Content: ").strip()

            if content.lower() in ['quit', 'exit', 'q']:
                print("\n  Goodbye!")
                break

            if not content:
                print("  → Empty input, please try again")
                continue

            # Execute agent workflow
            print("\n  → Agent analyzing...")
            result = plan_and_execute(content)

            # Display results
            print("\n" + "=" * 80)
            print(f"  DECISION:     {result['decision']}")
            print(f"  RISK SCORE:   {result['risk_score']}/100")
            print(f"  EXPLANATION:  {result['explanation']}")
            print(f"  AUDIT ID:     {result['audit_id']}")
            print("=" * 80)

            # Show sanitized version if available
            if result['decision'] == 'SANITIZE' and 'safe_prompt' in result:
                print("\n  SANITIZED OUTPUT:")
                print(f"  {result['safe_prompt']}")

                # Show smart sanitization if available (v2.0 feature)
                if 'smart_sanitized_content' in result:
                    print("\n  SMART SANITIZED:")
                    print(f"  {result['smart_sanitized_content']}")
                print("=" * 80)

        except KeyboardInterrupt:
            print("\n\n  Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n  ERROR: {str(e)}")


# ============================================================================
# TEST MODE - Automated Validation
# ============================================================================

def run_test_mode():
    """
    Run automated test cases to verify agent functionality.

    This validates the core workflows required by hackathon criteria.
    """
    print("=" * 80)
    print("  Running Automated Test Cases")
    print("=" * 80)

    init_memory()

    test_cases = [
        {
            "name": "Clean Content (No Threats)",
            "content": "Hello, can you help me with Python programming?",
            "expected": "SANITIZE"
        },
        {
            "name": "OpenAI API Key Detection",
            "content": "My OpenAI key is sk-1234567890abcdefghijklmnopqrstuvwxyz",
            "expected": "BLOCK"
        },
        {
            "name": "Email PII Detection",
            "content": "Contact me at john.doe@example.com for more information",
            "expected": "SANITIZE"
        },
        {
            "name": "AWS Credentials Detection",
            "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "expected": "BLOCK"
        }
    ]

    passed = 0
    failed = 0

    for test in test_cases:
        print(f"\n  {test['name']}")
        print(f"    Input: {test['content'][:60]}...")

        result = plan_and_execute(test['content'])

        if result['decision'] == test['expected']:
            print(f"    [PASS] Decision: {result['decision']}")
            passed += 1
        else:
            print(f"    [FAIL] Expected: {test['expected']}, Got: {result['decision']}")
            failed += 1

    print("\n" + "=" * 80)
    print(f"  Results: {passed} PASSED, {failed} FAILED")
    print("=" * 80)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    # Parse command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--cli":
            run_cli_mode()
        elif sys.argv[1] == "--test":
            run_test_mode()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("\nUsage:")
            print("  python main.py          # Run FastAPI server")
            print("  python main.py --cli    # Interactive CLI mode")
            print("  python main.py --test   # Run test cases")
    else:
        # Run FastAPI server (default mode)
        print("\n>> Starting LeakLockAI Agentic System...")
        print("   API: http://localhost:8000")
        print("   Docs: http://localhost:8000/docs\n")
        uvicorn.run(app, host="0.0.0.0", port=8000)
