# LeakLockAI – Technical Explanation

## 1. Planning & Reasoning Strategy
- **Pattern:** Dynamic ReAct loop implemented in `src/planner.py`. Each request walks through Observe → Act → Decide → Log, emitting execution trace entries for observability.
- **Task decomposition:**
  1. **Detect secrets** (always first). Finds critical credentials and immediately blocks without touching Gemini.
  2. **Detect PII** when secrets are absent; records the exact PII types (email, SSN, phone, etc.).
  3. **Evaluate policy** to determine whether sanitization is allowed for the incoming use case.
  4. **Sanitize** (standard + smart) only when policies permit and PII exists.
  5. **Score risk** and **generate explanation** with Gemini before logging the decision.
- **Optimization:** Early exit ensures the agent stays fast and deterministic (critical for hackathon judging).

## 2. Tooling & Gemini Integration
- **Regex/Rule Engines:** Secrets and PII detection rely on curated regex patterns (see `detect_secrets`, `detect_pii`). Regex sanitization also serves as the LLM fallback.
- **Google Gemini API (required integration):**
  - `sanitize_with_gemini()` masks sensitive spans while keeping semantics. Multi-model fallback ensures reliability under rate limits.
  - `smart_sanitize_with_gemini()` rewrites text with contextual awareness when PII is detected (v2.0 enhancement).
  - `generate_explanation()` summarizes why content was blocked/sanitized so users understand each decision.
- **Other helpers:** `evaluate_policy`, `calculate_risk_score`, and `extractors.py` for file uploads. All tool invocations originate from the planner, preserving a single flow of control.

## 3. Memory & Telemetry Usage
- Implemented in `src/memory.py`. Every decision is appended to an in-memory + JSON-backed list that powers:
  - `/history` – returns the last N decisions, including execution traces and sanitized variants.
  - `/stats` – aggregates totals, blocked count, sanitization count, and smart-sanitization rate for the telemetry widgets.
- Each log entry stores:
  - Audit ID, timestamp, decision, risk score.
  - Execution trace steps, policy references.
  - `safe_prompt` (Gemini sanitized text) and `smart_sanitized_content` when available.
  - Metadata on which Gemini model was used or whether regex fallback occurred.
- This data drives the frontend’s audit modal and telemetry filters without re-querying Gemini.

## 4. Limitations & Risks
- **LLM dependence:** Sanitization/explanations rely on Gemini quotas; if the API is unavailable, regex fallback runs but may be less accurate.
- **Regex false positives/negatives:** While regex patterns cover common secret/PII formats, they can miss obfuscated content or flag benign text.
- **OCR & PDFs:** File uploads require PyPDF2 and optional Tesseract/OCR; complex documents may lose formatting or contain unreadable images.
- **Latency vs. accuracy trade-off:** Smart sanitization is skipped when policies disallow it or when PII is absent, prioritizing responsiveness over exhaustive rewriting.
- **Memory persistence:** Current JSON-based storage fits MVP expectations but should be replaced with a database for production workloads.

Despite these limitations, the agent satisfies the hackathon’s architectural requirements: clear planning, tool orchestration, Gemini integration, and transparent memory/logging.
