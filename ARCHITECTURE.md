# LeakLockAI Architecture

> Gemini-powered data-loss prevention agent implemented for the Google Gemini Hackathon.

## High-Level Flow

```
┌────────────────────┐
│  Next.js Frontend  │
│  (frontend/)       │
└─────────┬──────────┘
          │HTTP (REST)
┌─────────▼──────────┐        ┌────────────────────────┐
│ FastAPI Gateway    │        │ Storage / Telemetry    │
│ src/main.py        │        │ storage/ , tests/logs  │
└─────────┬──────────┘        └─────────┬──────────────┘
          │ delegates                   │writes
┌─────────▼──────────┐        ┌──────────▼────────────┐
│ Planner (ReAct)    │        │ Memory/Audit Logger   │
│ src/planner.py     │------->│ src/memory.py         │
└─────────┬──────────┘        └──────────┬────────────┘
          │ orchestrates tools           │persists traces
┌─────────▼──────────┐
│ Executor/Tools     │<─────Gemini API (sanitize, explain)
│ src/executor.py    │
└────────────────────┘
Outcome → REST response (decision, risk score, sanitized text, audit id)
```

## Key Modules

### API Layer (`src/main.py`)

- Exposes `POST /analyze`, `POST /analyze-file`, `GET /stats`, `GET /history`, `GET /health`.
- Validates payloads, handles file uploads/temporary storage, and invokes `planner.plan_and_execute`.
- Formats HTTP responses with telemetry metadata for the frontend.

### Planner (`src/planner.py`)

- Implements the required ReAct cycle:
  1. **Observe:** capture metadata (input length, use-case).
  2. **Act:** secrets detection → PII detection → policy checks.
  3. **Act:** optionally call Gemini sanitizers through the executor.
  4. **Calculate/Explain:** compute risk score, generate Gemini explanation.
  5. **Decide:** emit `BLOCK` or `SANITIZE`.
  6. **Log:** push execution trace to memory for audit/history endpoints.
- Optimized for early exits: secrets immediately block, skipping Gemini calls for deterministic safety.

### Executor & Tooling (`src/executor.py`, `src/extractors.py`)

- **Regex agents:** detect secrets, PII, policy violations, and provide regex fallback sanitization.
- **Gemini integrations:**
  - `sanitize_with_gemini()` → multi-model fallback (`gemini-2.5-flash-lite` … `gemini-pro-latest`).
  - `smart_sanitize_with_gemini()` → context-aware rewriting when PII types are known.
  - `generate_explanation()` → natural-language summary of risk decision.
- **Risk scoring & policy evaluation:** helpers calculate 0–100 scores and cite stored policy references.
- `extractors.py` hosts file parsing helpers (PDF/text) used during `/analyze-file`.

### Memory & Telemetry (`src/memory.py`, `storage/`)

- Every decision is logged with:
  - Audit ID (UUID), timestamp, decision, explanation, execution trace.
  - Sanitized content variants, smart sanitization metadata, Gemini model tags.
- Provides in-memory stats for `/stats` (total decisions, blocked, sanitized, smart-sanitized) and `/history`.
- Backed by JSON files under `storage/` for persistence in the hackathon environment.

### Frontend Integration (`frontend/`)

- Next.js App Router interface consumes `/analyze`, `/stats`, `/history`.
- Visualizes agent pipeline, decisions, telemetry, and audit logs with glass-morphism UI.
- The dotted Three.js background and splash screen share the same Gemini-driven branding.

## Logging, Observability & CI

- Execution traces captured in planner → persisted via memory → surfaced in audit modal + `/history`.
- `TEST.sh` + `.github/workflows/ci.yml` provide reproducible smoke tests (pytest + FastAPI import).
- `.env.example` documents required env vars, especially `GEMINI_API_KEY`, `USE_GEMINI_VISION_FOR_OCR`, etc.

## Deployment Footprint

- Backend: Python 3.11 ready (see `environment.yml` / `Dockerfile`), Uvicorn entrypoint `src.main:app`.
- Frontend: Next.js hosted under `frontend/` with shadcn/Tailwind and `NEXT_PUBLIC_API_BASE_URL`.
