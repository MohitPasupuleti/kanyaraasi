# LeakLockAI – Agentic AI Hackathon Submission

> An intelligent Gemini-powered security gateway that analyzes prompts/files, detects secrets & PII, and blocks or sanitizes data before it reaches external AI services.

## Table of Contents
- [Team](#team)
- [Tech Stack](#tech-stack)
- [Repository Layout](#repository-layout)
- [Environment Setup](#environment-setup)
- [Backend (FastAPI)](#backend-fastapi)
- [Frontend (Next.js)](#frontend-nextjs)
- [Testing & CI](#testing--ci)
- [Gemini Integration](#gemini-integration)
- [Submission Requirements](#submission-requirements)

## Team
- Team Name: Kanyarashi
- Members: Mohit Pasupuleti, Radhesh Kudamala, Vamshri Hari, Taruni Reddy
- Repo forked from: `odsc2015/agentic-hackathon-template`

## Tech Stack
- Backend: Python 3.11, FastAPI, Google Gemini API
- Frontend: Next.js 16 (App Router), Tailwind CSS
- Deployment: Local dev via Uvicorn + Next.js, container-ready (Dockerfile provided)

## Repository Layout
```
.
├── .github/workflows/ci.yml        # smoke-test workflow
├── src/                            # planner, executor, memory, extractors
├── frontend/                       # Next.js App Router frontend
├── environment.yml                 # Conda env spec (alt. to Dockerfile)
├── Dockerfile                      # Optional docker build
├── TEST.sh                         # Smoke-test script (pytest + import check)
├── README.md                       # (this file)
├── ARCHITECTURE.md                 # diagram + component overview (add content)
├── EXPLANATION.md                  # planning/tool/memory/limits (add content)
├── DEMO.md                         # video link + timestamps (add content)
└── requirements.txt                # backend Python deps
```

## Environment Setup
### 1. Backend
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# set GEMINI_API_KEY and other vars
uvicorn src.main:app --reload --port 8000
```

### 2. Frontend
```bash
cd frontend
npm install
echo "NEXT_PUBLIC_API_BASE_URL=http://localhost:8000" > .env.local
npm run dev
```

## Backend (FastAPI)
- Entrypoint: `src/main.py`
- Planner/executor/memory modules located under `src/`
- API Endpoints:
  - `POST /analyze` – analyze JSON content
  - `POST /analyze-file` – analyze uploaded files
  - `GET /stats` – telemetry
  - `GET /history` – recent decisions
  - `GET /health` – health check
- Gemini usage: `GEMINI_API_KEY` is read from `.env`, invoked inside planner/executor for sanitization/explanations. Secrets never leave user infra; only sanitized payloads may call Gemini.
- File ingestion: install optional parsers included in `requirements.txt` (PyPDF2, python-docx, openpyxl, python-pptx, Pillow+pytesseract) so `/analyze-file` can process PDFs, Office docs, and images locally before any Gemini calls.

## Frontend (Next.js)
- Located in `frontend/` and built with the Next.js App Router, TypeScript, TailwindCSS, and shadcn/ui primitives.
- Install deps: `cd frontend && npm install`. Useful scripts:
  - `npm run dev` – start the dev server with the Three.js splash/background.
  - `npm run build` / `npm run start` – production build + serve.
  - `npm run lint` – TypeScript + ESLint checks.
- Environment: create `frontend/.env.local` with `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000` (or your deployment URL). The UI reads only this value and never exposes other secrets.
- Component architecture:
  - shadcn components live in `frontend/src/components/ui/` (managed via `npx shadcn-ui@latest add <component>`).
  - Feature folders (`frontend/src/features/*`) isolate the analysis form, agent pipeline, stats grid, and history modal.
  - Three.js visuals (`SplashScreen`, `DottedSurface`) reside in `frontend/src/components` and respect `prefers-reduced-motion`.
- The UI includes the text/file analysis workspace, agent pipeline visualization, telemetry pie chart, decision panel with `[REDACTED]` output, and an audit history modal with filters.

## Testing & CI
- Run smoke tests locally: `./TEST.sh`
- CI: `.github/workflows/ci.yml` installs deps via `requirements.txt` and runs `TEST.sh` on push/PR.

## Gemini Integration
- Set `GEMINI_API_KEY` in `.env` (never commit it) before running either the backend or the smoke tests.
- `src/executor.py` contains all Gemini touch-points:
  - `sanitize_with_gemini()` masks content with `gemini-2.5-flash-lite` → `gemini-pro-latest` fallbacks, then falls back to regex.
  - `smart_sanitize_with_gemini()` rewrites PII-heavy text for contextual redaction.
  - `generate_explanation()` uses Gemini to summarize why the agent blocked/sanitized.
- `src/planner.py` orchestrates these tools so Gemini is only invoked when policy rules allow sanitization (secrets trigger an early BLOCK without calling the LLM).
- Track quota/usage via https://aistudio.google.com/usage and update `.env.example` if new Gemini features are enabled.

## Submission Requirements
- [x] `ARCHITECTURE.md` – add diagram + explanations
- [x] `EXPLANATION.md` – add reasoning/memory/tool details
- [ ] `DEMO.md` – add 3–5 min video link w/ timestamps (00:00–00:30 intro, etc.)
- [ ] Record video + host publicly
- [ ] Complete official submission form with repo URL + video link
- [ ] Ensure README reflects team name and setup instructions
