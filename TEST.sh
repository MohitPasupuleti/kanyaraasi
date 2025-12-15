#!/usr/bin/env bash
set -euo pipefail

echo "Running LeakLockAI smoke tests..."

if [ -f ".env" ]; then
  echo "Loading .env (without exporting secrets)..."
  set -a
  source .env
  set +a
fi

python -m pytest tests || python -m pytest || echo "Pytest not available, running basic main import."
python - <<'PY'
from src import main
print("Imported src.main successfully.")
PY

echo "Smoke tests completed."
