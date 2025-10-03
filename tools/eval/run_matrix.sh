#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[eval] Starting canary and OAST via docker-compose..."
docker compose -f tools/eval/docker-compose.yaml up -d --build

echo "[eval] Waiting for services..."
for i in {1..30}; do
  if curl -fsS http://127.0.0.1:5000/ >/dev/null 2>&1 && curl -fsS http://127.0.0.1:9000/events >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

WORK_DIR="tools/eval/work"
mkdir -p "$WORK_DIR" "$WORK_DIR/evidence"

CANARY_URL="http://127.0.0.1:5000"
OAST_BASE="http://127.0.0.1:9000/t"

echo "[eval] Running scanner inside runner container against canary service"
docker compose -f tools/eval/docker-compose.yaml run --rm runner bash -lc "\
  export OAST_BASE_URL='$OAST_BASE'; \
  python main.py http://canary:5000 \
    --preset thorough \
    --browsers 3 \
    --workers 12 \
    --depth 3 \
    --hash-fuzz \
    --redact-evidence \
    --evidence-dir /work/evidence \
    --format json \
    --out /work/results.json \
"

echo "[eval] Evaluating results..."
docker compose -f tools/eval/docker-compose.yaml run --rm runner bash -lc "\
  python tools/eval/evaluate_matrix.py \
    --ground tools/eval/ground_truth.yaml \
    --scan /work/results.json \
    --oast /work/oast_hits.db \
    --report /work/eval_report.md \
    --csv /work/eval_metrics.csv \
"

echo "[eval] Report tail:"
tail -n 50 "$WORK_DIR/eval_report.md" || true
