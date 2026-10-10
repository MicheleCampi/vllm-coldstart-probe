#!/bin/bash
# Usage: run_capture.sh <slug1> <model1> [<slug2> <model2> ...]
# Pairs: slug (output filename tag) + HF model id. Pre-fetches all models
# first, then captures each one cold (cache dropped immediately before).
set -e

PROBE=/home/ubuntu/vllm-probe
LOADER=/home/ubuntu/load_model.py

# Parse slug/model pairs into arrays
SLUGS=(); MODELS=()
while [ $# -gt 0 ]; do
  SLUGS+=("$1"); MODELS+=("$2"); shift 2
done

echo "=== Phase 1: pre-fetch ${#MODELS[@]} model(s) (no probe) ==="
for i in "${!MODELS[@]}"; do
  echo "--- prefetch ${MODELS[$i]} ---"
  python3 "$LOADER" "${MODELS[$i]}" 2>&1 | tail -2
done

echo "=== Phase 2: cold captures ==="
for i in "${!MODELS[@]}"; do
  SLUG="${SLUGS[$i]}"; MODEL="${MODELS[$i]}"
  OUT="/home/ubuntu/coldstart_${SLUG}.jsonl"
  LOG="/home/ubuntu/load_${SLUG}.log"
  echo "--- capture $SLUG ($MODEL) ---"
  sync && sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
  rm -f "$OUT" "$LOG"
  python3 "$LOADER" "$MODEL" > "$LOG" 2>&1 &
  PYPID=$!
  sleep 0.5
  sudo "$PROBE" --pid 0 --duration 240 --output "$OUT" 2>&1 | grep -E 'attached|consumed|dropped' &
  PROBEPID=$!
  wait $PYPID
  sleep 5
  sudo kill -INT $PROBEPID 2>/dev/null || true
  wait $PROBEPID 2>/dev/null || true
  echo "  output: $(wc -l < "$OUT") lines"
  echo "  wrapper PID: $PYPID"
  grep -oE "EngineCore pid=[0-9]+" "$LOG" | sort -u
  grep -oE "Model loaded in [0-9.]+s" "$LOG" | tail -1
done
echo "=== all captures complete ==="
