#!/bin/bash
# Phase D orchestrator. Three captures of Qwen2.5-7B-Instruct (FP16):
#   d1_graph    : enforce_eager=False (CUDA graphs), cold cache
#   d2_warm     : enforce_eager=True, WARM cache (no drop) — run twice,
#                 first to warm the page cache, second is the measured one
# Baseline (eager, cold) already exists from Phase C.
set -e
PROBE=/home/ubuntu/vllm-probe
LOADER=/home/ubuntu/load_model.py
LOADER_GRAPH=/home/ubuntu/load_model_graph.py
MODEL=Qwen/Qwen2.5-7B-Instruct

capture () {
  local SLUG="$1" LOADER_SCRIPT="$2" DROP="$3"
  local OUT="/home/ubuntu/coldstart_${SLUG}.jsonl"
  local LOG="/home/ubuntu/load_${SLUG}.log"
  echo "--- capture $SLUG (drop_caches=$DROP) ---"
  if [ "$DROP" = "yes" ]; then
    sync && sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
  fi
  rm -f "$OUT" "$LOG"
  python3 "$LOADER_SCRIPT" "$MODEL" > "$LOG" 2>&1 &
  local PYPID=$!
  sleep 0.5
  sudo "$PROBE" --pid 0 --duration 240 --output "$OUT" 2>&1 | grep -E 'attached|consumed|dropped' &
  local PROBEPID=$!
  wait $PYPID
  sleep 5
  sudo kill -INT $PROBEPID 2>/dev/null || true
  wait $PROBEPID 2>/dev/null || true
  echo "  output: $(wc -l < "$OUT") lines"
  echo "  wrapper PID: $PYPID"
  grep -oE "EngineCore pid=[0-9]+" "$LOG" | sort -u
  grep -oE "Model loaded in [0-9.]+s" "$LOG" | tail -1
}

echo "=== Prefetch FP16 model ==="
python3 "$LOADER" "$MODEL" 2>&1 | tail -1

echo "=== D1: CUDA graphs enabled, cold cache ==="
capture d1_graph "$LOADER_GRAPH" yes

echo "=== D2 warm-up pass (eager, populates page cache, discarded) ==="
capture d2_warmup "$LOADER" no

echo "=== D2: eager, WARM cache (measured) ==="
capture d2_warm "$LOADER" no

echo "=== Phase D captures complete ==="
