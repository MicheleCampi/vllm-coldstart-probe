#!/usr/bin/env bash
# Regenerate analysis/summaries/ from the captures in data/, which are not
# in this repository (CAPTURES.md says why). Each capture is checked against
# SHA256SUMS first, then analysed on the loader and EngineCore PIDs listed
# in captures.tsv, the filter the README's tables use.
set -euo pipefail
cd "$(dirname "$0")/.."
sha256sum -c --quiet analysis/SHA256SUMS
mkdir -p analysis/summaries
tail -n +2 analysis/captures.tsv | while IFS=$'\t' read -r file loader engine; do
  out="analysis/summaries/${file%.jsonl}.txt"
  python3 analysis/analyze.py "data/$file" --pid "$loader" --pid "$engine" > "$out"
  echo "$out"
done
