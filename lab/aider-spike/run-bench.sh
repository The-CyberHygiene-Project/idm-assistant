#!/bin/bash
cd "$(dirname "$0")"
for m in openai/mistralai/devstral-small-2-2512 openai/google/gemma-4-26b-a4b-qat; do
  ./run-aider.sh bench.py "$m" 20 results.jsonl >> bench-progress.log 2>> bench-err.log
done
echo BENCH-DONE >> bench-progress.log
