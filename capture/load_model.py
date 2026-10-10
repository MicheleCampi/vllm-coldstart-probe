import os
import sys
import time

# Model name passed as argv[1] so one script serves every capture.
model = sys.argv[1] if len(sys.argv) > 1 else "Qwen/Qwen2.5-7B-Instruct-AWQ"

print(f"PID: {os.getpid()}", flush=True)
print(f"MODEL: {model}", flush=True)
print("Waiting 3s for probe to attach...", flush=True)
time.sleep(3)

print("Importing vllm...", flush=True)
from vllm import LLM

print("Loading model...", flush=True)
t0 = time.time()
llm = LLM(
    model=model,
    dtype="float16",
    gpu_memory_utilization=0.85,
    enforce_eager=True,
)
elapsed = time.time() - t0
print(f"Model loaded in {elapsed:.2f}s", flush=True)

print("Holding 5s...", flush=True)
time.sleep(5)
print("Done", flush=True)
