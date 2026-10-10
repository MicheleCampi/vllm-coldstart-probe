# Capture scripts

The scripts that produced the phase B, C and D captures in `data/`, run on
Lambda nodes on 30 May 2026. They are committed as they were used, including
the defect described below.

- `load_model.py <model>` prints its PID, waits 3 s for the probe to attach,
  imports vLLM and times the `LLM(...)` constructor (`enforce_eager=True`),
  printing `Model loaded in X s`. That figure is the "load time" in the
  README: it covers building the engine, not serving a request, and it
  excludes the 3 s wait and the vLLM import.
- `load_model_graph.py <model>` is the same with `enforce_eager=False`
  (phase D, CUDA graphs captured during warm-up).
- `run_capture.sh <slug> <model> [<slug> <model> ...]` pre-fetches every
  model without the probe, then for each one drops the page cache, starts the
  loader, starts `vllm-probe --pid 0 --duration 240`, and prints the event
  count, the loader and EngineCore PIDs and the load time.
- `run_capture_d.sh` runs phase D: CUDA graphs with a cold cache, then an
  eager warm-up pass that is discarded, then the measured warm-cache capture.

The scripts expect the probe binary at `/home/ubuntu/vllm-probe` and
themselves in `/home/ubuntu`.

**Defect.** `PROBEPID=$!` takes the PID of the last command of the
backgrounded pipeline, `grep`, not the probe's. The `kill -INT` therefore
stops `grep`, and the probe runs its full 240 s: each capture extends well
past the end of the load (the FP16 capture of phase C started at 16:57:17
UTC and ended at 17:01:17 UTC). The libcuda figures are unaffected, since
only vLLM calls libcuda. Syscall counts taken without `--pid` include
whatever the node's other processes did during the tail.

**Phase A** (28 to 30 May) used earlier versions of these scripts: the
loader had Mistral-7B-Instruct-v0.3 fixed in it, and the probe ran for 180 s.
The first capture filtered on the loader's PID, so it holds no events from
vLLM's EngineCore subprocess; the two later ones used `--pid 0`. Those
versions are recorded in the capture session, not in this repository.
