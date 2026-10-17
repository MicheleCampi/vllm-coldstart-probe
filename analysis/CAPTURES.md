# Captures

The ten captures behind the README's numbers. The capture files
(`*.jsonl`, 9 to 28 MB each) are not in the git tree: they are assets of the
release [`captures-2026-05`](https://github.com/MicheleCampi/vllm-coldstart-probe/releases/tag/captures-2026-05),
compressed with xz (0.5 to 1.5 MB each). Each line is one event of six
integers (`timestamp_ns`, `pid`, `tid`, `syscall_nr`, `kind`, `ret`), with
no strings. Nine were taken with `vllm-probe --pid 0` and hold every process
on the node, not only vLLM. `SHA256SUMS` pins their content, and `summaries/`
holds what `analyze.py` reports for each one filtered to the loader and
EngineCore PIDs, which is how every syscall figure in the README was computed.

| File | Start (UTC) | GPU | Model | Configuration | Probe recorded | libcuda uprobes | Loader / EngineCore PID | Events | Dropped | Load time | SHA-256 (first 16) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `mistral-7b-a10-cold-start.jsonl` | 2026-05-28 18:22:15 | A10 | `mistralai/Mistral-7B-Instruct-v0.3` | FP16, eager, cold cache | loader PID only | none | 2899 / 3001 | 106,880 | 0 | 11.73 s | `c987b1ec09f272d1` |
| `mistral-7b-a10-cold-start-with-uprobe.jsonl` | 2026-05-29 19:08:27 | A10 | `mistralai/Mistral-7B-Instruct-v0.3` | FP16, eager, cold cache | all (--pid 0) | entry | 3025 / 3127 | 147,364 | 229 | not recorded | `946fb3d38b67b804` |
| `mistral-7b-a10-cold-start-uretprobe.jsonl` | 2026-05-30 09:40:30 | A10 | `mistralai/Mistral-7B-Instruct-v0.3` | FP16, eager, cold cache | all (--pid 0) | entry+return | 2534 / 2637 | 148,655 | 497 | not recorded | `0a5ffc335d17fc74` |
| `qwen2.5-7b-awq-a10-coldstart.jsonl` | 2026-05-30 11:09:44 | A10 | `Qwen/Qwen2.5-7B-Instruct-AWQ` | AWQ, eager, cold cache | all (--pid 0) | entry+return | 3100 / 3275 | 196,108 | 0 | 18.97 s | `91948eb486baa0b8` |
| `qwen2.5-14b-awq-a10-coldstart.jsonl` | 2026-05-30 11:13:47 | A10 | `Qwen/Qwen2.5-14B-Instruct-AWQ` | AWQ, eager, cold cache | all (--pid 0) | entry+return | 3391 / 3566 | 203,503 | 1,493 | 25.02 s | `60017e7672695c52` |
| `qwen2.5-32b-awq-a100-coldstart.jsonl` | 2026-05-30 12:15:34 | A100 | `Qwen/Qwen2.5-32B-Instruct-AWQ` | AWQ, eager, cold cache | all (--pid 0) | entry+return | 2584 / 2762 | 206,582 | 0 | 28.36 s | `41f910b4770001b1` |
| `qwen2.5-7b-fp16-a10-coldstart.jsonl` | 2026-05-30 16:57:17 | A10 | `Qwen/Qwen2.5-7B-Instruct` | FP16, eager, cold cache | all (--pid 0) | entry+return | 2816 / 2920 | 149,730 | 114 | 15.05 s | `fd9d7878fe79fee1` |
| `qwen2.5-7b-gptq-a10-coldstart.jsonl` | 2026-05-30 17:01:20 | A10 | `Qwen/Qwen2.5-7B-Instruct-GPTQ-Int4` | GPTQ, eager, cold cache | all (--pid 0) | entry+return | 3038 / 3212 | 192,621 | 539 | 12.32 s | `f467117627066d8a` |
| `qwen2.5-7b-fp16-cudagraph-a10-coldstart.jsonl` | 2026-05-30 17:25:12 | A10 | `Qwen/Qwen2.5-7B-Instruct` | FP16, CUDA graphs, cold cache | all (--pid 0) | entry+return | 2530 / 2635 | 325,494 | 82 | 47.72 s | `20f0c4d772cc4945` |
| `qwen2.5-7b-fp16-warmcache-a10-coldstart.jsonl` | 2026-05-30 17:33:15 | A10 | `Qwen/Qwen2.5-7B-Instruct` | FP16, eager, warm cache | all (--pid 0) | entry+return | 3003 / 3107 | 145,804 | 1,256 | 11.70 s | `038ac95475efee8e` |

Where each column comes from:

- **File, Events, SHA-256**: computed from the capture file (line count,
  `sha256sum`); the full hashes are in `SHA256SUMS`.
- **Start, Probe recorded, libcuda uprobes, PIDs, Dropped, Load time**:
  printed by the probe and by the capture scripts during each session, and
  transcribed on 2026-10-10. The event count each session printed equals the
  file's line count in all ten cases, which ties each row to its file. The
  node logs they came from were not kept.
- **Dropped**: events the probe drained from the kernel ring buffer and then
  discarded because its writer fell behind (`probe/src/main.rs:161-162`).
  They are not in the file, so counts from a capture with drops are lower
  bounds. Events lost because the ring buffer itself was full are not
  counted anywhere: the eBPF side returns without a trace when
  `EVENTS.reserve` fails (`probe-ebpf/src/main.rs`). A capture with zero
  drops is therefore not proven complete.
- **Load time**: the loader's `Model loaded in` line, the time to construct
  `LLM(...)` (`capture/README.md`). For two phase A captures the session
  output that was kept does not include that line.
- **GPU, Model, Configuration**: from the capture scripts and the file names.

Two captures differ from the rest:

- `mistral-7b-a10-cold-start.jsonl` was filtered on the loader's PID while
  capturing. vLLM's EngineCore subprocess (3001) did the model loading and
  CUDA work, and none of its events are in the file.
- `mistral-7b-a10-cold-start-with-uprobe.jsonl` predates uretprobe support:
  its libcuda events are entries only, so it gives counts but no durations.

To check and regenerate, from a clone of this repository (`gh` downloads
the assets; the release page has the same files):

    gh release download captures-2026-05 -R MicheleCampi/vllm-coldstart-probe -D data
    xz -d data/*.jsonl.xz
    sha256sum -c analysis/SHA256SUMS
    analysis/summarize.sh
    git diff --exit-code analysis/summaries

The last command prints nothing and exits 0 when every summary is
regenerated byte for byte, as it did on 2026-10-17.
