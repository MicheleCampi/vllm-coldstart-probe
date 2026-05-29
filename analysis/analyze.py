#!/usr/bin/env python3
"""
Analyze a cold-start JSONL capture from vllm-probe.

Produces three reports on stdout:
  1. Per-syscall pair counts (enter/exit balance check).
  2. Per-syscall duration statistics (count, total time, p50/p95/p99/max).
  3. Time profile in 100ms buckets across the capture window.

Usage:
    python3 analyze.py <path/to/capture.jsonl>

The expected schema is one JSON object per line with fields:
    timestamp_ns, pid, tid, syscall_nr, kind (0=enter, 1=exit), ret
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# x86_64 syscall numbers we currently capture. Update probe-ebpf
# define_syscall_tracepoint! invocations and this map together when
# adding new syscalls.
SYSCALL_NAMES: dict[int, str] = {
    0: "read",
    3: "close",
    9: "mmap",
    257: "openat",
}

# Uprobe event ids (>= 1000) and their human names. These mirror the
# define_uprobe! invocations in probe-ebpf/src/main.rs. Unlike syscalls,
# uprobe events are one-sided (ENTER only) and act as phase markers in the
# cold-start timeline rather than paired-duration measurements.
UPROBE_NAMES: dict[int, str] = {
    1000: "cuInit",
    1001: "cuModuleLoadData",
    1002: "cuMemAlloc_v2",
    1003: "cuLaunchKernel",
}


def load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def report_pair_balance(events: list[dict]) -> None:
    counts: dict[int, dict[str, int]] = defaultdict(lambda: {"enter": 0, "exit": 0})
    for ev in events:
        kind = "enter" if ev["kind"] == 0 else "exit"
        counts[ev["syscall_nr"]][kind] += 1

    print("=== Pair balance (enter vs exit) ===")
    print(f"{'syscall':<10} {'enter':>10} {'exit':>10} {'delta':>10}")
    print("-" * 44)
    for nr in sorted(SYSCALL_NAMES):
        c = counts.get(nr, {"enter": 0, "exit": 0})
        delta = c["enter"] - c["exit"]
        name = SYSCALL_NAMES[nr]
        print(f"{name:<10} {c['enter']:>10} {c['exit']:>10} {delta:>10}")
    print()


def report_durations(events: list[dict]) -> None:
    # Pair enter/exit by (pid, tid, syscall_nr) using sequential order
    # within each tid. This is the best we can do without a syscall-level
    # request identifier; mismatch is possible only if the same tid
    # invokes the same syscall recursively, which Linux does not allow.
    events_by_key: dict[tuple[int, int, int], list[dict]] = defaultdict(list)
    for ev in events:
        key = (ev["pid"], ev["tid"], ev["syscall_nr"])
        events_by_key[key].append(ev)

    durations_by_syscall: dict[int, list[int]] = defaultdict(list)
    for key, ev_list in events_by_key.items():
        ev_list.sort(key=lambda e: e["timestamp_ns"])
        enter = None
        for ev in ev_list:
            if ev["kind"] == 0:
                enter = ev
            elif ev["kind"] == 1 and enter is not None:
                durations_by_syscall[ev["syscall_nr"]].append(
                    ev["timestamp_ns"] - enter["timestamp_ns"]
                )
                enter = None

    print("=== Duration statistics (nanoseconds, displayed in us/ms) ===")
    print(
        f"{'syscall':<10} {'count':>8} {'total_ms':>12} "
        f"{'p50_us':>10} {'p95_us':>10} {'p99_us':>10} {'max_ms':>10}"
    )
    print("-" * 76)

    total_kernel_ns = 0
    for nr in sorted(SYSCALL_NAMES):
        durs = sorted(durations_by_syscall.get(nr, []))
        if not durs:
            continue
        n = len(durs)
        total_ns = sum(durs)
        total_kernel_ns += total_ns
        p50 = durs[n // 2]
        p95 = durs[int(n * 0.95)]
        p99 = durs[int(n * 0.99)]
        max_ns = durs[-1]
        name = SYSCALL_NAMES[nr]
        print(
            f"{name:<10} {n:>8} {total_ns / 1e6:>12.2f} "
            f"{p50 / 1000:>10.2f} {p95 / 1000:>10.2f} "
            f"{p99 / 1000:>10.2f} {max_ns / 1e6:>10.2f}"
        )
    print("-" * 76)
    print(f"Sum of all kernel time: {total_kernel_ns / 1e9:.3f} s\n")


def report_time_profile(events: list[dict], bucket_ms: int = 100) -> None:
    bucket_ns = bucket_ms * 1_000_000

    # Only count enter events to avoid double-counting per syscall invocation.
    enters = [ev for ev in events if ev["kind"] == 0]
    if not enters:
        print("No enter events found; skipping time profile.\n")
        return
    enters.sort(key=lambda e: e["timestamp_ns"])

    first_ts = enters[0]["timestamp_ns"]
    last_ts = enters[-1]["timestamp_ns"]
    span_s = (last_ts - first_ts) / 1e9

    buckets: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for ev in enters:
        b = (ev["timestamp_ns"] - first_ts) // bucket_ns
        buckets[b][ev["syscall_nr"]] += 1

    print(f"=== Time profile ({bucket_ms}ms buckets, {span_s:.2f}s span) ===")
    print(
        f"{'time_s':>8} {'openat':>8} {'read':>8} "
        f"{'mmap':>8} {'close':>8} {'total':>8}"
    )
    print("-" * 60)
    for b in range(max(buckets) + 1):
        c = buckets.get(b, {})
        total = sum(c.get(nr, 0) for nr in SYSCALL_NAMES)
        if total == 0:
            continue
        t = b * bucket_ms / 1000
        print(
            f"{t:>8.1f} {c.get(257, 0):>8} {c.get(0, 0):>8} "
            f"{c.get(9, 0):>8} {c.get(3, 0):>8} {total:>8}"
        )
    print()

def report_uprobe_markers(events: list[dict]) -> None:
    # Uprobe events (id >= 1000) are one-sided phase markers. For each one
    # we report how many times it fired and when, relative to the first
    # event in the whole capture, so the CUDA-side phases can be lined up
    # against the syscall I/O timeline.
    enters = [ev for ev in events if ev["kind"] == 0]
    if not enters:
        return
    enters.sort(key=lambda e: e["timestamp_ns"])
    capture_start = enters[0]["timestamp_ns"]

    by_id: dict[int, list[int]] = defaultdict(list)
    for ev in enters:
        if ev["syscall_nr"] >= 1000:
            by_id[ev["syscall_nr"]].append(ev["timestamp_ns"])

    print("=== Uprobe phase markers (libcuda) ===")
    if not by_id:
        print("No uprobe events captured "
              "(libcuda not present, or none of the traced symbols were hit).\n")
        return

    print(f"{'function':<20} {'count':>8} {'first_s':>10} {'last_s':>10}")
    print("-" * 50)
    for event_id in sorted(by_id):
        ts = by_id[event_id]
        name = UPROBE_NAMES.get(event_id, f"id={event_id}")
        first_s = (ts[0] - capture_start) / 1e9
        last_s = (ts[-1] - capture_start) / 1e9
        print(f"{name:<20} {len(ts):>8} {first_s:>10.3f} {last_s:>10.3f}")
    print()



def report_uprobe_durations(events: list[dict]) -> None:
    # Pair entry/return by (pid, tid, event_id) in sequential order within
    # each tid, identical to the syscall pairing. A CUDA driver call is
    # synchronous from the calling thread's view, so entry and return
    # alternate cleanly per tid; nested calls to the same symbol on one
    # thread would break this, but the libcuda entry points we trace do
    # not re-enter themselves.
    events_by_key: dict[tuple[int, int, int], list[dict]] = defaultdict(list)
    for ev in events:
        if ev["syscall_nr"] < 1000:
            continue
        key = (ev["pid"], ev["tid"], ev["syscall_nr"])
        events_by_key[key].append(ev)

    durations_by_id: dict[int, list[int]] = defaultdict(list)
    for key, ev_list in events_by_key.items():
        ev_list.sort(key=lambda e: e["timestamp_ns"])
        enter = None
        for ev in ev_list:
            if ev["kind"] == 0:
                enter = ev
            elif ev["kind"] == 1 and enter is not None:
                durations_by_id[ev["syscall_nr"]].append(
                    ev["timestamp_ns"] - enter["timestamp_ns"]
                )
                enter = None

    print("=== Uprobe call durations (time inside each libcuda call) ===")
    if not durations_by_id:
        print("No paired uprobe entry/return events "
              "(capture predates uretprobe support, or libcuda was not used).\n")
        return

    print(
        f"{'function':<20} {'count':>8} {'total_ms':>12} "
        f"{'p50_us':>10} {'p95_us':>10} {'p99_us':>10} {'max_ms':>10}"
    )
    print("-" * 82)
    total_cuda_ns = 0
    for event_id in sorted(durations_by_id):
        durs = sorted(durations_by_id[event_id])
        n = len(durs)
        total_ns = sum(durs)
        total_cuda_ns += total_ns
        p50 = durs[n // 2]
        p95 = durs[int(n * 0.95)]
        p99 = durs[int(n * 0.99)]
        max_ns = durs[-1]
        name = UPROBE_NAMES.get(event_id, f"id={event_id}")
        print(
            f"{name:<20} {n:>8} {total_ns / 1e6:>12.2f} "
            f"{p50 / 1000:>10.2f} {p95 / 1000:>10.2f} "
            f"{p99 / 1000:>10.2f} {max_ns / 1e6:>10.2f}"
        )
    print("-" * 82)
    print(f"Sum of all libcuda call time: {total_cuda_ns / 1e9:.3f} s\n")
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a cold-start JSONL capture from vllm-probe."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to the JSONL file produced by `vllm-probe --output`.",
    )
    parser.add_argument(
        "--bucket-ms",
        type=int,
        default=100,
        help="Time profile bucket size in milliseconds (default: 100).",
    )
    args = parser.parse_args()

    if not args.path.exists():
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 1

    events = load_events(args.path)
    if not events:
        print(f"error: no events in {args.path}", file=sys.stderr)
        return 1

    print(f"Loaded {len(events)} events from {args.path}\n")
    report_pair_balance(events)
    report_durations(events)
    report_time_profile(events, bucket_ms=args.bucket_ms)
    report_uprobe_markers(events)
    report_uprobe_durations(events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
