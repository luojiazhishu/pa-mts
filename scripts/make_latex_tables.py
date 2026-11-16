#!/usr/bin/env python3
"""Turn the parsed benchmark results of one run into the LaTeX table bodies of the paper.

Usage: python3 scripts/make_latex_tables.py bench_results/<RUN_ID> [more run dirs ...]

Reads timings.csv (written by parse_bench_results.py) from every given run directory
(later directories override earlier ones for the same operation and setting) and sizes.csv
from the last directory that has one. Prints three LaTeX table bodies:
  1. Sign / Aggr / Verify (MTS vs PA-MTS), the isolated PA-MTS steps 6-7 of Aggr, Trace,
     TraceVerify;
  2. UGen_on / UGen_off (MTS vs PA-MTS);
  3. serialized sizes.
All times are Criterion point estimates (mean) in milliseconds, except Trace (microseconds).
"""
import csv
import sys
from pathlib import Path

SIG_PARAMS = [(100, 1), (300, 1), (500, 1), (100, 3), (300, 3), (500, 3), (100, 5), (300, 5), (500, 5)]
SETUP_PARAMS = [(10, 1), (30, 1), (50, 1), (10, 3), (30, 3), (50, 3), (10, 5), (30, 5), (50, 5)]


def load(run_dirs):
    times = {}
    sizes = None
    for d in run_dirs:
        p = Path(d) / "timings.csv"
        if p.exists():
            for row in csv.DictReader(p.open(encoding="utf-8")):
                key = (row["operation"], int(row["N"]), int(row["K"]))
                times[key] = float(row["estimate_seconds"]) * 1e3
        s = Path(d) / "sizes.csv"
        if s.exists():
            sizes = list(csv.DictReader(s.open(encoding="utf-8")))
    return times, sizes


def fmt(ms):
    if ms < 0.1:
        return f"{ms:.3f}"
    if ms >= 1000:
        return f"{ms:,.0f}".replace(",", "{,}")
    if ms >= 100:
        return f"{ms:.1f}"
    return f"{ms:.2f}"


def pct(base, new):
    return f"{100.0 * (new - base) / base:.2f}\\%".replace("-", "$-$")


def signature_table(t):
    lines = []
    for i, (n, k) in enumerate(SIG_PARAMS):
        if i and i % 3 == 0:
            lines.append("\\midrule")
        g = lambda op: t[(op, n, k)]
        lines.append(
            f"{n} & {k} & {n * k}"
            f" & {fmt(g('multiverse_sign'))} / {fmt(g('pa_multiverse_sign'))}"
            f" & {fmt(g('multiverse_aggregate'))} / {fmt(g('pa_multiverse_aggregate'))}"
            f" & {fmt(g('pa_multiverse_aggregate_extra'))}"
            f" & {fmt(g('multiverse_verify'))} / {fmt(g('pa_multiverse_verify'))}"
            f" & {g('pa_multiverse_trace') * 1e3:.1f} & {fmt(g('pa_multiverse_trace_verify'))} \\\\"
        )
    return "\n".join(lines)


def setup_table(t):
    lines = []
    for i, (n, k) in enumerate(SETUP_PARAMS):
        if i and i % 3 == 0:
            lines.append("\\midrule")
        g = lambda op: t[(op, n, k)]
        lines.append(
            f"{n} & {k} & {n * k}"
            f" & {fmt(g('mts_ugen_on'))} / {fmt(g('pa_mts_ugen_on'))}"
            f" & {pct(g('mts_ugen_on'), g('pa_mts_ugen_on'))}"
            f" & {fmt(g('mts_ugen_off'))} / {fmt(g('pa_mts_ugen_off'))}"
            f" & {pct(g('mts_ugen_off'), g('pa_mts_ugen_off'))} \\\\"
        )
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    times, sizes = load(sys.argv[1:])
    print("% ---- Table: Sign / Aggr / Verify / Trace / TraceVerify (ms) ----")
    try:
        print(signature_table(times))
    except KeyError as e:
        print(f"% missing timing: {e}")
    print("% ---- Table: universe setup (ms) ----")
    try:
        print(setup_table(times))
    except KeyError as e:
        print(f"% missing timing: {e}")
    if sizes:
        print("% ---- sizes.csv (bytes) ----")
        for row in sizes:
            print("% " + ", ".join(f"{k}={v}" for k, v in row.items()))


if __name__ == "__main__":
    main()
