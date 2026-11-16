#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from pathlib import Path


TIME_RE = re.compile(
    r"^(?P<operation>[a-z0-9_]+) \[N=(?P<n>\d+), K=(?P<k>\d+)"
    r"\]\s+time:\s+"
    r"\[(?P<low>[0-9.]+) (?P<low_unit>[^ ]+) "
    r"(?P<estimate>[0-9.]+) (?P<estimate_unit>[^ ]+) "
    r"(?P<high>[0-9.]+) (?P<high_unit>[^\]]+)\]$"
)
NAME_RE = re.compile(
    r"^(?P<operation>[a-z0-9_]+) \[N=(?P<n>\d+), K=(?P<k>\d+)\]$"
)
INTERVAL_RE = re.compile(
    r"^time:\s+\[(?P<low>[0-9.]+) (?P<low_unit>[^ ]+) "
    r"(?P<estimate>[0-9.]+) (?P<estimate_unit>[^ ]+) "
    r"(?P<high>[0-9.]+) (?P<high_unit>[^\]]+)\]$"
)

UNIT_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "μs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
}

PAIRS = {
    "sign": ("multiverse_sign", "pa_multiverse_sign"),
    "aggregate": ("multiverse_aggregate", "pa_multiverse_aggregate"),
    "verify": ("multiverse_verify", "pa_multiverse_verify"),
    "ugen_on": ("mts_ugen_on", "pa_mts_ugen_on"),
    "ugen_off": ("mts_ugen_off", "pa_mts_ugen_off"),
}

PAIR_SOURCE_GROUPS = (
    (
        "bench_multiverse_sig.txt",
        "bench_pa_multiverse_sig.txt",
        ("sign", "aggregate", "verify"),
    ),
    (
        "bench_mts_ugen.txt",
        "bench_pa_mts_ugen.txt",
        ("ugen_on", "ugen_off"),
    ),
)


def seconds(value, unit):
    if unit not in UNIT_SECONDS:
        raise ValueError(f"unsupported Criterion time unit: {unit}")
    return float(value) * UNIT_SECONDS[unit]


def parse_timing_file(path):
    rows = []
    pending_name = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        match = TIME_RE.match(stripped)
        if match:
            values = match.groupdict()
            pending_name = None
        else:
            name_match = NAME_RE.match(stripped)
            if name_match:
                pending_name = name_match.groupdict()
                continue
            interval_match = INTERVAL_RE.match(stripped)
            if pending_name is None or interval_match is None:
                continue
            values = {**pending_name, **interval_match.groupdict()}
            pending_name = None

        if values["low_unit"] not in UNIT_SECONDS:
            continue
        n = int(values["n"])
        k = int(values["k"])
        rows.append(
            {
                "operation": values["operation"],
                "N": n,
                "K": k,
                "W": n * k,
                "low_seconds": seconds(values["low"], values["low_unit"]),
                "estimate_seconds": seconds(
                    values["estimate"], values["estimate_unit"]
                ),
                "high_seconds": seconds(values["high"], values["high_unit"]),
                "source": path.name,
            }
        )
    return rows


def write_csv(path, rows, fieldnames):
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def paired_overheads(rows):
    by_key = {
        (row["operation"], row["N"], row["K"]): row for row in rows
    }
    output = []
    for phase, (mts_name, pa_name) in PAIRS.items():
        for (operation, n, k), mts_row in sorted(by_key.items()):
            if operation != mts_name:
                continue
            pa_row = by_key.get((pa_name, n, k))
            if pa_row is None:
                continue
            mts_time = mts_row["estimate_seconds"]
            pa_time = pa_row["estimate_seconds"]
            output.append(
                {
                    "phase": phase,
                    "N": n,
                    "K": k,
                    "W": n * k,
                    "mts_estimate_seconds": mts_time,
                    "pa_mts_estimate_seconds": pa_time,
                    "absolute_overhead_seconds": pa_time - mts_time,
                    "relative_overhead_percent": (pa_time / mts_time - 1.0) * 100.0,
                }
            )
    return output


def validate_paired_sources(rows, source_names):
    by_operation = {}
    for row in rows:
        by_operation.setdefault(row["operation"], set()).add((row["N"], row["K"]))

    for mts_source, pa_source, phases in PAIR_SOURCE_GROUPS:
        if mts_source not in source_names or pa_source not in source_names:
            continue
        for phase in phases:
            mts_name, pa_name = PAIRS[phase]
            mts_grid = by_operation.get(mts_name, set())
            pa_grid = by_operation.get(pa_name, set())
            if not mts_grid or not pa_grid:
                raise ValueError(f"missing paired {phase} timing rows")
            if mts_grid != pa_grid:
                raise ValueError(f"mismatched MTS/PA-MTS parameter grid for {phase}")


def extract_sizes(run_dir):
    source = run_dir / "bench_size_report.txt"
    if not source.exists():
        return None
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    start = next((index for index, line in enumerate(lines) if line.startswith("N,K,")), None)
    if start is None:
        raise ValueError("size report CSV header was not found")
    csv_lines = []
    for line in lines[start:]:
        if not line or line.startswith("#"):
            continue
        if line.startswith(("warning:", "Compiling ", "Finished ", "Running ")):
            break
        if re.match(r"^(N|\d+),", line):
            csv_lines.append(line)
    if len(csv_lines) < 2:
        raise ValueError("no size-report rows were parsed")

    parsed_rows = list(csv.DictReader(csv_lines))
    try:
        size_keys = {(int(row["N"]), int(row["K"])) for row in parsed_rows}
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid N/K fields in size report") from error
    if len(size_keys) != len(parsed_rows):
        raise ValueError("duplicate (N,K) rows in size report")

    (run_dir / "sizes.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    return size_keys


def main():
    parser = argparse.ArgumentParser(description="Parse PA-MTS Criterion text results")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        parser.error(f"not a benchmark result directory: {run_dir}")

    timing_sources = [
        source
        for source in sorted(run_dir.glob("bench_*.txt"))
        if source.name not in {"bench_size_report.txt", "bench_smoke.txt"}
    ]
    rows = []
    for source in timing_sources:
        source_rows = parse_timing_file(source)
        if not source_rows:
            raise ValueError(f"no Criterion timing rows were parsed from {source.name}")
        rows.extend(source_rows)

    row_keys = [(row["operation"], row["N"], row["K"]) for row in rows]
    if len(row_keys) != len(set(row_keys)):
        raise ValueError("duplicate operation/(N,K) timing rows were parsed")
    source_names = {source.name for source in timing_sources}
    validate_paired_sources(rows, source_names)
    rows.sort(key=lambda row: (row["operation"], row["N"], row["K"]))

    timing_fields = [
        "operation",
        "N",
        "K",
        "W",
        "low_seconds",
        "estimate_seconds",
        "high_seconds",
        "source",
    ]
    write_csv(run_dir / "timings.csv", rows, timing_fields)

    overhead_rows = paired_overheads(rows)
    overhead_fields = [
        "phase",
        "N",
        "K",
        "W",
        "mts_estimate_seconds",
        "pa_mts_estimate_seconds",
        "absolute_overhead_seconds",
        "relative_overhead_percent",
    ]
    write_csv(run_dir / "paired_overheads.csv", overhead_rows, overhead_fields)
    size_keys = extract_sizes(run_dir)
    signature_accountability_keys = {
        (row["N"], row["K"])
        for row in rows
        if row["operation"] in {"multiverse_sign", "pa_multiverse_sign"}
    }
    if (
        size_keys is not None
        and signature_accountability_keys
        and size_keys != signature_accountability_keys
    ):
        raise ValueError(
            "size-report grid does not match signature and accountability timing grid"
        )

    print(f"Parsed {len(rows)} timing rows into {run_dir / 'timings.csv'}")
    print(
        f"Computed {len(overhead_rows)} paired rows into "
        f"{run_dir / 'paired_overheads.csv'}"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
