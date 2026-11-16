#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BENCH_RUN_ID="${BENCH_RUN_ID:-eval-$(date -u +%Y%m%dT%H%M%SZ)}"
source "${script_dir}/bench_capture_lib.sh"

bench_write_metadata

# Signature and Accountability Performance
bench_capture bench_multiverse_sig cargo bench --locked --bench bench_multiverse_sig "$@"
bench_capture bench_pa_multiverse_sig cargo bench --locked --bench bench_pa_multiverse_sig "$@"

# Universe Setup Performance
bench_capture bench_mts_ugen cargo bench --locked --bench bench_mts_ugen "$@"
bench_capture bench_pa_mts_ugen cargo bench --locked --bench bench_pa_mts_ugen "$@"

# Communication and Storage Costs
bench_capture bench_size_report cargo bench --locked --bench bench_size_report

bench_summarize
bench_print_results_dir
