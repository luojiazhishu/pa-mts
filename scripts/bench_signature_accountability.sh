#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/bench_capture_lib.sh"

bench_write_metadata
bench_capture bench_multiverse_sig cargo bench --locked --bench bench_multiverse_sig "$@"
bench_capture bench_pa_multiverse_sig cargo bench --locked --bench bench_pa_multiverse_sig "$@"
bench_summarize
bench_print_results_dir
