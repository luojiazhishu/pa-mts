#!/usr/bin/env bash

bench_results_root="${BENCH_RESULTS_DIR:-bench_results}"
bench_run_id="${BENCH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
bench_run_dir="${bench_results_root}/${bench_run_id}"

mkdir -p "${bench_run_dir}"

bench_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bench_project_root="$(cd "${bench_lib_dir}/.." && pwd)"
bench_param_file="${bench_project_root}/benches/benchmark_params.rs"

# Read explicit `(N, K)` tuples from one benchmark-parameter function.
# benchmark_params.rs remains the only benchmark-parameter source.
bench_params_from_rs() {
    local fn_name="$1"

    if [ ! -r "${bench_param_file}" ]; then
        echo "error: benchmark parameter file is not readable: ${bench_param_file}" >&2
        return 1
    fi

    awk -v target="${fn_name}" '
        $0 ~ "^[[:space:]]*pub fn[[:space:]]+" target "[[:space:]]*\\(" {
            in_fn = 1
            found_fn = 1
            next
        }
        in_fn {
            line = $0
            sub(/\/\/.*/, "", line)
            while (match(line, /\([[:space:]]*[0-9]+[[:space:]]*,[[:space:]]*[0-9]+[[:space:]]*\)/)) {
                tuple = substr(line, RSTART, RLENGTH)
                gsub(/[[:space:]]/, "", tuple)
                if (out != "") out = out ","
                out = out tuple
                line = substr(line, RSTART + RLENGTH)
                found_tuple = 1
            }
            if ($0 ~ "^[[:space:]]*}[[:space:]]*$") {
                in_fn = 0
                exit
            }
        }
        END {
            if (!found_fn) {
                printf "error: benchmark function %s not found in %s\n", target, FILENAME > "/dev/stderr"
                exit 2
            }
            if (!found_tuple) {
                printf "error: no parameter tuples found in %s in %s\n", target, FILENAME > "/dev/stderr"
                exit 3
            }
            print out
        }
    ' "${bench_param_file}"
}

bench_signature_accountability_params() {
    bench_params_from_rs signature_accountability_params
}

bench_universe_setup_params() {
    bench_params_from_rs universe_setup_params
}

bench_communication_storage_params() {
    # The size report intentionally uses the same grid as the signature and
    # accountability benchmarks; benchmark_params.rs remains the source of truth.
    bench_signature_accountability_params
}

bench_cmd_value() {
    "$@" 2>/dev/null || true
}

bench_lscpu_value() {
    local key="$1"
    if command -v lscpu >/dev/null 2>&1; then
        lscpu | awk -F: -v key="$key" '$1 == key { sub(/^[ \t]+/, "", $2); print $2; exit }'
    fi
}

bench_mem_total() {
    if command -v free >/dev/null 2>&1; then
        free -h | awk '/^Mem:/ { print $2; exit }'
    elif [ -r /proc/meminfo ]; then
        awk '/^MemTotal:/ { print $2 " " $3; exit }' /proc/meminfo
    fi
}

bench_os_pretty_name() {
    if [ -r /etc/os-release ]; then
        awk -F= '$1 == "PRETTY_NAME" { gsub(/^"|"$/, "", $2); print $2; exit }' /etc/os-release
    fi
}


bench_write_metadata() {
    local out="${bench_run_dir}/metadata.txt"
    {
        echo "# PA-MTS benchmark metadata"
        echo
        echo "[run]"
        echo "run_id=${bench_run_id}"
        echo
        echo "[parameters]"
        echo "source=benches/benchmark_params.rs"
        echo "parameter_tuple=(N,K)"
        echo "N=number of parties"
        echo "K=uniform weight assigned to each party"
        echo "W=N*K"
        echo "B=K"
        echo "T=floor(W/2)"
        echo "signature_accountability_params=$(bench_signature_accountability_params)"
        echo "universe_setup_params=$(bench_universe_setup_params)"
        echo "communication_storage_params=$(bench_communication_storage_params)"
        echo "signature_accountability_quorum=first N/2 parties; total weight exactly T"
        echo "universe_setup_contributors=all N parties"
        echo
        echo "[benchmark]"
        echo "criterion=10 samples; 3s warm-up"
        echo "parallelism=none explicit"
        echo "signature_accountability_partial_signature_pairing_validation=excluded from both timed MTS/PA-MTS Aggr paths"
        echo "universe_setup_scope=algebraic core: UGenOn interpolation/exponentiations and UGenOff additive aggregation; formal NIZK, consistency checks, and coefficient derivation/weighting excluded"
        echo "communication_storage_scope=serialized object sizes using compressed group encodings"
        echo "communication_storage_ugen_nizk=excluded from universe setup message sizes, matching the evaluation scope"
        echo
        echo "[environment]"
        echo "cpu=$(bench_lscpu_value "Model name")"
        echo "logical_cpus=$(bench_lscpu_value "CPU(s)")"
        echo "cores_per_socket=$(bench_lscpu_value "Core(s) per socket")"
        echo "sockets=$(bench_lscpu_value "Socket(s)")"
        echo "memory=$(bench_mem_total)"
        echo "os=$(bench_os_pretty_name)"
        echo "rustc=$(bench_cmd_value rustc --version)"
        echo "cargo=$(bench_cmd_value cargo --version)"
    } >"${out}"
}

bench_capture() {
    local name="$1"
    shift
    local out="${bench_run_dir}/${name}.txt"

    {
        echo "run_id=${bench_run_id}"
        echo "command=$*"
        echo
        "$@"
    } 2>&1 | tee "${out}"
}

bench_print_results_dir() {
    echo
    echo "Benchmark text results saved under: ${bench_run_dir}"
}

bench_summarize() {
    local python_bin="${BENCH_PYTHON:-python3}"
    if command -v "${python_bin}" >/dev/null 2>&1 \
        && "${python_bin}" -c 'import sys' >/dev/null 2>&1; then
        "${python_bin}" "${script_dir}/parse_bench_results.py" "${bench_run_dir}"
    else
        echo "warning: ${python_bin} is unavailable; raw benchmark text is complete, but CSV summaries were not generated" >&2
    fi
}
