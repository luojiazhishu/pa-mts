# PA-MTS Artifact

This artifact implements the current PA-MTS construction:
the aggregate signature is `sigma = (hat_sigma', hat_sigma'_0, hat_sigma'_1, d, tau)` (384 bytes),
the tracing credential is `c = Enc(tk, (Q, u))` under a fresh AES-256-GCM key `tk`,
`d = H(c || Q || u)` is hashed to `G_2`, and `tau` is a BLS signature of the aggregator on the
compressed `hat_sigma' || hat_sigma'_0 || hat_sigma'_1 || d`. `Verify` checks `tau` and the two MTS
equations; `Trace` decrypts `c`; `TraceVerify` checks `Q in Lambda`, `d`, `tau`, and the three
algebraic relations. The shared primitives are in `src/pa_issue.rs`.

**Library.** The original MTS artifact depends on a git fork (`civicrypt/bls12_381`) that adds
Pippenger multi-exponentiation. This version uses the crates.io crate `bls12_381_plus = 0.8.18`
instead, renamed to `bls12_381` in `Cargo.toml`. It provides the same `sum_of_products`
(Pippenger) API and RFC 9380 hash-to-curve. MTS and PA-MTS use the same library, so the
comparison is unaffected, but absolute timings differ from runs made with the fork.

Generate the LaTeX table bodies of the paper from a run with
`python3 scripts/make_latex_tables.py bench_results/<RUN_ID>`.

This artifact contains the PA-MTS implementation and scripts for **Signature and Accountability Performance**, **Universe Setup Performance**, and **Communication and Storage Costs**.

## 1. Build and correctness checks

Assuming the project is extracted to `~/pa-mts`:

```bash
cd ~/pa-mts
cargo fetch --locked
cargo build --release --locked
cargo test --all-features --locked
cargo bench --no-run --locked
```

A successful test run should complete with no failures.

## 2. Smoke test

The smoke test checks that the main MTS and PA-MTS paths execute successfully. It is not used for the performance results.

```bash
cd ~/pa-mts
SMOKE_ID=smoke-$(date -u +%Y%m%dT%H%M%SZ)
BENCH_RUN_ID="$SMOKE_ID" CARGO_NET_OFFLINE=true \
  bash scripts/bench_smoke.sh
```

A successful run reports the following five Criterion tests:

```text
smoke_multiverse_sig
smoke_pa_multiverse_sig
smoke_mts_ugen
smoke_pa_mts_ugen
smoke_pa_mts_end_to_end
```

## 3. Full evaluation

The full evaluation runs all three evaluation categories. Criterion uses 10 samples per parameter setting after its warm-up phase. The run can take a substantial amount of time, so the following command executes it in the background.

```bash
cd ~/pa-mts

RUN_ID=eval-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "bench_results/$RUN_ID"

nohup env \
  BENCH_RUN_ID="$RUN_ID" \
  CARGO_NET_OFFLINE=true \
  bash scripts/bench_eval.sh \
  > "bench_results/$RUN_ID/console.log" 2>&1 &

EVAL_PID=$!
printf 'RUN_ID=%s\nPID=%s\n' "$RUN_ID" "$EVAL_PID"
```

Monitor the run with:

```bash
tail -f "bench_results/$RUN_ID/console.log"
```

Pressing `Ctrl+C` stops only the log viewer. The background evaluation continues. Its status can be checked with:

```bash
ps -p "$EVAL_PID" -o pid,etime,pcpu,pmem,cmd
pgrep -af 'bench_eval|cargo bench'
```

After a complete run, the final log should include:

```text
Parsed 108 timing rows
Computed 45 paired rows
Benchmark text results saved under: bench_results/<RUN_ID>
```

## 4. Evaluation coverage and parameters

### Signature and Accountability Performance

This category benchmarks MTS `Sign`, `Aggr`, and `Verify`, and PA-MTS `Sign`, `Aggr`, `Verify`, `Trace`, and `TraceVerify`.

```text
(N,K) =
(100,1), (300,1), (500,1),
(100,3), (300,3), (500,3),
(100,5), (300,5), (500,5)
```

Here, `N` is the number of parties, `K` is the uniform weight assigned to each party, `W=N*K`, `B=K`, and `T=floor(W/2)`. Both MTS and PA-MTS use the first `N/2` parties as the benchmark quorum, whose total weight is exactly `T`. Pairing validation of partial signatures is excluded from both timed `Aggr` paths, as in the MTS artifact. `pa_mts::aggregate` implements the validation (randomized batch check of step 2) and is covered by the unit tests.

To run only this category:

```bash
cd ~/pa-mts
BENCH_RUN_ID=signature-accountability-$(date -u +%Y%m%dT%H%M%SZ) \
  CARGO_NET_OFFLINE=true bash scripts/bench_signature_accountability.sh
```

### Universe Setup Performance

This category benchmarks `UGenOn` and `UGenOff` for both MTS and PA-MTS.

```text
(N,K) =
(10,1), (30,1), (50,1),
(10,3), (30,3), (50,3),
(10,5), (30,5), (50,5)
```

All `N` parties contribute universe setup messages. The benchmark measures the algebraic setup core: interpolation and exponentiation in `UGenOn`, and additive aggregation of pre-generated setup messages in `UGenOff`. Formal NIZK operations, universe setup consistency checks, and coefficient derivation and weighting are outside the benchmark scope.

To run only this category:

```bash
cd ~/pa-mts
BENCH_RUN_ID=universe-setup-$(date -u +%Y%m%dT%H%M%SZ) \
  CARGO_NET_OFFLINE=true bash scripts/bench_universe_setup.sh
```

### Communication and Storage Costs

The size report uses the same `(N,K)` grid as the Signature and Accountability Performance evaluation. It reports serialized sizes for partial and aggregate signatures, verification keys, public parameters, universe setup messages, tracing credentials, tracing keys, disclosed quorums, and trace outputs. Universe setup message sizes exclude NIZK proofs, consistent with the benchmark scope.

To run only this category:

```bash
cd ~/pa-mts
BENCH_RUN_ID=communication-storage-$(date -u +%Y%m%dT%H%M%SZ) \
  CARGO_NET_OFFLINE=true bash scripts/bench_communication_storage.sh
```

## 5. Result files

New runs write the following files under `bench_results/<RUN_ID>/`:

```text
metadata.txt
console.log
bench_multiverse_sig.txt
bench_pa_multiverse_sig.txt
bench_mts_ugen.txt
bench_pa_mts_ugen.txt
bench_size_report.txt
timings.csv
paired_overheads.csv
sizes.csv
```

`timings.csv` contains the Criterion timing estimates and confidence intervals. `paired_overheads.csv` contains the absolute and relative PA-MTS overheads for operations directly paired with MTS. `sizes.csv` contains the serialized communication and storage measurements. `metadata.txt` records the benchmark parameters and execution environment.

