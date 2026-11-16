# Portable core microbenchmarks

This harness measures elapsed wall-clock time per synchronous library operation on synthetic inputs. It does not measure Android forwarding, battery, network throughput, end-to-end latency, resident memory or superiority over other firewalls.

## Run

Stable Rust, release mode, no additional Rust dependencies:

```sh
cargo run --release --locked -p netscope-bench -- --smoke > smoke.csv
cargo run --release --locked -p netscope-bench > baseline.csv
python3 tools/summarize_bench.py baseline.csv > summary.md
```

Smoke mode performs 100 iterations with three measured samples; baseline performs 10,000 iterations with seven measured samples. Both also output sample 0 as warmup, excluded from the summary. Allocation-based setup and fixture validation happen outside measurement, except unique flow insertion intentionally includes table growth/allocation. The harness uses black_box on inputs/results and rejects debug builds. Each sample records operation count, elapsed nanoseconds and nanoseconds per operation. Output includes loop, black_box and timing overhead: tiny values are not standalone operation latency guarantees. No baseline subtraction or confidence intervals are applied.

## Original core cases (31)

- Five parsing cases: minimum-size IPv4/IPv6 TCP/UDP datagrams and truncated IPv4 rejection. Checksums are synthetic and not validated; no payload-size sweep, TCP options or extension headers.
- Ten policy cases: empty/default-deny, then 64/512/4096 rules with matching first, matching last or no matching rule. These rules filter TCP and destination port; CIDR and source-port costs are not measured by these cases. Policy creation is outside timing. The pre-optimization reference scans all rules. Current policy compiles precedence and stops at a match; first/last here denote ORIGINAL input positions and the matching rule has priority 0, so both can move to the front after compilation. Miss cases remain full scans.
- Sixteen flow cases: 1/64/512/4096 directional entries, with unique insertion, existing-flow refresh, full-table new-flow rejection and batch expiration of all entries. Insertion/refresh/rejection include the real expiry operation (O(F) sweep in the reference, due-only ordered expiry in the current code); timestamps remain fixed during a batch to prevent accidental expiration. Batch expiration uses one operation per sample and its ns/op is per whole-table drain, not per flow; short drains have particularly high timer noise. Table setup is outside those measurements. HashMap randomization and allocator behavior introduce run-to-run variation.

## CI and comparisons

The separate ten-minute benchmark job runs on standard ubuntu-24.04 with two build workers. It uploads raw.csv, summary.md, build-and-run.log and environment.txt for seven days. The latter records actual checkout SHA (a synthetic merge SHA for PR runs), rustc version/host, kernel, CPU, RAM and disk. No fixed runner specifications are assumed. Compare repeated runs on the same host/toolchain/profile and input sizes; shared hosted-runner results are noisy. Case order is fixed; thermal/frequency/order effects are not controlled. A fixed workload is reproducible, but exact timings are not.

CI initially verifies successful execution and fixture assertions only; it does not enforce a percentage speed threshold. Set regression thresholds only after repeated baseline runs establish natural variation. When optimizing, retain raw before/after results and repeat identical workloads. Preserve an artifact externally if longer than seven-day retention is needed.

Future work: packet/payload-size sweeps, CIDR rule workloads, adversarial traffic distributions, a real Android transport/device matrix, long-lived mixed flow workloads, allocation/RSS measurements and controlled comparisons against NetGuard/RethinkDNS/PCAPdroid on matching devices. These benchmarks make none of those claims.

## Same-runner reference comparison

CI additionally checks out immutable pre-optimization eade0426c803aabb59cd4626718143c75287324a, then runs its unchanged 31 cases on the same runner/stable toolchain. Artifacts include baseline.csv, baseline-commit.txt, baseline-build.log and comparison.md. Current executes before reference: thermal/order effects and randomized HashMaps are uncontrolled, so ratios are observations rather than general speed guarantees. Legacy `*_with_sweep` identifiers are retained for exact case matching; current code uses an ordered due-only expiry check. Changed-timestamp index updates are not represented by fixed-timestamp refresh cases. Bulk drain may be slower and index memory is larger; report these tradeoffs.

## DNS additions (six cases; 37 total)

New current-only cases measure standard query parsing, compressed response parsing, and domain-rule hit/miss evaluation at 64/4096 rules. Construction and fixture checks are outside timing. Matching rules have explicit priority 0; miss cases scan the compiled list. Parsing includes owned normalized question-name allocation. Historical same-runner comparison remains limited to the 31 common core cases; DNS is a new baseline with no previous-version ratio. Smoke now emits 149 CSV lines; baseline emits 297.
