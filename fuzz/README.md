# Packet fuzzing

Isolated development-only workspace, not a production dependency. Requires nightly Rust, cargo-fuzz 0.13.2 and a C++ compiler. libfuzzer-sys is exactly pinned and fuzz/Cargo.lock is committed. Core code still forbids unsafe; the fuzz runtime uses upstream instrumentation/unsafe code.

From the repository root:

```sh
rustup toolchain install nightly --profile minimal
cargo +stable install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fetch --manifest-path fuzz/Cargo.toml --locked
python3 fuzz/seeds.py
cargo +nightly fuzz run packet -- -max_total_time=30 -timeout=5 -rss_limit_mb=1024 -max_len=65575 -seed=1
git diff --exit-code -- fuzz/Cargo.lock
```

Four structural seeds plus the independent checksum test vectors (including maximum-length binary datagrams and deliberately invalid pseudo-header input) reach metadata and checked-parser paths. The fuzz target calls both explicit checksum policies and checks metadata/result-status consistency. Raw arbitrary bytes exercise error handling; successful parses must satisfy length/address/port bounds and reject truncation or appended bytes. Fuzz input size covers the largest supported IPv6 datagram. A fixed seed helps repeat experiments but duration, nightly/compiler and machine still affect execution counts; record toolchain and use a saved crash file for exact reproduction.

CI limits build parallelism to two, fuzzing to 30 seconds, RSS to 1024 MiB and the whole job to 15 minutes. Crash artifacts are uploaded only on failure with seven-day retention. No privileged tokens, production captures or paid runners. Generated corpus, artifacts and build output are gitignored. Reproduce a crash with `cargo +nightly fuzz run packet fuzz/artifacts/packet/<crash-file>` and turn any validated fix into a normal regression test. A smoke run does not establish complete parser safety.

Dependency metadata was reviewed: fuzz dependencies declare MIT/Apache-2.0 alternatives, with NCSA additionally required by libfuzzer-sys. r-efi offers an MIT/Apache-2.0 alternative; LGPL is not required when choosing those terms. This metadata review is not a vulnerability advisory audit.

## Stateful portable engine target

`cargo +nightly fuzz run engine -- -max_total_time=30 -timeout=5 -rss_limit_mb=1024 -max_len=1024 -seed=1` varies checked admissions, monotonic/reversed clocks, valid/invalid policy updates and resets under an eight-flow cap. It asserts bounded state and no acceptance under default deny. Both this target and the serializer/parser target are pure in-memory code and never open sockets. The CI job runs both targets sequentially after one toolchain/CLI install; each target has a 30-second budget. Parser fuzzing also checks generated UDP datagrams against strict checksum parsing.
