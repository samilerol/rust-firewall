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

Four synthetic structural IPv4/IPv6 TCP/UDP seeds reach transport parsing. Their checksums are not validated. Raw arbitrary bytes exercise error handling; successful parses must satisfy length/address/port bounds and reject truncation or appended bytes. Fuzz input size covers the largest supported IPv6 datagram. A fixed seed helps repeat experiments but duration, nightly/compiler and machine still affect execution counts; record toolchain and use a saved crash file for exact reproduction.

CI limits build parallelism to two, fuzzing to 30 seconds, RSS to 1024 MiB and the whole job to 15 minutes. Crash artifacts are uploaded only on failure with seven-day retention. No privileged tokens, production captures or paid runners. Generated corpus, artifacts and build output are gitignored. Reproduce a crash with `cargo +nightly fuzz run packet fuzz/artifacts/packet/<crash-file>` and turn any validated fix into a normal regression test. A smoke run does not establish complete parser safety.
