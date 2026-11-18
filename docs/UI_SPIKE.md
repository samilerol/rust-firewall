# Rust-native UI spike (egui/eframe)

Status: spike, 2026-11-19. Decision context: ADR-025 (whole product in Rust, UI included). Not wired to the APK, no device or emulator result, no claim about APK size or memory yet.

## What exists

`ui/` is an **isolated workspace** (excluded from the root workspace, like `fuzz/`). The core keeps MSRV 1.85 and almost no dependencies; the UI has its own lockfile, `rust-version = 1.85` and an MSRV-aware resolver (`ui/.cargo/config.toml`).

- `records.rs`: decoder for the 96-byte active-flow records of `snapshotForwarding`, plus byte formatting. Tested.
- `app.rs`: a minimal Connections screen with sample rows. Presentation only: no packet, policy or decision logic.
- `lib.rs`: Android `NativeActivity` entry symbol (one function-local `unsafe_code` exception, same pattern as the JNI exports, no unsafe blocks). `main.rs`: desktop runner for development.

## Dependencies chosen (need owner approval, requested 2026-11-19)

`eframe =0.32.3` (glow; `android-native-activity` on Android, `x11` on desktop) and `android-activity =0.6.1`. 0.32.3 is the newest eframe whose declared MSRV is 1.85; 0.37 needs 1.95. About 296 locked packages (egui stack, windowing, image), versus a near-empty core graph. Treat the UI graph as a trusted but large dependency set; cargo-deny runs on it in CI (`dependencies.yml`).

## Verified locally (Rust 1.100.0 and 1.85.0)

- `cargo +1.85.0 check --locked` on the host and `--target aarch64-linux-android --lib`: passed.
- UI crate fmt, `clippy -D warnings` and 4 unit tests: passed. Root workspace unchanged (138 tests).

## Not verified / next

- cargo-deny licenses/advisories for the UI graph (CI result decides; `BSL-1.0` and `Zlib` may need an explicit policy decision).
- Gradle/APK packaging of the Rust library, APK size, memory and startup, behavior on an emulator and the phone.
- Calling `snapshotForwarding` from Rust (the export is JNI, so the bridge shape is still open).
- Screens beyond Connections (Dashboard, Apps, Captures, Settings) and Turkish strings.
