//! Rust-native UI spike (egui/eframe). Presentation only.
pub mod app;
pub mod records;

/// Android entry point (NativeActivity). One exported symbol, like the JNI exports; no unsafe
/// blocks. The desktop binary in main.rs exists only to run the same screen on a workstation.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[no_mangle]
fn android_main(app: android_activity::AndroidApp) {
    let options = eframe::NativeOptions {
        android_app: Some(app),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "NetScope",
        options,
        Box::new(|_| Ok(Box::new(app::ConnectionsApp::new(app::sample_rows())))),
    );
}
