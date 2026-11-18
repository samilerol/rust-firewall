//! Desktop runner for the UI spike; not part of the Android product.
fn main() -> eframe::Result {
    eframe::run_native(
        "NetScope (spike)",
        eframe::NativeOptions::default(),
        Box::new(|_| {
            Ok(Box::new(netscope_ui::app::ConnectionsApp::new(
                netscope_ui::app::sample_rows(),
            )))
        }),
    )
}
