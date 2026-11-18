//! Minimal "Connections" screen drawn with egui. Spike: shows sample rows until the snapshot
//! bridge is connected; contains no packet, policy or decision logic.
use crate::records::{human_bytes, FlowRow};
use eframe::egui;

pub struct ConnectionsApp {
    rows: Vec<FlowRow>,
}

impl ConnectionsApp {
    pub fn new(rows: Vec<FlowRow>) -> Self {
        Self { rows }
    }
}

impl eframe::App for ConnectionsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Connections");
            ui.label(format!("{} active", self.rows.len()));
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for row in &self.rows {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(if row.tcp { "TCP" } else { "UDP" });
                        ui.label(format!("{}:{}", row.destination, row.destination_port));
                        ui.label(match row.uid {
                            Some(uid) => format!("uid {uid}"),
                            None => "uid ?".to_owned(),
                        });
                        ui.label(format!(
                            "↑ {}  ↓ {}",
                            human_bytes(row.out_bytes),
                            human_bytes(row.in_bytes)
                        ));
                    });
                }
            });
        });
    }
}

/// Sample data for the spike only.
pub fn sample_rows() -> Vec<FlowRow> {
    (0..3)
        .map(|i| FlowRow {
            tcp: i != 2,
            source: "10.111.0.1".parse().unwrap(),
            source_port: 40_000 + i,
            destination: "93.184.216.34".parse().unwrap(),
            destination_port: if i == 2 { 53 } else { 443 },
            uid: (i != 1).then_some(10_000 + u32::from(i)),
            out_packets: 10,
            out_bytes: 12_345 * (u64::from(i) + 1),
            in_packets: 20,
            in_bytes: 987_654 * (u64::from(i) + 1),
            created_ms: 0,
            last_seen_ms: 1,
        })
        .collect()
}
