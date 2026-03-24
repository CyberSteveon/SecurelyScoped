use serde::Serialize;

// Data structures for scan results

#[derive(Debug, Serialize)]
enum Severity {
  Minimal,
  Low,
  Medium,
  High,
  Critical,
}

#[derive(Debug, Serialize)]
struct FindingVuln {
  pub title: String,
  pub id: String,
  pub description: String,
  pub severity: Severity,
  pub file: String,
  pub line: usize,
}

#[derive(Debug, Serialize)]
struct ScanResult {
  pub path: String,
  pub findings: Vec<FindingVuln>,
  pub scantime: String,
}

// Tauri Command

#[tauri::command]
fn app_info() -> String {
  let app_name = "Secure Scope Scanner";
  let version = "1.0.0";

  format!("{}\nVersion: {}", app_name, version)
}

// Tauri Application Setup

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![app_info]) 
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}