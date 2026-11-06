#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod automation;
mod remote;
mod report;
mod vm;

use report::{sign, Signed, Violation};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sysinfo::System;
use tauri::{AppHandle, Emitter, WebviewWindow};

// Local testing only. Production needs an authenticated HTTPS session handshake.
const SERVER: &str = "http://127.0.0.1:3000";
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Deserialize)]
struct Session {
    key: String,
    nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerStatus {
    locked: bool,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Clone, Serialize)]
struct Update {
    nonce: String,
    report: Signed,
    status: Option<ServerStatus>,
    error: Option<String>,
}

fn scan(sys: &mut System) -> Vec<Violation> {
    sys.refresh_processes();
    let mut v = vm::check(sys);
    v.extend(remote::check(sys));
    v.extend(automation::check(sys));
    v
}

fn send_report(http: &reqwest::blocking::Client, report: &Signed) -> Result<ServerStatus, String> {
    http.post(format!("{SERVER}/api/guard/report"))
        .json(report)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<ServerStatus>())
        .map_err(|e| format!("Report delivery failed; exam remains locked: {e}"))
}

fn begin_session(app: AppHandle) -> Result<Update, String> {
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    // The key stays in Rust; the webview never receives credentials.
    let session = http.post(format!("{SERVER}/api/guard/session"))
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<Session>())
        .map_err(|e| format!("Cannot start local session. Run node server/verify.js first: {e}"))?;
    if session.key.is_empty() || session.nonce.is_empty() {
        return Err("Server returned an invalid session".into());
    }

    let mut sys = System::new();
    let first = sign(session.key.as_bytes(), &session.nonce, 0, &scan(&mut sys));
    let status = send_report(&http, &first)?;
    let update = Update {
        nonce: session.nonce.clone(), report: first, status: Some(status), error: None,
    };

    automation::start_input_monitor();
    // Keep reporting even when locked, so staff can review the session and see
    // whether a violation has stopped. Ongoing violations correctly re-lock it.
    std::thread::spawn(move || {
        let mut seq = 1u64;
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let report = sign(session.key.as_bytes(), &session.nonce, seq, &scan(&mut sys));
            let (status, error) = match send_report(&http, &report) {
                Ok(status) => (Some(status), None),
                Err(error) => (None, Some(error)),
            };
            let _ = app.emit("guard:report", Update {
                nonce: session.nonce.clone(), report, status, error,
            });
            seq += 1;
        }
    });
    Ok(update)
}

#[tauri::command]
async fn start_session(app: AppHandle, window: WebviewWindow) -> Result<Update, String> {
    if MONITOR_STARTED.swap(true, Ordering::SeqCst) {
        return Err("A session is already running. Restart the app for a new session.".into());
    }
    if let Err(e) = window.set_content_protected(true) {
        MONITOR_STARTED.store(false, Ordering::SeqCst);
        return Err(e.to_string());
    }
    // Blocking HTTP must not run on Tauri's UI/async executor thread.
    let result = tauri::async_runtime::spawn_blocking(move || begin_session(app))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    if result.is_err() {
        MONITOR_STARTED.store(false, Ordering::SeqCst);
    }
    result
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start_session])
        .run(tauri::generate_context!())
        .expect("error while running ExamGuard");
}
