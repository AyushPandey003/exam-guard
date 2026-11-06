#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod automation;
mod remote;
mod report;
mod vm;

use report::{sign, Signed, Violation};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sysinfo::System;
use tauri::{AppHandle, Emitter, WebviewWindow};

static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

fn scan(sys: &mut System) -> Vec<Violation> {
    sys.refresh_processes();
    let mut v = vm::check(sys);
    v.extend(remote::check(sys));
    v.extend(automation::check(sys));
    v
}

/// Called by the exam page after login. `key` and `nonce` are issued by your
/// server per session (over TLS) and are never hard-coded in the binary.
#[tauri::command]
fn start_session(app: AppHandle, window: WebviewWindow, key: String, nonce: String, server_url: String) -> Result<Signed, String> {
    // SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) on Windows,
    // NSWindow.sharingType = .none on macOS — Tauri does both.
    window.set_content_protected(true).map_err(|e| e.to_string())?;

    automation::start_input_monitor();

    let mut sys = System::new();
    let violations = scan(&mut sys);
    let first = sign(key.as_bytes(), &nonce, 0, &violations);
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    // Report goes agent -> server directly; the webview is not on this path.
    let _ = http.post(&server_url).json(&first).send();

    // Preflight failed: don't start monitoring, the page must keep the exam locked.
    if !first.ok {
        return Ok(first);
    }

    if !MONITOR_STARTED.swap(true, Ordering::SeqCst) {
        std::thread::spawn(move || {
            let mut seq = 1u64;
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let v = scan(&mut sys);
                // Heartbeat every tick so the server can detect a killed agent.
                let signed = sign(key.as_bytes(), &nonce, seq, &v);
                let _ = http.post(&server_url).json(&signed).send();
                let _ = app.emit("guard:report", signed); // UI display only
                seq += 1;
            }
        });
    }
    Ok(first)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start_session])
        .run(tauri::generate_context!())
        .expect("error while running ExamGuard");
}
