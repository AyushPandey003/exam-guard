use crate::report::Violation;
use sysinfo::System;

const MACRO_TOOLS: &[&str] = &[
    "autohotkey", "autoit3", "autoclicker", "op auto clicker", "gs auto clicker",
    "tinytask", "jitbit", "pulover", "mrecorder", "xmousebuttoncontrol", "ghub",
];

const SCRIPT_MARKERS: &[&str] = &["pyautogui", "pynput", "pydirectinput", "autopy", "xdotool", "robotjs"];

pub fn check(sys: &System) -> Vec<Violation> {
    let mut out = Vec::new();
    for p in sys.processes().values() {
        let name = p.name().to_lowercase();
        if let Some(t) = MACRO_TOOLS.iter().find(|t| name.contains(*t)) {
            out.push(Violation::new("AUTOMATION_TOOL", format!("{name} (matches '{t}')")));
            continue;
        }
        if name.contains("python") || name.contains("node") {
            let cmd = p.cmd().join(" ").to_lowercase();
            if let Some(m) = SCRIPT_MARKERS.iter().find(|m| cmd.contains(*m)) {
                out.push(Violation::new("AUTOMATION_SCRIPT", format!("{name} cmdline references '{m}'")));
            }
        }
    }
    out.extend(input_anomalies());
    out
}

#[derive(serde::Serialize, Default)]
pub struct InputDiagnostics {
    pub supported: bool,
    pub keyboard_active: bool,
    pub mouse_active: bool,
    pub injected_keys: u32,
    pub injected_clicks: u32,
    pub samples: usize,
    pub mean_ms: Option<f64>,
    pub sd_ms: Option<f64>,
}

fn timing_stats(times: &[u32]) -> Option<(f64, f64)> {
    if times.len() < 2 { return None; }
    let intervals: Vec<f64> = times.windows(2)
        .map(|w| w[1].wrapping_sub(w[0]) as f64).collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let sd = (intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
        / intervals.len() as f64).sqrt();
    Some((mean, sd))
}

pub use imp::{diagnostics, input_anomalies, start_input_monitor};

#[cfg(windows)]
mod imp {
    use crate::report::Violation;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
    use std::sync::Mutex;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::*;

    static KEYBOARD_ACTIVE: AtomicBool = AtomicBool::new(false);
    static MOUSE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static INJ_KEYS: AtomicU32 = AtomicU32::new(0);
    static INJ_CLICKS: AtomicU32 = AtomicU32::new(0);
    static KEY_TIMES: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    unsafe extern "system" fn kb_proc(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
        if code >= 0 && (w.0 as u32 == WM_KEYDOWN || w.0 as u32 == WM_SYSKEYDOWN) {
            let k = &*(l.0 as *const KBDLLHOOKSTRUCT);
            if k.flags.0 & 0x10 != 0 {
                INJ_KEYS.fetch_add(1, Relaxed); // LLKHF_INJECTED
            }
            if let Ok(mut v) = KEY_TIMES.lock() {
                v.push(k.time);
                let n = v.len();
                if n > 200 {
                    v.drain(0..n - 200);
                }
            }
        }
        CallNextHookEx(HHOOK::default(), code, w, l)
    }

    unsafe extern "system" fn ms_proc(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
        if code >= 0 && w.0 as u32 == WM_LBUTTONDOWN {
            let m = &*(l.0 as *const MSLLHOOKSTRUCT);
            if m.flags & 0x01 != 0 {
                INJ_CLICKS.fetch_add(1, Relaxed); // LLMHF_INJECTED
            }
        }
        CallNextHookEx(HHOOK::default(), code, w, l)
    }

    pub fn start_input_monitor() {
        std::thread::spawn(|| unsafe {
            let hm = GetModuleHandleW(PCWSTR::null())
                .map(|m| HINSTANCE(m.0))
                .unwrap_or(HINSTANCE(std::ptr::null_mut()));
            let keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, Some(kb_proc), hm, 0);
            let mouse = SetWindowsHookExW(WH_MOUSE_LL, Some(ms_proc), hm, 0);
            KEYBOARD_ACTIVE.store(keyboard.is_ok(), Relaxed);
            MOUSE_ACTIVE.store(mouse.is_ok(), Relaxed);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, HWND::default(), 0, 0).0 > 0 {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            KEYBOARD_ACTIVE.store(false, Relaxed);
            MOUSE_ACTIVE.store(false, Relaxed);
            if let Ok(hook) = keyboard { let _ = UnhookWindowsHookEx(hook); }
            if let Ok(hook) = mouse { let _ = UnhookWindowsHookEx(hook); }
        });
    }

    pub fn diagnostics() -> super::InputDiagnostics {
        let mut d = super::InputDiagnostics {
            supported: true,
            keyboard_active: KEYBOARD_ACTIVE.load(Relaxed),
            mouse_active: MOUSE_ACTIVE.load(Relaxed),
            injected_keys: INJ_KEYS.load(Relaxed),
            injected_clicks: INJ_CLICKS.load(Relaxed),
            ..Default::default()
        };
        if let Ok(times) = KEY_TIMES.lock() {
            d.samples = times.len();
            if let Some((mean, sd)) = super::timing_stats(&times) {
                d.mean_ms = Some(mean);
                d.sd_ms = Some(sd);
            }
        }
        d
    }

    pub fn input_anomalies() -> Vec<Violation> {
        let mut out = Vec::new();
        let d = diagnostics();
        // Counts are cumulative for this app process, not per typing attempt.
        let (k, c) = (d.injected_keys, d.injected_clicks);
        if k >= 3 || c >= 3 {
            out.push(Violation::new("INJECTED_INPUT", format!("{k} injected keys, {c} injected clicks")));
        }
        if d.samples >= 40 {
            if let (Some(mean), Some(sd)) = (d.mean_ms, d.sd_ms) {
                if mean < 250.0 && sd < 4.0 {
                    out.push(Violation::new("INPUT_TIMING", format!("keystroke interval mean {mean:.0}ms sd {sd:.1}ms")));
                }
            }
        }
        out
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::report::Violation;
    pub fn start_input_monitor() {}
    pub fn diagnostics() -> super::InputDiagnostics { super::InputDiagnostics::default() }
    pub fn input_anomalies() -> Vec<Violation> {
        Vec::new()
    }
}
