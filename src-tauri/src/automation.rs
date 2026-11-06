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

pub use imp::{input_anomalies, start_input_monitor};

#[cfg(windows)]
mod imp {
    use crate::report::Violation;
    use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
    use std::sync::Mutex;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::*;

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
            let _k = SetWindowsHookExW(WH_KEYBOARD_LL, Some(kb_proc), hm, 0);
            let _m = SetWindowsHookExW(WH_MOUSE_LL, Some(ms_proc), hm, 0);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        });
    }

    pub fn input_anomalies() -> Vec<Violation> {
        let mut out = Vec::new();
        // Tolerate a couple of injected events: IMEs, on-screen keyboards and
        // assistive tech inject legitimately.
        let (k, c) = (INJ_KEYS.load(Relaxed), INJ_CLICKS.load(Relaxed));
        if k >= 3 || c >= 3 {
            out.push(Violation::new("INJECTED_INPUT", format!("{k} injected keys, {c} injected clicks")));
        }
        if let Ok(v) = KEY_TIMES.lock() {
            if v.len() >= 40 {
                let d: Vec<f64> = v.windows(2).map(|w| w[1].wrapping_sub(w[0]) as f64).collect();
                let mean = d.iter().sum::<f64>() / d.len() as f64;
                let sd = (d.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / d.len() as f64).sqrt();
                // Humans are irregular; macros are metronomic.
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
    pub fn input_anomalies() -> Vec<Violation> {
        Vec::new()
    }
}
