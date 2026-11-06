use crate::report::Violation;
use sysinfo::System;

const REMOTE_TOOLS: &[&str] = &[
    "anydesk", "teamviewer", "tv_w32", "tv_x64", "remoting_host", "remoting_desktop",
    "parsecd", "pservice", "rustdesk", "ultraviewer", "splashtop", "srservice",
    "logmein", "lmiguardian", "ammyy", "vncviewer", "winvnc", "tvnserver", "tightvnc",
    "screenconnect", "supremo", "dwagent", "mstsc", "quickassist", "msra",
];

const RECORDERS: &[&str] = &[
    "obs64", "obs32", "obs-studio", "bandicam", "camtasia", "sharex", "screenrec",
    "flashbackrecorder", "snagit", "action_x64",
];

pub fn check(sys: &System) -> Vec<Violation> {
    let mut out = Vec::new();

    for p in sys.processes().values() {
        let name = p.name().to_lowercase();
        let name = name.trim_end_matches(".exe");
        if let Some(t) = REMOTE_TOOLS.iter().find(|t| name.contains(*t)) {
            out.push(Violation::new("REMOTE_TOOL", format!("{name} (matches '{t}')")));
        }
        if let Some(t) = RECORDERS.iter().find(|t| name.contains(*t)) {
            out.push(Violation::new("RECORDER", format!("{name} (matches '{t}')")));
        }
    }

    if rdp_session() {
        out.push(Violation::new("RDP_SESSION", "running inside a remote desktop session"));
    }
    out
}

#[cfg(windows)]
fn rdp_session() -> bool {
    use windows::Win32::System::RemoteDesktop::{
        WTSClientProtocolType, WTSFreeMemory, WTSQuerySessionInformationW,
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
    unsafe {
        if GetSystemMetrics(SM_REMOTESESSION) != 0 {
            return true;
        }
        // WTSClientProtocolType: 0 = console, 2 = RDP
        let mut buf = windows::core::PWSTR::null();
        let mut len = 0u32;
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSClientProtocolType,
            &mut buf,
            &mut len,
        )
        .is_ok()
        {
            let proto = *(buf.0 as *const u16);
            WTSFreeMemory(buf.0 as *mut _);
            return proto != 0;
        }
    }
    false
}

#[cfg(not(windows))]
fn rdp_session() -> bool {
    // Linux/macOS: SSH/X-forwarding/VNC are caught by the process list above.
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some()
}
