# ExamGuard native agent (Tauri 2 + Rust)

Enforcer layer for the proctoring stack. Runs on the candidate's machine, checks the environment, and sends HMAC-signed reports to your server.

## What it does

| Check | How | Platforms |
|---|---|---|
| VM detection | guest-tool processes, SMBIOS strings (registry / `/sys/class/dmi`), guest-driver registry keys, CPUID hypervisor bit + vendor, `kern.hv_vmm_present` | Win / macOS / Linux |
| RDP / remote control | `SM_REMOTESESSION`, `WTSClientProtocolType`, blacklist (AnyDesk, TeamViewer, Chrome Remote Desktop, Parsec, RustDesk, VNC, ...) | Windows (full), others partial |
| Automation | macro/auto-clicker process blacklist, `python`/`node` command lines referencing pyautogui/pynput/..., low-level keyboard + mouse hooks flagging **injected** events (`LLKHF_INJECTED` / `LLMHF_INJECTED`) and metronomic keystroke timing | Windows |
| Screen capture blocking | `set_content_protected(true)` → `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on Windows, `NSWindow.sharingType = none` on macOS; recorder process blacklist | Win / macOS |
| Tamper evidence | per-session `key` + `nonce` from your server; every 2s a signed heartbeat with monotonic `seq` | all |

## Server contract

1. On exam start your server issues `{key, nonce}` over TLS.
2. Page calls `start_session(key, nonce)`; agent returns a signed report (seq 0). Unlock the exam only if the server verifies `HMAC-SHA256(key, payload) == sig` and `ok == true`.
3. Heartbeats arrive as `guard:report` events. The server must check signature, nonce, increasing `seq`, fresh `ts`. **A missing heartbeat means the agent was killed: lock the exam.**

## Review dashboard and staff accounts

Requires Node 22+ (uses built-in `node:sqlite`; no npm install).

```
cd server
node create-user.js alice "a-long-passphrase"    # 12+ chars; run again to reset a password
node verify.js                                    # then open http://localhost:3000/dashboard
```

Sessions, violation events, reviews and staff accounts live in SQLite (`examguard.db`). Passwords are scrypt-hashed, login tokens are random, stored only as hashes and expire after 8 hours, and logins are throttled to 5 failures per 15 minutes per IP. Locked sessions sort first with recent violations; a reviewer can **Clear** (false positive, unlocks the session) or **Confirm**, and a note is required. Each decision records the reviewer's name. A server restart no longer loses sessions; live sessions get a short grace period so agents can reconnect before the heartbeat watchdog fires.

**Before production:** serve over HTTPS (reverse proxy), put the dashboard on an internal network or behind your VPN/SSO, back up the `.db` file, and run behind a process manager. The throttle uses the socket IP, so configure your proxy accordingly.

## Code signing

Sign release builds so candidates see a verified publisher and the OS/AV doesn't flag the agent as unknown software.
- Windows: set `bundle.windows.certificateThumbprint` (an EV or OV code-signing cert installed on the build machine) in `tauri.conf.json`.
- macOS: set `bundle.macOS.signingIdentity` to your Developer ID Application identity, then notarize (`APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` env vars).
- Publish a checksum of each release and have the exam page refuse to start if the agent version it reports is below your minimum.

## Build

```
cargo install tauri-cli --version "^2"
cd exam-guard && cargo tauri icon path/to/logo.png   # generates required icons
cargo tauri dev        # or: cargo tauri build
```

## Known limits (read before relying on it)

- **Bypassable by a determined user.** A user-mode agent can be run under a debugger, have its checks patched, or be given a spoofed environment (hardened VMs hide CPUID/SMBIOS; a second physical machine or capture card defeats screen protection; hardware HID emulators defeat injected-input checks). Treat it as raising cost, and combine with webcam/AI review and server-side behavioral signals.
- **The webview relays reports.** Currently the page forwards the signed reports, so a tampered page can drop them. Better: have the agent POST directly to your server (add `reqwest`) so the page never touches the report path.
- **False positives:** Windows with VBS/Memory Integrity reports a hypervisor even on bare metal (handled: only flagged if SMBIOS says "Virtual Machine"); IMEs, on-screen keyboards and assistive tech inject input legitimately (hence the threshold of 3). Provide a human-review path rather than silently failing candidates, and disclose to candidates exactly what is monitored (consent/privacy law).
- Cmdline scanning only sees scripts launched with the library name visible in args.
- **Test status:** `server/test.js` passes (signature, replay, stale timestamp, outdated agent, heartbeat loss, reviewer override). The detection modules compile and run on Linux (they correctly flag a KVM guest). The Windows-only code (registry, WTS, input hooks) and the full Tauri build have **not** been compiled; run `cargo tauri build` on Windows first and expect small fixes against `windows = "0.58"`.

## Server settings

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port |
| `DB_PATH` | `server/examguard.db` | SQLite database file |
| `MIN_AGENT_VERSION` | `0.1.0` | Sessions reporting an older `agent_version` are locked |
| `AUDIT_LOG` | `server/audit.jsonl` | Append-only log of locks, logins and reviewer decisions |

Run the checks with `node server/test.js`.
