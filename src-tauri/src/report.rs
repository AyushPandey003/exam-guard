use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Clone, Debug)]
pub struct Violation {
    pub code: String,
    pub detail: String,
}

impl Violation {
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.to_string(), detail: detail.into() }
    }
}

#[derive(Serialize)]
struct Payload<'a> {
    agent_version: &'static str,
    nonce: &'a str,
    seq: u64,
    ts: u64,
    ok: bool,
    violations: &'a [Violation],
}

/// `payload` is the exact JSON string that was signed; the server must verify
/// HMAC-SHA256(session_key, payload) == sig, then check nonce, monotonic seq
/// and timestamp freshness. Missing heartbeats = agent killed = lock exam.
#[derive(Serialize)]
pub struct Signed {
    pub ok: bool,
    pub payload: String,
    pub sig: String,
}

pub fn sign(key: &[u8], nonce: &str, seq: u64, violations: &[Violation]) -> Signed {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let ok = violations.is_empty();
    let payload = serde_json::to_string(&Payload { agent_version: env!("CARGO_PKG_VERSION"), nonce, seq, ts, ok, violations }).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(payload.as_bytes());
    Signed { ok, payload, sig: hex::encode(mac.finalize().into_bytes()) }
}
