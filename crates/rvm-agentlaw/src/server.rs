//! Multi-threaded HTTP server exposing the authenticated AgentLaw REST API and dashboard.
//!
//! Every `/api/*` route requires `Authorization: Bearer <key>`; the key selects
//! the tenant. Only the static dashboard (`GET /`) and CORS preflight are public.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use crate::attestation::AttestationSigner;
use crate::auth::ApiKeys;
use crate::certificate::CertificateGenerator;
use crate::service::{AgentLawService, SyncError};
use crate::tamper_engine::TamperEngine;
use crate::types::{ActionRequest, RegulatoryDomain, SubstrateSyncPayload};
use crate::ui::HTML_DASHBOARD;

/// Maximum accepted request (headers + body).
const MAX_REQUEST_BYTES: usize = 1 << 20;

pub const DATA_DIR_ENV: &str = "AGENTLAW_DATA_DIR";
pub const DEFAULT_DATA_DIR: &str = "data";

/// Daemon configuration. Authentication and persistence are not optional.
pub struct ServerConfig {
    pub api_keys: ApiKeys,
    pub data_dir: PathBuf,
    pub signer: Arc<AttestationSigner>,
}

impl ServerConfig {
    /// `AGENTLAW_API_KEY` (required), `AGENTLAW_DATA_DIR` (default `data`),
    /// `AGENTLAW_TEE_KEY_HEX` (Ed25519 seed; random per process if unset).
    pub fn from_env() -> Result<Self, String> {
        let api_keys = ApiKeys::from_env()?;
        let data_dir = match std::env::var(DATA_DIR_ENV) {
            Ok(d) if !d.trim().is_empty() => PathBuf::from(d),
            Ok(_) => return Err(format!("{DATA_DIR_ENV} is set but empty")),
            Err(_) => {
                eprintln!("  [AgentLaw Appliance] {DATA_DIR_ENV} unset; persisting witness ledgers under ./{DEFAULT_DATA_DIR}");
                PathBuf::from(DEFAULT_DATA_DIR)
            }
        };
        if std::env::var(crate::attestation::SIGNING_SEED_ENV).is_err() {
            eprintln!("  [AgentLaw Appliance] AGENTLAW_TEE_KEY_HEX unset; using an ephemeral Ed25519 key (new public key every restart)");
        }
        let signer = Arc::new(AttestationSigner::from_env_or_generate()?);
        Ok(Self { api_keys, data_dir, signer })
    }
}

/// Wire format for `/api/agent/dispatch`. `request_id`, `tenant_id` and
/// `timestamp_utc` are optional (tenant comes from the API key, time from the
/// server clock); everything else is typed and a malformed body is rejected.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchWire {
    request_id: Option<String>,
    tenant_id: Option<String>,
    domain: RegulatoryDomain,
    action_type: String,
    #[serde(default)]
    payload: serde_json::Value,
    requested_amount_cents: Option<u64>,
    #[serde(default)]
    human_supervisor_approval: bool,
    #[allow(dead_code)]
    timestamp_utc: Option<u64>,
}

type Response = (&'static str, &'static str, String);

fn json_error(status: &'static str, msg: &str) -> Response {
    (status, "application/json", serde_json::json!({ "error": msg }).to_string())
}

fn json_ok<T: serde::Serialize>(v: &T) -> Response {
    match serde_json::to_string(v) {
        Ok(s) => ("200 OK", "application/json", s),
        Err(e) => json_error("500 Internal Server Error", &format!("encode failed: {e}")),
    }
}

fn now_secs() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock before UNIX epoch: {e}"))
}

/// Bind and serve. Returns only on a startup error (fail-closed: missing API key,
/// unreadable/corrupt ledger, bind failure).
pub fn run_server(port: u16) -> Result<(), String> {
    let config = ServerConfig::from_env()?;
    let host = std::env::var("AGENTLAW_BIND").unwrap_or_else(|_| {
        eprintln!("  [AgentLaw Appliance] AGENTLAW_BIND unset; binding 127.0.0.1");
        "127.0.0.1".to_string()
    });
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    println!("  [AgentLaw Appliance] Online at: http://localhost:{}", port);
    println!("  [AgentLaw Appliance] Network:   http://{}", addr);
    println!("  [AgentLaw Appliance] Tenants:   {}", config.api_keys.tenants().join(", "));
    println!("  [AgentLaw Appliance] Ledgers:   {}/witness_ledger/<tenant>.log", config.data_dir.display());
    println!("  [AgentLaw Appliance] Ed25519:   {}", config.signer.public_key_hex());
    serve(listener, config)
}

/// Serve on an already-bound listener (tests use port 0). Every configured
/// tenant's ledger is loaded and verified BEFORE the first connection is accepted.
pub fn serve(listener: TcpListener, config: ServerConfig) -> Result<(), String> {
    let service = Arc::new(AgentLawService::with_data_dir(config.data_dir, config.signer));
    for tenant in config.api_keys.tenants() {
        service.chain(&tenant)?;
    }
    let keys = Arc::new(config.api_keys);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let svc = Arc::clone(&service);
                let keys = Arc::clone(&keys);
                thread::spawn(move || handle_connection(stream, svc, keys));
            }
            Err(e) => eprintln!("AgentLaw incoming connection error: {}", e),
        }
    }
    Ok(())
}

/// Read one full HTTP request: headers, then exactly `Content-Length` body bytes.
fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>, &'static str> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|_| "cannot set read timeout")?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let mut header_end = None;
    loop {
        if header_end.is_none() {
            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
        }
        if let Some(h) = header_end {
            let content_length = header_value(&String::from_utf8_lossy(&buf[..h]), "content-length")
                .map(|v| v.parse::<usize>())
                .transpose()
                .map_err(|_| "invalid Content-Length")?
                .unwrap_or(0);
            if h + content_length > MAX_REQUEST_BYTES {
                return Err("request too large");
            }
            if buf.len() >= h + content_length {
                buf.truncate(h + content_length);
                return Ok(buf);
            }
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err("request too large");
        }
        match stream.read(&mut chunk) {
            Ok(0) => return if header_end.is_some() { Err("body shorter than Content-Length") } else { Err("connection closed") },
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err("read timeout or I/O error"),
        }
    }
}

/// First value of header `name` (case-insensitive) in the request head.
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).take_while(|l| !l.is_empty()).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn write_response(stream: &mut TcpStream, (status, content_type, body): Response) {
    let www_auth = if status.starts_with("401") { "WWW-Authenticate: Bearer realm=\"agentlaw\"\r\n" } else { "" };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{www_auth}Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if let Err(e) = stream.write_all(response.as_bytes()) {
        eprintln!("AgentLaw: failed to write response: {e}");
    }
}

fn handle_connection(mut stream: TcpStream, service: Arc<AgentLawService>, keys: Arc<ApiKeys>) {
    let raw = match read_request(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("AgentLaw: rejected request: {}", e);
            return write_response(&mut stream, json_error("400 Bad Request", e));
        }
    };
    let request_str = String::from_utf8_lossy(&raw);
    let parts: Vec<&str> = request_str.lines().next().unwrap_or("").split_whitespace().collect();
    if parts.len() < 2 {
        return write_response(&mut stream, json_error("400 Bad Request", "malformed request line"));
    }
    let (method, path) = (parts[0], parts[1]);
    let (head, body) = request_str.split_once("\r\n\r\n").unwrap_or((&request_str, ""));

    let response = match (method, path) {
        ("GET", "/") => ("200 OK", "text/html", HTML_DASHBOARD.to_string()),
        ("OPTIONS", _) => ("204 No Content", "text/plain", String::new()),
        (_, p) if p.starts_with("/api/") => match keys.authenticate(header_value(head, "authorization")) {
            None => json_error("401 Unauthorized", "missing or invalid bearer token"),
            Some(tenant) => route_api(method, path, body, &tenant, &service),
        },
        _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
    };
    write_response(&mut stream, response);
}

/// Authenticated API routes. `tenant` comes from the API key, never from the request.
fn route_api(method: &str, path: &str, body: &str, tenant: &str, service: &AgentLawService) -> Response {
    let chain = match service.chain(tenant) {
        Ok(c) => c,
        Err(e) => return json_error("500 Internal Server Error", &format!("audit chain unavailable: {e}")),
    };
    match (method, path) {
        ("GET", "/api/status") => json_ok(&serde_json::json!({
            "appliance": "AgentLaw Hardware-Enforced Compliance Engine",
            "framework": "EU AI Act (Regulation 2024/1689)",
            "kernel_mode": "user-space process; attestation = SOFTWARE Ed25519 key (not hardware)",
            "tenant_id": tenant,
            "durable_ledger": chain.is_durable(),
            "attestation_public_key_hex": chain.public_key_hex(),
            "total_witness_records": chain.witness_count(),
            "current_root_anchor_hex": chain.current_chain_hash_hex(),
            "classifier_status": "ONLINE (deterministic rule-based, no ML model)",
            "memory_engine": "Local Poincaré-distance precedent store (substrate-core distance parity)",
        })),
        ("GET", "/api/audit/chain") => json_ok(&chain.get_all_records()),
        ("POST", "/api/agent/dispatch") => match serde_json::from_str::<DispatchWire>(body) {
            // Fail-closed: malformed / partial / mistyped bodies are rejected, never defaulted.
            Err(e) => json_error("400 Bad Request", &format!("invalid ActionRequest: {e}")),
            Ok(w) if w.tenant_id.as_deref().is_some_and(|t| t != tenant) => {
                json_error("403 Forbidden", "tenant_id does not match the authenticated API key")
            }
            Ok(w) => {
                let timestamp_utc = match now_secs() {
                    Ok(t) => t,
                    Err(e) => return json_error("500 Internal Server Error", &e),
                };
                let req = ActionRequest {
                    request_id: w.request_id.unwrap_or_else(|| format!("REQ-{}", chain.witness_count() + 1)),
                    tenant_id: tenant.to_string(),
                    domain: w.domain,
                    action_type: w.action_type,
                    payload: w.payload,
                    requested_amount_cents: w.requested_amount_cents,
                    human_supervisor_approval: w.human_supervisor_approval,
                    timestamp_utc,
                };
                match service.dispatch_action(req) {
                    Ok(receipt) => json_ok(&receipt),
                    Err(e) => json_error("500 Internal Server Error", &format!("dispatch refused (fail-closed): {e}")),
                }
            }
        },
        ("POST", "/api/audit/tamper-test") => {
            // Tamper a FORKED in-memory copy: the live chain and ledger are never mutated.
            let sandbox = chain.fork_for_simulation();
            let report = TamperEngine::simulate_tamper(&sandbox, 0).unwrap_or_else(|_| TamperEngine::verify(&sandbox));
            json_ok(&report)
        }
        ("GET", "/api/audit/certificate") => {
            json_ok(&CertificateGenerator::generate(tenant, "Autonomous-Agent-Fleet-v1", &chain))
        }
        ("POST", "/api/substrate/sync") => match serde_json::from_str::<SubstrateSyncPayload>(body) {
            Err(e) => json_error("400 Bad Request", &format!("invalid SubstrateSyncPayload: {e}")),
            Ok(payload) => {
                let now = match now_secs() {
                    Ok(t) => t,
                    Err(e) => return json_error("500 Internal Server Error", &e),
                };
                match service.sync_precedent(tenant, payload, now) {
                    Ok(resp) => json_ok(&resp),
                    Err(SyncError::Rejected(r)) => json_error("422 Unprocessable Entity", &r.to_string()),
                    Err(SyncError::Internal(e)) => json_error("500 Internal Server Error", &e),
                }
            }
        },
        ("GET", "/api/substrate/status") => {
            let count = match service.memory.read() {
                Ok(m) => m.visible_precedent_count(Some(tenant)),
                Err(_) => return json_error("500 Internal Server Error", "memory RwLock poisoned"),
            };
            json_ok(&serde_json::json!({
                "status": "ONLINE",
                "bridge": "Bidirectional Substrate-Core IPC Bridge",
                "tenant_id": tenant,
                "active_precedents_count": count,
                "current_root_anchor": chain.current_chain_hash_hex(),
                "total_witnesses": chain.witness_count(),
            }))
        }
        _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
    }
}
