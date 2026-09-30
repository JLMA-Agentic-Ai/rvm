//! Regressions for the four architectural hardening items:
//! 1. durable witness ledger, 2. Ed25519 attestation, 3. precedent-drift trip,
//! 4. bearer auth + tenant-isolated chains.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rvm_agentlaw::circuit_breaker::PRECEDENT_DRIFT_TRIP_DISTANCE;
use rvm_agentlaw::{
    serve, ActionRequest, AgentLawCircuitBreaker, AgentLawService, MemoryPrecedent, ApiKeys, AttestationSigner, CertificateGenerator, ExecutionStatus,
    RegulatoryDomain, ServerConfig, SubstrateSyncPayload, TamperEngine,
};

fn tmp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("agentlaw-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn routine(tenant: &str, id: &str) -> ActionRequest {
    ActionRequest {
        request_id: id.into(),
        tenant_id: tenant.into(),
        domain: RegulatoryDomain::FinTech,
        action_type: "wire_transfer_disbursement".into(),
        payload: serde_json::json!({ "amount": 4500.0 }),
        requested_amount_cents: Some(450_000),
        human_supervisor_approval: false,
        timestamp_utc: 1_789_500_000,
    }
}

fn signer() -> Arc<AttestationSigner> {
    Arc::new(AttestationSigner::generate().unwrap())
}

fn hexd(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Independent third-party check: only the public key, message and signature.
fn third_party_verify(pk_hex: &str, msg_hex: &str, sig_hex: &str) -> bool {
    let pk: [u8; 32] = hexd(pk_hex).try_into().unwrap();
    let sig: [u8; 64] = hexd(sig_hex).try_into().unwrap();
    VerifyingKey::from_bytes(&pk).unwrap().verify(&hexd(msg_hex), &Signature::from_bytes(&sig)).is_ok()
}

// ------------------------------------------------------------- 1. persistence

#[test]
fn ledger_survives_restart_and_continues_the_chain() {
    let dir = tmp_dir("persist");
    let key = signer();
    let (tip, count) = {
        let svc = AgentLawService::with_data_dir(&dir, Arc::clone(&key));
        svc.dispatch_action(routine("acme", "A1")).unwrap();
        svc.dispatch_action(routine("acme", "A2")).unwrap();
        let c = svc.chain("acme").unwrap();
        assert!(c.is_durable());
        (c.current_chain_hash_hex(), c.witness_count())
    };
    assert_eq!(count, 4, "2 genesis + 2 dispatches");
    assert!(dir.join("witness_ledger/acme.log").exists());

    // "Restart": a fresh service with a DIFFERENT signing key reloads the history.
    let svc = AgentLawService::with_data_dir(&dir, signer());
    let c = svc.chain("acme").unwrap();
    assert_eq!(c.witness_count(), count, "history must survive restart");
    assert_eq!(c.current_chain_hash_hex(), tip);
    assert!(TamperEngine::verify(&c).chain_valid);
    let r = svc.dispatch_action(routine("acme", "A3")).unwrap();
    assert_eq!(r.witness_record.sequence, 5, "sequence continues after reload");
    assert_eq!(r.witness_record.prev_hash_hex, tip);
    assert!(TamperEngine::verify(&c).chain_valid);
}

fn tampered_reload(edit: impl Fn(String) -> String) -> Result<(), String> {
    let dir = tmp_dir("tamper");
    {
        let svc = AgentLawService::with_data_dir(&dir, signer());
        svc.dispatch_action(routine("acme", "T1")).unwrap();
    }
    let path = dir.join("witness_ledger/acme.log");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, edit(text)).unwrap();
    AgentLawService::with_data_dir(&dir, signer()).chain("acme").map(|_| ())
}

#[test]
fn tampered_or_torn_ledger_refuses_to_load() {
    // Rewriting the verdict label (action_name is now bound into record_hash).
    let e = tampered_reload(|t| t.replacen("AUTHORIZED_EXECUTION_", "CIRCUIT_BREAKER_HALT_", 1)).unwrap_err();
    assert!(e.contains("record_hash mismatch"), "{e}");
    // Altered payload.
    let e = tampered_reload(|t| {
        let mut lines: Vec<String> = t.lines().map(String::from).collect();
        let mut rec: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        rec["payload_hex"] = serde_json::Value::String("00".into());
        lines[2] = rec.to_string();
        lines.join("\n") + "\n"
    })
    .unwrap_err();
    assert!(e.contains("record_hash mismatch"), "{e}");
    // Deleted middle record.
    let e = tampered_reload(|t| {
        let lines: Vec<&str> = t.lines().collect();
        format!("{}\n{}\n", lines[0], lines[2])
    })
    .unwrap_err();
    assert!(e.contains("not contiguous"), "{e}");
    // Torn final line (crash mid-write).
    let e = tampered_reload(|t| t[..t.len() - 10].to_string()).unwrap_err();
    assert!(e.contains("torn"), "{e}");
    // Forged signature.
    let e = tampered_reload(|t| {
        let mut lines: Vec<String> = t.lines().map(String::from).collect();
        let mut rec: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        rec["signature_hex"] = serde_json::Value::String("11".repeat(64));
        lines[0] = rec.to_string();
        lines.join("\n") + "\n"
    })
    .unwrap_err();
    assert!(e.contains("signature invalid"), "{e}");
}

// ------------------------------------------------------------- 2. Ed25519

#[test]
fn certificate_and_receipts_verify_with_public_key_only() {
    let svc = AgentLawService::new();
    let receipt = svc.dispatch_action(routine("acme", "E1")).unwrap();
    let att = &receipt.tee_attestation;
    assert!(att.verified);
    assert_eq!(att.signature_hex.len(), 128);
    assert!(third_party_verify(&att.public_key_hex, &att.signed_payload_hex, &att.signature_hex));
    assert!(att.signed_payload_hex.contains(&receipt.witness_record.chain_hash_hex), "signature binds the chain hash");

    let cert = CertificateGenerator::generate("acme", "fleet", &svc.chain("acme").unwrap());
    assert_eq!(cert.public_key_hex, svc.public_key_hex());
    assert!(third_party_verify(&cert.public_key_hex, &cert.signed_payload_hex, &cert.tee_signature));
    assert!(cert.signed_payload_hex.contains(&cert.root_anchor_hash_sha256));
    assert!(rvm_agentlaw::verify_attestation_hex(&cert.public_key_hex, &cert.signed_payload_hex, &cert.tee_signature));

    // Any altered byte fails; a different key fails.
    let mut forged = hexd(&cert.signed_payload_hex);
    *forged.last_mut().unwrap() ^= 1;
    let forged_hex: String = forged.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!third_party_verify(&cert.public_key_hex, &forged_hex, &cert.tee_signature));
    assert!(!rvm_agentlaw::verify_attestation_hex(&signer().public_key_hex(), &cert.signed_payload_hex, &cert.tee_signature));
    assert!(!rvm_agentlaw::verify_attestation_hex("zz", &cert.signed_payload_hex, &cert.tee_signature));
}

// ------------------------------------------------------------- 3. drift trip

fn sync(svc: &AgentLawService, tenant: &str, id: &str, emb: Vec<f64>, outcome: &str) {
    svc.sync_precedent(
        tenant,
        SubstrateSyncPayload {
            source: "test".into(),
            precedent_id: id.into(),
            domain: RegulatoryDomain::FinTech,
            description: "x".into(),
            embedding: emb,
            outcome: outcome.into(),
            active_inference_uncertainty: None,
        },
        1_789_500_000,
    )
    .unwrap();
}

#[test]
fn high_risk_precedent_near_query_trips_the_breaker() {
    let svc = AgentLawService::new();
    assert_eq!(svc.dispatch_action(routine("acme", "D0")).unwrap().status, ExecutionStatus::ApprovedAndExecuted);

    // Substrate-Core reports the routine-transfer region as a suspended AML pattern.
    sync(&svc, "acme", "AML-LIVE-1", vec![0.11, 0.14, 0.06, 0.07], "HIGH_RISK_SUSPENDED");
    let r = svc.dispatch_action(routine("acme", "D1")).unwrap();
    let p = r.memory_precedent.as_ref().unwrap();
    assert_eq!(p.precedent_id, "AML-LIVE-1");
    assert!(p.poincare_distance < PRECEDENT_DRIFT_TRIP_DISTANCE);
    assert_eq!(r.status, ExecutionStatus::RefusedByCircuitBreaker, "fail-closed on high-risk precedent drift");
    assert!(r.circuit_breaker.reason.as_deref().unwrap().contains("PRECEDENT DRIFT TRIP"));
    assert!(r.witness_record.action_name.starts_with("CIRCUIT_BREAKER_HALT_"));

    // Human supervisor approval overrides (Article 14), like every other rule.
    let mut approved = routine("acme", "D2");
    approved.human_supervisor_approval = true;
    assert!(!svc.dispatch_action(approved).unwrap().circuit_breaker.tripped);

    // Another tenant is not affected by acme's precedents.
    let other = svc.dispatch_action(routine("globex", "D3")).unwrap();
    assert_eq!(other.status, ExecutionStatus::ApprovedAndExecuted);
    assert_ne!(other.memory_precedent.unwrap().precedent_id, "AML-LIVE-1");
}

#[test]
fn benign_precedent_does_not_trip() {
    let svc = AgentLawService::new();
    // Benign outcome at the same point: nearest, but not high-risk.
    sync(&svc, "acme", "OK-1", vec![0.11, 0.14, 0.06, 0.07], "COMPLIANT_APPROVED");
    assert_eq!(svc.dispatch_action(routine("acme", "N1")).unwrap().status, ExecutionStatus::ApprovedAndExecuted);
}

#[test]
fn drift_rule_threshold_boundaries() {
    let mk = |d: f64, outcome: &str| MemoryPrecedent {
        precedent_id: "P".into(),
        description: String::new(),
        poincare_distance: d,
        recency_adjusted_score: d,
        temporal_weight: 1.0,
        outcome_status: outcome.into(),
        query_embedding: vec![],
        precedent_embedding: vec![],
    };
    let req = routine("acme", "B");
    let trips = |p: &MemoryPrecedent| AgentLawCircuitBreaker::precedent_drift_trip(&req, Some(p)).is_some();
    assert!(trips(&mk(0.0, "HIGH_RISK_SUSPENDED")));
    assert!(trips(&mk(0.3499, "CRITICAL_OVERDOSE_BLOCKED")));
    assert!(trips(&mk(f64::NAN, "HIGH_RISK_SUSPENDED")), "NaN distance fails closed");
    assert!(!trips(&mk(PRECEDENT_DRIFT_TRIP_DISTANCE, "HIGH_RISK_SUSPENDED")), "threshold is strict <");
    assert!(!trips(&mk(0.9, "HIGH_RISK_SUSPENDED")));
    assert!(!trips(&mk(0.0, "COMPLIANT_APPROVED")));
    assert!(AgentLawCircuitBreaker::precedent_drift_trip(&req, None).is_none());

    // Wired into the full evaluation, ahead of the normal approval.
    let (class, _) = rvm_agentlaw::LocalSemanticClassifier::new().classify(&req);
    let cb = AgentLawCircuitBreaker::new();
    assert!(!cb.evaluate(&req, &class).tripped);
    assert!(cb.evaluate_with_precedent(&req, &class, Some(&mk(0.1, "HIGH_RISK_SUSPENDED"))).tripped);
}

// ------------------------------------------------------------- 4. auth + tenancy

#[test]
fn api_key_config_fails_closed() {
    assert!(ApiKeys::parse("").is_err());
    assert!(ApiKeys::parse("short").is_err(), "short secret");
    assert!(ApiKeys::parse("../evil:0123456789abcdef0123456789abcdef").is_err(), "path traversal tenant");
    assert!(ApiKeys::parse("a:0123456789abcdef0123456789abcdef,b:0123456789abcdef0123456789abcdef").is_err(), "shared secret");
    let k = ApiKeys::parse("a:0123456789abcdef0123456789abcdefAA,b:0123456789abcdef0123456789abcdefBB").unwrap();
    assert_eq!(k.authenticate(Some("Bearer 0123456789abcdef0123456789abcdefBB")).as_deref(), Some("b"));
    assert_eq!(k.authenticate(Some("bearer 0123456789abcdef0123456789abcdefAA")).as_deref(), Some("a"));
    assert_eq!(k.authenticate(Some("Basic 0123456789abcdef0123456789abcdefAA")), None);
    assert_eq!(k.authenticate(Some("Bearer wrong")), None);
    assert_eq!(k.authenticate(None), None);
    let single = ApiKeys::parse("0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(single.tenants(), vec!["default".to_string()]);
}

const KEY_A: &str = "tenant-a-secret-0123456789abcdef0123456789";
const KEY_B: &str = "tenant-b-secret-0123456789abcdef0123456789";

fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: &str) -> (u16, serde_json::Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: t\r\n{auth}Content-Length: {}\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let json = out.split("\r\n\r\n").nth(1).and_then(|b| serde_json::from_str(b).ok()).unwrap_or_default();
    (out[9..12].parse().unwrap(), json)
}

#[test]
fn http_requires_bearer_and_isolates_tenant_chains() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = tmp_dir("http");
    let config = ServerConfig {
        api_keys: ApiKeys::parse(&format!("alpha:{KEY_A},beta:{KEY_B}")).unwrap(),
        data_dir: dir.clone(),
        signer: signer(),
    };
    std::thread::spawn(move || serve(listener, config).unwrap());

    let dispatch = r#"{"domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{"amount":10.0},"requested_amount_cents":1000}"#;
    for path in ["/api/status", "/api/audit/chain", "/api/audit/certificate", "/api/substrate/status"] {
        assert_eq!(http(port, "GET", path, None, "").0, 401, "{path} without token");
        assert_eq!(http(port, "GET", path, Some("not-a-valid-key"), "").0, 401, "{path} with bad token");
    }
    assert_eq!(http(port, "POST", "/api/agent/dispatch", None, dispatch).0, 401);
    assert_eq!(http(port, "POST", "/api/audit/tamper-test", None, "").0, 401);
    assert_eq!(http(port, "GET", "/", None, "").0, 200, "static dashboard stays public");

    // alpha dispatches 3 actions; beta none.
    for _ in 0..3 {
        let (code, r) = http(port, "POST", "/api/agent/dispatch", Some(KEY_A), dispatch);
        assert_eq!(code, 200);
        assert_eq!(r["tenant_id"], "alpha", "tenant comes from the key");
    }
    // Claiming another tenant in the body is forbidden.
    let spoof = r#"{"tenant_id":"beta","domain":"FinTech","action_type":"read_balance","payload":{}}"#;
    assert_eq!(http(port, "POST", "/api/agent/dispatch", Some(KEY_A), spoof).0, 403);

    let (_, a) = http(port, "GET", "/api/audit/chain", Some(KEY_A), "");
    let (_, b) = http(port, "GET", "/api/audit/chain", Some(KEY_B), "");
    assert_eq!(a.as_array().unwrap().len(), 5, "alpha: 2 genesis + 3 dispatches");
    assert_eq!(b.as_array().unwrap().len(), 2, "beta sees only its own genesis records");
    assert_ne!(a[0]["chain_hash_hex"], b[0]["chain_hash_hex"], "per-tenant genesis anchors");

    let (_, cert) = http(port, "GET", "/api/audit/certificate", Some(KEY_B), "");
    assert_eq!(cert["tenant_id"], "beta");
    assert_eq!(cert["total_decisions_audited"], 2);
    assert!(third_party_verify(
        cert["public_key_hex"].as_str().unwrap(),
        cert["signed_payload_hex"].as_str().unwrap(),
        cert["tee_signature"].as_str().unwrap()
    ));

    // Separate on-disk ledgers per tenant.
    let lines = |t: &str| std::fs::read_to_string(dir.join(format!("witness_ledger/{t}.log"))).unwrap().lines().count();
    assert_eq!((lines("alpha"), lines("beta")), (5, 2));
}

#[test]
fn missing_api_key_env_is_a_startup_error() {
    // Parsing the env var directly would race with other tests; exercise the same
    // code path through `parse` of the empty value and the typed error message.
    let err = ApiKeys::parse("   ").err().unwrap();
    assert!(err.contains("AGENTLAW_API_KEY"));
}
