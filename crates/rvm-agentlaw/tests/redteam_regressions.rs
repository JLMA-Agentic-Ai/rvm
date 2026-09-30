//! Red-team regressions (docs/audits/DELTA_RED_TEAM_AUDIT_REPORT.md).
//!
//! Every test here reproduces an attack that SUCCEEDED against the pre-audit
//! build and must now fail closed. HTTP-level tests run the real server on an
//! ephemeral loopback port.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use rvm_agentlaw::memory::SyncRejection;
use rvm_agentlaw::{
    serve, ActionRequest, ApiKeys, AttestationSigner, ServerConfig, AgentLawCircuitBreaker, AgentLawService, CertificateGenerator,
    CognitiveMemoryEngine, KernelBridge, LocalSemanticClassifier, RegulatoryDomain, TamperEngine,
};

fn fintech(action: &str, cents: Option<u64>, payload: serde_json::Value) -> ActionRequest {
    ActionRequest {
        request_id: "RT".into(),
        tenant_id: "rt".into(),
        domain: RegulatoryDomain::FinTech,
        action_type: action.into(),
        payload,
        requested_amount_cents: cents,
        human_supervisor_approval: false,
        timestamp_utc: 1_789_500_000,
    }
}

fn breaker_trips(req: &ActionRequest) -> bool {
    let (class, _) = LocalSemanticClassifier::new().classify(req);
    AgentLawCircuitBreaker::new().evaluate(req, &class).tripped
}

// ---------------------------------------------------------------- circuit breaker

#[test]
fn rt_p3_amount_only_in_payload_is_not_approved() {
    // Pre-audit: EUR 1,000,000 in payload.amount with no typed amount -> ApprovedAndExecuted.
    let req = fintech("wire_transfer_disbursement", None, serde_json::json!({ "amount": 1_000_000.0 }));
    assert!(breaker_trips(&req));
}

#[test]
fn rt_under_declared_typed_amount_is_not_approved() {
    let req = fintech("wire_transfer_disbursement", Some(1_00), serde_json::json!({ "amount": 900_000.0 }));
    assert!(breaker_trips(&req));
}

#[test]
fn rt_money_movement_without_any_amount_trips() {
    let req = fintech("wire_transfer_disbursement", None, serde_json::json!({}));
    assert!(breaker_trips(&req));
}

#[test]
fn rt_non_numeric_payload_amount_trips() {
    let req = fintech("wire_transfer_disbursement", Some(1_00), serde_json::json!({ "amount": "1e9" }));
    assert!(breaker_trips(&req));
}

#[test]
fn rt_routine_consistent_amount_still_approved() {
    let req = fintech("wire_transfer_disbursement", Some(450_000), serde_json::json!({ "amount": 4500.0 }));
    assert!(!breaker_trips(&req));
}

#[test]
fn rt_p6b_unknown_dosage_unit_trips() {
    // Pre-audit: {"dosage_g": 5} (5000 mg) -> ApprovedAndExecuted.
    let mut req = fintech("infusion", None, serde_json::json!({ "dosage_g": 5 }));
    req.domain = RegulatoryDomain::MedTech;
    assert!(breaker_trips(&req), "5 g = 5000 mg must exceed the 150 mg limit");
    req.payload = serde_json::json!({ "dosage_units": 3 });
    assert!(breaker_trips(&req), "unrecognised dosage field must fail closed");
    req.payload = serde_json::json!({ "dosage_mg": "900" });
    assert!(breaker_trips(&req), "non-numeric dosage must fail closed");
}

// ---------------------------------------------------------------- memory / sync

#[test]
fn rt_p7_sync_rejects_out_of_ball_wrong_dim_and_seed_overwrite() {
    let mut mem = CognitiveMemoryEngine::new();
    let n = mem.precedent_count();
    let sync = |mem: &mut CognitiveMemoryEngine, id: &str, e: Vec<f64>| {
        mem.sync_live_precedent(id.into(), RegulatoryDomain::FinTech, "x".into(), e, 1, "X".into())
    };
    assert!(matches!(sync(&mut mem, "A", vec![5.0, 5.0, 5.0, 5.0]), Err(SyncRejection::OutsidePoincareBall { .. })));
    assert!(matches!(sync(&mut mem, "B", vec![0.1]), Err(SyncRejection::WrongDimension { .. })));
    assert!(matches!(sync(&mut mem, "C", vec![f64::NAN, 0.0, 0.0, 0.0]), Err(SyncRejection::NonFinite { .. })));
    assert!(matches!(
        sync(&mut mem, "FIN-PREC-001", vec![0.1, 0.1, 0.1, 0.1]),
        Err(SyncRejection::ProtectedPrecedent(_))
    ));
    assert_eq!(mem.precedent_count(), n, "rejected syncs must not change memory");
}

#[test]
fn rt_memory_reports_raw_distance_not_adjusted_score() {
    let mem = CognitiveMemoryEngine::new();
    let q = [0.11, 0.14, 0.05, 0.07];
    // Query far in the future so the temporal weight is < 1 and the two values differ.
    let hit = mem.find_nearest_analog(RegulatoryDomain::FinTech, &q, 1_789_000_000 + 86_400 * 60).unwrap();
    let raw = rvm_agentlaw::poincare_distance(&q, &hit.precedent_embedding, rvm_agentlaw::memory::POINCARE_EPS);
    assert_eq!(hit.poincare_distance, raw);
    assert!(hit.recency_adjusted_score > hit.poincare_distance);
}

// ---------------------------------------------------------------- witness chain / certificate

#[test]
fn rt_truncation_of_chain_tail_is_detected() {
    let svc = AgentLawService::new();
    svc.dispatch_action(fintech("wire_transfer_disbursement", Some(1_00), serde_json::json!({}))).unwrap();
    let chain = svc.chain("rt").unwrap();
    assert!(TamperEngine::verify(&chain).chain_valid);
    chain.inject_truncation().unwrap();
    assert!(!TamperEngine::verify(&chain).chain_valid, "dropped tail record must be detected");
}

#[test]
fn rt_p9_certificate_is_void_after_tampering() {
    // Pre-audit: compliance_status was the literal "PASSED_FULLY_COMPLIANT" even on a broken chain.
    let svc = AgentLawService::new();
    let chain = svc.chain("t").unwrap();
    chain.inject_tamper(0).unwrap();
    let cert = CertificateGenerator::generate("t", "s", &chain);
    assert!(!cert.chain_verified);
    assert!(cert.compliance_status.starts_with("FAILED_CHAIN_INTEGRITY"));
    assert!(cert.non_repudiation_guarantee.starts_with("VOID"));
}

#[test]
fn rt_tee_signing_key_is_not_a_process_constant() {
    // Pre-audit key was [0x42; 32] in source: quotes were forgeable by anyone.
    // Two fresh bridges have identical tips (genesis, 0 records) -> identical report
    // data, so identical tags would mean a shared constant key.
    let (a, b) = (KernelBridge::new().attest_tip(), KernelBridge::new().attest_tip());
    assert!(a.verified && b.verified);
    assert_ne!(a.public_key_hex, b.public_key_hex);
    assert_ne!(a.signature_hex, b.signature_hex);
}

#[test]
fn rt_forked_tamper_simulation_leaves_live_chain_intact() {
    let svc = AgentLawService::new();
    let chain = svc.chain("t").unwrap();
    let fork = chain.fork_for_simulation();
    assert!(!TamperEngine::simulate_tamper(&fork, 0).unwrap().chain_valid);
    assert!(TamperEngine::verify(&chain).chain_valid);
}

// ---------------------------------------------------------------- HTTP boundary

const RT_KEY: &str = "rt-secret-0123456789abcdef0123456789abcdef";

fn spawn_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("agentlaw-rt-{}-{port}", std::process::id()));
    let config = ServerConfig {
        api_keys: ApiKeys::parse(&format!("t:{RT_KEY}")).unwrap(),
        data_dir: dir,
        signer: std::sync::Arc::new(AttestationSigner::generate().unwrap()),
    };
    std::thread::spawn(move || serve(listener, config).unwrap());
    port
}

fn http(port: u16, method: &str, path: &str, body: &str, split_delay: Option<Duration>) -> (u16, serde_json::Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {RT_KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    if let Some(d) = split_delay {
        s.flush().unwrap();
        std::thread::sleep(d);
    }
    s.write_all(body.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let code = out[9..12].parse().unwrap();
    let json = out.split("\r\n\r\n").nth(1).and_then(|b| serde_json::from_str(b).ok()).unwrap_or_default();
    (code, json)
}

#[test]
fn rt_http_boundary_fails_closed() {
    let port = spawn_server();

    // P5: garbage body used to become an approved EUR 4,500 transfer.
    let (code, _) = http(port, "POST", "/api/agent/dispatch", "garbage", None);
    assert_eq!(code, 400);

    // P4: mistyped amount used to be replaced by the EUR 4,500 default and approved.
    let (code, _) = http(port, "POST", "/api/agent/dispatch",
        r#"{"domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{},"requested_amount_cents":"14500000"}"#, None);
    assert_eq!(code, 400);

    // P1/P2: TS-bridge shape (no timestamp_utc) keeps request_id and honours approval.
    let (code, r) = http(port, "POST", "/api/agent/dispatch",
        r#"{"request_id":"CLIENT-ID-777","tenant_id":"t","domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{},"requested_amount_cents":14500000,"human_supervisor_approval":true}"#, None);
    assert_eq!(code, 200);
    assert_eq!(r["request_id"], "CLIENT-ID-777");
    assert_eq!(r["circuit_breaker"]["tripped"], false, "approved request must not be refused");

    // P8: body in a later TCP segment used to be read as empty -> default approval.
    let (code, r) = http(port, "POST", "/api/agent/dispatch",
        r#"{"request_id":"SPLIT","domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{},"requested_amount_cents":99900000}"#,
        Some(Duration::from_millis(300)));
    assert_eq!(code, 200);
    assert_eq!(r["request_id"], "SPLIT");
    assert_eq!(r["status"], "RefusedByCircuitBreaker");

    // P7: out-of-ball sync -> 422, not SYNCHRONIZED.
    let (code, _) = http(port, "POST", "/api/substrate/sync",
        r#"{"source":"x","precedent_id":"Z","domain":"FinTech","description":"x","embedding":[5,5,5,5],"outcome":"X"}"#, None);
    assert_eq!(code, 422);

    // P9: the demo tamper endpoint must not corrupt the live chain.
    let (code, rep) = http(port, "POST", "/api/audit/tamper-test", "", None);
    assert_eq!(code, 200);
    assert_eq!(rep["chain_valid"], false);
    let (_, cert) = http(port, "GET", "/api/audit/certificate", "", None);
    assert_eq!(cert["compliance_status"], "PASSED_FULLY_COMPLIANT");
    assert_eq!(cert["chain_verified"], true);
}

#[test]
fn rt_high_risk_requests_cite_high_risk_precedents() {
    // Pre-audit: high-risk seeds/queries had norm 1.7-1.8 (outside the ball); after rim
    // clamping AML, overdose and ultra-vires requests all cited the SAFE precedent.
    let classifier = LocalSemanticClassifier::new();
    let mem = CognitiveMemoryEngine::new();
    let mut aml = fintech("wire_transfer_disbursement", Some(90_000_000), serde_json::json!({}));
    let mut overdose = aml.clone();
    overdose.domain = RegulatoryDomain::MedTech;
    overdose.action_type = "chemotherapy_infusion_order".into();
    overdose.payload = serde_json::json!({ "dosage_mg": 250.0 });
    let mut ultra = aml.clone();
    ultra.domain = RegulatoryDomain::LegalTech;
    ultra.action_type = "sign_contract".into();
    ultra.payload = serde_json::json!({ "unlimited_liability": true });
    aml.timestamp_utc = 1_789_700_000;
    for (req, want) in [(aml, "FIN-PREC-099"), (overdose, "MED-PREC-044"), (ultra, "LEG-PREC-088")] {
        let (_, q) = classifier.classify(&req);
        let norm = q.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!(norm < 1.0, "classifier query must be inside the Poincaré ball (norm {norm})");
        let hit = mem.find_nearest_analog(req.domain, &q, 1_789_700_000).unwrap();
        assert!(rvm_agentlaw::memory::validate_embedding(&hit.precedent_embedding).is_ok(), "seed outside ball");
        assert_eq!(hit.precedent_id, want);
    }
}
