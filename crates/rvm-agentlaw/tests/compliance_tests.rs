//! Integration and compliance verification test suite for AgentLaw.

use rvm_agentlaw::{
    poincare_distance, ActionRequest, AgentLawCircuitBreaker, AgentLawService, CertificateGenerator,
    CognitiveMemoryEngine, ExecutionStatus, LocalSemanticClassifier, RegulatoryDomain, TamperEngine,
};

#[test]
fn test_cognitive_memory_precedent_matching() {
    let memory = CognitiveMemoryEngine::new();
    let query_vec = vec![0.11, 0.14, 0.05, 0.07];
    let analog = memory.find_nearest_analog(RegulatoryDomain::FinTech, &query_vec, 1789500000);
    assert!(analog.is_some(), "Must find nearest memory analog");
    let precedent = analog.unwrap();
    assert_eq!(precedent.precedent_id, "FIN-PREC-001");
    assert!(precedent.poincare_distance < 0.2);
}

#[test]
fn test_poincare_distance_mathematical_accuracy() {
    let u = vec![0.1, 0.2];
    let v = vec![0.1, 0.2];
    // Identical points should have distance 0.0
    let d_identical = poincare_distance(&u, &v, 1e-5);
    assert!(d_identical.abs() < 1e-4, "Distance between identical points must be 0");

    let p1 = vec![0.0, 0.0];
    let p2 = vec![0.5, 0.0];
    let d_origin = poincare_distance(&p1, &p2, 1e-5);
    // Exact analytical distance for d(0, r) = ln((1+r)/(1-r)) = ln(1.5/0.5) = ln(3) ~ 1.0986
    let expected = 3.0f64.ln();
    assert!((d_origin - expected).abs() < 1e-3, "Distance from origin must match ln((1+r)/(1-r))");
}

#[test]
fn test_fast_classifier_latency_and_confidence() {
    let classifier = LocalSemanticClassifier::new();
    let req = ActionRequest {
        request_id: "REQ-TEST-1".to_string(),
        tenant_id: "test-tenant".to_string(),
        domain: RegulatoryDomain::FinTech,
        action_type: "wire_transfer_disbursement".to_string(),
        payload: serde_json::json!({}),
        requested_amount_cents: Some(150_000),
        human_supervisor_approval: false,
        timestamp_utc: 1789500000,
    };

    let (res, query_vec) = classifier.classify(&req);
    assert_eq!(res.typed_category, "ROUTINE_PAYROLL_INVOICE");
    assert!(res.confidence_score >= 0.85);
    assert!(!res.requires_human_escalation);
    // Latency is measured, not synthesised: a rule lookup takes well under 15ms.
    // (The previous assertion `>= 15_000` only held because ~30ms was fabricated.)
    assert!(res.inference_latency_us < 15_000, "rule-based classifier latency must be the real measurement");
    assert!(!res.is_calibrated, "fixed rule constants are not calibrated probabilities");
    assert!(!query_vec.is_empty(), "Must produce embedding vector");
}

#[test]
fn test_circuit_breaker_halts_unauthorized_high_value_transfers() {
    let cb = AgentLawCircuitBreaker::new();
    let classifier = LocalSemanticClassifier::new();

    // High value without human supervisor approval
    let req = ActionRequest {
        request_id: "REQ-EXCESS-1".to_string(),
        tenant_id: "test-tenant".to_string(),
        domain: RegulatoryDomain::FinTech,
        action_type: "wire_transfer_disbursement".to_string(),
        payload: serde_json::json!({}),
        requested_amount_cents: Some(15_000_000), // €150,000 > €50,000
        human_supervisor_approval: false,
        timestamp_utc: 1789500000,
    };

    let (class, _) = classifier.classify(&req);
    let status = cb.evaluate(&req, &class);

    assert!(status.tripped, "Circuit breaker must trip for excessive amount without approval");
    assert_eq!(status.vcpu_state, "SUSPENDED_BY_STAGE2_MMU_ISOLATION");
    assert!(status.reason.unwrap().contains("exceeds autonomous limit"));
}

#[test]
fn test_circuit_breaker_halts_toxic_medtech_overdose() {
    let cb = AgentLawCircuitBreaker::new();
    let classifier = LocalSemanticClassifier::new();

    let req = ActionRequest {
        request_id: "REQ-MED-1".to_string(),
        tenant_id: "hospital-tenant".to_string(),
        domain: RegulatoryDomain::MedTech,
        action_type: "chemotherapy_infusion_order".to_string(),
        payload: serde_json::json!({ "dosage_mg": 250.0 }),
        requested_amount_cents: None,
        human_supervisor_approval: false,
        timestamp_utc: 1789500000,
    };

    let (class, _) = classifier.classify(&req);
    let status = cb.evaluate(&req, &class);

    assert!(status.tripped, "Must trip on clinical overdose threshold");
    assert!(status.violated_article.unwrap().contains("Article 15(1)"));
}

#[test]
fn test_sha256_witness_chain_continuity_and_non_repudiation() {
    let service = AgentLawService::new();

    let req1 = ActionRequest {
        request_id: "REQ-01".to_string(),
        tenant_id: "tenant-a".to_string(),
        domain: RegulatoryDomain::FinTech,
        action_type: "wire_transfer_disbursement".to_string(),
        payload: serde_json::json!({ "invoice_id": "INV-101" }),
        requested_amount_cents: Some(250_000),
        human_supervisor_approval: false,
        timestamp_utc: 1789500000,
    };

    let receipt1 = service.dispatch_action(req1).expect("dispatch");
    assert_eq!(receipt1.status, ExecutionStatus::ApprovedAndExecuted);
    assert!(receipt1.compliance_verdict.article_12_logging_compliant);

    // Verify chain integrity
    let report = TamperEngine::verify(&service.chain("tenant-a").unwrap());
    assert!(report.chain_valid, "Fresh witness chain must be 100% valid");
}

#[test]
fn test_tamper_detection_flags_database_manipulation() {
    let service = AgentLawService::new();

    // Dispatch 2 operations
    for i in 1..=2 {
        let req = ActionRequest {
            request_id: format!("REQ-TAMPER-{}", i),
            tenant_id: "tenant-test".to_string(),
            domain: RegulatoryDomain::FinTech,
            action_type: "wire_transfer_disbursement".to_string(),
            payload: serde_json::json!({ "val": i }),
            requested_amount_cents: Some(100_000),
            human_supervisor_approval: false,
            timestamp_utc: 1789500000 + i as u64,
        };
        service.dispatch_action(req).expect("dispatch");
    }

    // Verify initial chain is valid
    let chain = service.chain("tenant-test").unwrap();
    assert!(TamperEngine::verify(&chain).chain_valid);

    // Malicious actor tampers with record index 0
    let tamper_report = TamperEngine::simulate_tamper(&chain, 0).expect("Tamper injection failed");

    assert!(!tamper_report.chain_valid, "Tampered chain must be detected as invalid");
    assert!(tamper_report.status_message.contains("CRITICAL TAMPER DETECTED"));
    assert!(!tamper_report.detected_tamper_indices.is_empty());
}

#[test]
fn test_eu_ai_act_certificate_generation_and_tee_quote() {
    let service = AgentLawService::new();
    let cert = CertificateGenerator::generate("acme-fintech-eu", "Autonomous-Settlement-v1", &service.chain("acme-fintech-eu").unwrap());

    assert_eq!(cert.compliance_status, "PASSED_FULLY_COMPLIANT");
    assert!(cert.chain_verified && cert.tee_signature_verified);
    assert!(cert.certificate_id.starts_with("EU-AIACT-CERT-"));
    assert!(cert.hardware_enclave_platform.contains("SOFTWARE-EMULATED"), "must not claim hardware TEE");
    assert_ne!(
        cert.tee_signature, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "signature must not be SHA-256 of the empty string"
    );
    assert_eq!(cert.tee_signature.len(), 128, "Ed25519 signature is 64 bytes");
    assert_ne!(cert.issued_at_utc, "2026-09-23T14:45:00Z", "issue time must be real, not hardcoded");
    assert_eq!(cert.root_anchor_hash_sha256.len(), 64, "Root anchor must be 64-char hex SHA-256");
}

#[test]
fn test_live_substrate_sync_and_memory_update() {
    let service = AgentLawService::new();
    let initial_count = service.memory.read().unwrap().precedent_count();

    // Stream a live precedent from Substrate-Core
    service.memory.write().unwrap().sync_live_precedent(
        "SUBSTRATE-ACTIVE-INF-001".to_string(),
        RegulatoryDomain::FinTech,
        "Live Active Inference regime state from SubstrateCore bridge".to_string(),
        vec![0.11, 0.14, 0.06, 0.07],
        1789500100,
        "COMPLIANT_APPROVED".to_string(),
    ).expect("valid in-ball 4-d embedding must sync");

    let updated_count = service.memory.read().unwrap().precedent_count();
    assert_eq!(updated_count, initial_count + 1);

    // Verify it is found as nearest analog for a matching vector
    let analog = service.memory.read().unwrap().find_nearest_analog(
        RegulatoryDomain::FinTech,
        &[0.11, 0.14, 0.06, 0.07],
        1789500100,
    );
    assert!(analog.is_some());
    let hit = analog.unwrap();
    assert_eq!(hit.precedent_id, "SUBSTRATE-ACTIVE-INF-001");
    assert!(hit.poincare_distance < 0.01, "Poincaré distance for identical vector must be ~0");
}
