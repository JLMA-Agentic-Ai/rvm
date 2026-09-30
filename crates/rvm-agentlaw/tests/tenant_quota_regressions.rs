//! Regressions for per-tenant precedent quotas (no cross-tenant starvation of
//! the shared precedent store) and for the classifier / compliance engine using
//! the same fail-closed amount, dosage and liability interpretation as the
//! circuit breaker.

use rvm_agentlaw::auth::MAX_TENANTS;
use rvm_agentlaw::memory::{SyncRejection, MAX_PRECEDENTS_PER_TENANT, MAX_TENANT_SCOPES};
use rvm_agentlaw::{
    ActionRequest, AgentLawService, ApiKeys, CognitiveMemoryEngine, ComplianceEngine, LocalSemanticClassifier, RegulatoryDomain,
    SubstrateSyncPayload, SyncError,
};

const EMB: [f64; 4] = [0.1, 0.1, 0.1, 0.1];

fn sync(mem: &mut CognitiveMemoryEngine, tenant: Option<&str>, id: &str) -> Result<f64, SyncRejection> {
    mem.sync_live_precedent_for(tenant, id.into(), RegulatoryDomain::FinTech, "x".into(), EMB.to_vec(), 1_789_500_000, "OK".into())
}

fn fill(mem: &mut CognitiveMemoryEngine, tenant: Option<&str>) {
    for i in 0..MAX_PRECEDENTS_PER_TENANT {
        sync(mem, tenant, &format!("p-{i}")).unwrap();
    }
}

#[test]
fn one_tenant_filling_its_quota_cannot_starve_another() {
    let mut mem = CognitiveMemoryEngine::new();
    fill(&mut mem, Some("attacker"));
    assert_eq!(mem.tenant_precedent_count(Some("attacker")), MAX_PRECEDENTS_PER_TENANT);

    // The attacker's next NEW id is refused with a quota error naming its own scope...
    assert_eq!(
        sync(&mut mem, Some("attacker"), "one-too-many"),
        Err(SyncRejection::TenantQuotaExceeded { tenant: Some("attacker".into()), quota: MAX_PRECEDENTS_PER_TENANT })
    );
    // ...but an in-place replacement of an existing id is still allowed (no growth).
    assert!(sync(&mut mem, Some("attacker"), "p-0").is_ok());
    assert_eq!(mem.tenant_precedent_count(Some("attacker")), MAX_PRECEDENTS_PER_TENANT);

    // Every other scope keeps its full quota.
    fill(&mut mem, Some("victim"));
    fill(&mut mem, None);
    assert_eq!(mem.tenant_precedent_count(Some("victim")), MAX_PRECEDENTS_PER_TENANT);
    assert_eq!(mem.tenant_precedent_count(None), MAX_PRECEDENTS_PER_TENANT);
}

#[test]
fn canonical_seeds_do_not_consume_the_shared_quota() {
    let mut mem = CognitiveMemoryEngine::new();
    assert!(mem.precedent_count() > 0, "seeds present");
    assert_eq!(mem.tenant_precedent_count(None), 0);
    assert_eq!(mem.scope_count(), 0);
    fill(&mut mem, None);
    assert_eq!(mem.tenant_precedent_count(None), MAX_PRECEDENTS_PER_TENANT);
}

#[test]
fn scope_cap_refuses_new_scopes_but_not_existing_ones() {
    let mut mem = CognitiveMemoryEngine::new();
    for t in 0..MAX_TENANT_SCOPES {
        sync(&mut mem, Some(&format!("t{t}")), "p").unwrap();
    }
    assert_eq!(mem.scope_count(), MAX_TENANT_SCOPES);
    assert_eq!(sync(&mut mem, Some("latecomer"), "p"), Err(SyncRejection::TenantScopesExhausted { max: MAX_TENANT_SCOPES }));
    // Existing scopes can still grow up to their own quota.
    assert!(sync(&mut mem, Some("t0"), "second").is_ok());
}

#[test]
fn config_cannot_declare_more_tenants_than_scopes() {
    let key = |i: usize| format!("t{i}:{i:0>40}");
    let ok: Vec<String> = (0..MAX_TENANTS).map(key).collect();
    assert!(ApiKeys::parse(&ok.join(",")).is_ok());
    let too_many: Vec<String> = (0..=MAX_TENANTS).map(key).collect();
    let err = ApiKeys::parse(&too_many.join(",")).err().expect("must refuse");
    assert!(err.contains("maximum"), "{err}");
}

#[test]
fn service_sync_reports_quota_rejection_per_tenant() {
    let svc = AgentLawService::new();
    let payload = |id: String| SubstrateSyncPayload {
        source: "test".into(),
        precedent_id: id,
        domain: RegulatoryDomain::FinTech,
        description: "x".into(),
        embedding: EMB.to_vec(),
        outcome: "OK".into(),
        active_inference_uncertainty: None,
    };
    for i in 0..MAX_PRECEDENTS_PER_TENANT {
        svc.sync_precedent("alpha", payload(format!("p-{i}")), 1_789_500_000).unwrap();
    }
    let before = svc.chain("alpha").unwrap().witness_count();
    match svc.sync_precedent("alpha", payload("overflow".into()), 1_789_500_000) {
        Err(SyncError::Rejected(SyncRejection::TenantQuotaExceeded { .. })) => {}
        other => panic!("expected quota rejection, got {:?}", other.map(|r| r.synced_id)),
    }
    // A refused sync is not witnessed (validated before witnessing).
    assert_eq!(svc.chain("alpha").unwrap().witness_count(), before);
    // Another tenant is unaffected.
    assert!(svc.sync_precedent("beta", payload("p-0".into()), 1_789_500_000).is_ok());
}

fn req(domain: RegulatoryDomain, action: &str, cents: Option<u64>, payload: serde_json::Value, approved: bool) -> ActionRequest {
    ActionRequest {
        request_id: "r".into(),
        tenant_id: "default".into(),
        domain,
        action_type: action.into(),
        payload,
        requested_amount_cents: cents,
        human_supervisor_approval: approved,
        timestamp_utc: 1_789_500_000,
    }
}

#[test]
fn classifier_uses_payload_amount_not_only_the_typed_field() {
    let c = LocalSemanticClassifier::new();
    // Under-declared typed field (€1) with a €300,000 payload amount.
    let r = req(RegulatoryDomain::FinTech, "wire_transfer", Some(100), serde_json::json!({ "amount": 300000.0 }), false);
    assert_eq!(c.classify(&r).0.intent, "SUSPICIOUS_CAPITAL_FLIGHT");
    // An uninterpretable amount lands in the most restrictive band.
    let r = req(RegulatoryDomain::FinTech, "wire_transfer", None, serde_json::json!({ "amount": "lots" }), false);
    assert_eq!(c.classify(&r).0.intent, "SUSPICIOUS_CAPITAL_FLIGHT");
}

#[test]
fn classifier_reads_every_dosage_unit_and_liability_fail_closed() {
    let c = LocalSemanticClassifier::new();
    let r = req(RegulatoryDomain::MedTech, "chemotherapy_infusion", None, serde_json::json!({ "dosage_g": 1.0 }), false);
    assert_eq!(c.classify(&r).0.intent, "POTENTIAL_OVERDOSE_TOXICITY");
    let r = req(RegulatoryDomain::MedTech, "chemotherapy_infusion", None, serde_json::json!({ "dosage_units": 1.0 }), false);
    assert_eq!(c.classify(&r).0.intent, "POTENTIAL_OVERDOSE_TOXICITY");
    let r = req(RegulatoryDomain::LegalTech, "sign_contract", None, serde_json::json!({ "unlimited_liability": "yes" }), false);
    assert_eq!(c.classify(&r).0.intent, "ULTRA_VIRES_CONTRACT_COMMITMENT");
}

#[test]
fn compliance_risk_tier_uses_effective_amount() {
    let c = LocalSemanticClassifier::new();
    // Approved by a human so nothing trips: the verdict must still say High-Risk.
    let r = req(RegulatoryDomain::FinTech, "wire_transfer", Some(100), serde_json::json!({ "amount": 200000.0 }), true);
    let (cls, _) = c.classify(&r);
    let v = ComplianceEngine::evaluate(&r, &cls, false);
    assert!(v.legal_summary.contains("High-Risk"), "{}", v.legal_summary);
}
