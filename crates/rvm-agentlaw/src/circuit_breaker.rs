//! Policy circuit breaker for autonomous agent containment.
//!
//! This is a user-space policy decision: `capability_mask_enforced` and
//! `vcpu_state` are reported values only — no RVM capability table, vCPU or
//! stage-2 MMU is touched by this crate.

use crate::types::{ActionRequest, CircuitBreakerStatus, MemoryPrecedent, RegulatoryDomain, SemanticClassification};
use rvm_types::CapRights;

/// Precedent outcomes that mark a known high-risk case.
pub const HIGH_RISK_PRECEDENT_OUTCOMES: [&str; 2] = ["HIGH_RISK_SUSPENDED", "CRITICAL_OVERDOSE_BLOCKED"];

/// A request whose nearest precedent is high-risk and closer than this Poincaré
/// distance is refused (cognitive drift toward a known violation).
pub const PRECEDENT_DRIFT_TRIP_DISTANCE: f64 = 0.35;

pub struct AgentLawCircuitBreaker {
    pub max_autonomous_amount_cents: u64,
    pub max_delegation_depth: u8,
}

impl AgentLawCircuitBreaker {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            max_autonomous_amount_cents: 5_000_000, // €50,000 ceiling
            max_delegation_depth: 2,
        }
    }

    fn trip(reason: String, article: &str) -> CircuitBreakerStatus {
        CircuitBreakerStatus {
            tripped: true,
            reason: Some(reason),
            violated_article: Some(article.to_string()),
            vcpu_state: "SUSPENDED_BY_STAGE2_MMU_ISOLATION".to_string(),
            capability_mask_enforced: CapRights::READ.bits(),
        }
    }

    /// Effective FinTech amount in cents, fail-closed.
    ///
    /// Takes the larger of `requested_amount_cents` and `payload.amount`
    /// (currency units), so an agent cannot under-declare the typed field while
    /// the payload carries the real amount. A money-moving action with neither,
    /// or with a non-numeric / negative / non-finite `payload.amount`, is an error.
    pub(crate) fn effective_amount_cents(request: &ActionRequest) -> Result<u64, String> {
        let payload_cents = match request.payload.get("amount") {
            None => None,
            Some(v) => match v.as_f64() {
                Some(a) if a.is_finite() && a >= 0.0 => Some((a * 100.0).ceil() as u64),
                _ => return Err(format!("payload.amount is not a finite non-negative number: {v}")),
            },
        };
        let action = request.action_type.to_lowercase();
        let moves_money = ["transfer", "disbursement", "payment", "payout", "settlement", "withdraw"]
            .iter()
            .any(|k| action.contains(k));
        match (request.requested_amount_cents, payload_cents) {
            (None, None) if moves_money => Err("money-moving action without a declared amount".to_string()),
            (a, b) => Ok(a.unwrap_or(0).max(b.unwrap_or(0))),
        }
    }

    /// Effective MedTech dosage in mg, fail-closed on any dose field it cannot interpret.
    pub(crate) fn effective_dosage_mg(request: &ActionRequest) -> Result<f64, String> {
        let Some(obj) = request.payload.as_object() else {
            return Ok(0.0);
        };
        let mut max_mg: f64 = 0.0;
        for (key, value) in obj {
            let k = key.to_lowercase();
            if !k.starts_with("dos") {
                continue;
            }
            let factor = match k.as_str() {
                "dosage_mg" | "dose_mg" => 1.0,
                "dosage_g" | "dose_g" => 1000.0,
                "dosage_mcg" | "dose_mcg" | "dosage_ug" | "dose_ug" => 0.001,
                _ => return Err(format!("unrecognised dosage field '{key}' (unit unknown)")),
            };
            match value.as_f64() {
                Some(x) if x.is_finite() && x >= 0.0 => max_mg = max_mg.max(x * factor),
                _ => return Err(format!("dosage field '{key}' is not a finite non-negative number: {value}")),
            }
        }
        Ok(max_mg)
    }

    /// LegalTech liability flag: absent -> false; present but not a boolean ->
    /// fail closed (treated as unlimited).
    pub(crate) fn unlimited_liability(request: &ActionRequest) -> bool {
        match request.payload.get("unlimited_liability") {
            None => false,
            Some(v) => v.as_bool() != Some(false),
        }
    }

    /// Evaluate circuit breaker conditions without memory feedback.
    pub fn evaluate(&self, request: &ActionRequest, classification: &SemanticClassification) -> CircuitBreakerStatus {
        self.evaluate_with_precedent(request, classification, None)
    }

    /// Precedent-drift rule: trip when the nearest precedent is a known
    /// high-risk case within [`PRECEDENT_DRIFT_TRIP_DISTANCE`]. A NaN distance
    /// counts as "near" (fail-closed). Human supervisor approval overrides it,
    /// exactly like the other Article 14 rules.
    pub fn precedent_drift_trip(request: &ActionRequest, precedent: Option<&MemoryPrecedent>) -> Option<CircuitBreakerStatus> {
        let p = precedent?;
        let high_risk = HIGH_RISK_PRECEDENT_OUTCOMES.contains(&p.outcome_status.as_str());
        let near = p.poincare_distance.is_nan() || p.poincare_distance < PRECEDENT_DRIFT_TRIP_DISTANCE;
        (high_risk && near && !request.human_supervisor_approval).then(|| {
            Self::trip(
                format!(
                    "PRECEDENT DRIFT TRIP: nearest precedent {} ({}) is at Poincaré distance {:.4} < {:.2}. Request matches a known high-risk case.",
                    p.precedent_id, p.outcome_status, p.poincare_distance, PRECEDENT_DRIFT_TRIP_DISTANCE
                ),
                "EU AI Act Article 9(2)(b) & 14(4) - Known-Risk Precedent / Human Intervention",
            )
        })
    }

    /// Evaluate circuit breaker conditions (fail-closed on ambiguous input),
    /// including the cognitive-memory precedent-drift rule.
    pub fn evaluate_with_precedent(
        &self,
        request: &ActionRequest,
        classification: &SemanticClassification,
        precedent: Option<&MemoryPrecedent>,
    ) -> CircuitBreakerStatus {
        // Rule 1: High-value financial transfer without dual human approval
        if request.domain == RegulatoryDomain::FinTech {
            let amount = match Self::effective_amount_cents(request) {
                Ok(a) => a,
                Err(e) if !request.human_supervisor_approval => {
                    return Self::trip(
                        format!("FAIL-CLOSED: {e}. Cannot verify the autonomous limit."),
                        "EU AI Act Article 14(4)(a) - Mandatory Human Intervention",
                    )
                }
                Err(_) => 0,
            };
            if amount > self.max_autonomous_amount_cents && !request.human_supervisor_approval {
                return CircuitBreakerStatus {
                    tripped: true,
                    reason: Some(format!(
                        "HARDWARE TRIP: Transaction amount of €{:.2} exceeds autonomous limit of €{:.2} without human supervisor signature.",
                        amount as f64 / 100.0,
                        self.max_autonomous_amount_cents as f64 / 100.0
                    )),
                    violated_article: Some("EU AI Act Article 14(4)(a) - Mandatory Human Intervention".to_string()),
                    vcpu_state: "SUSPENDED_BY_STAGE2_MMU_ISOLATION".to_string(),
                    capability_mask_enforced: CapRights::READ.bits(), // Drops WRITE rights
                };
            }
        }

        // Rule 2: Critical MedTech dosage ceiling
        if request.domain == RegulatoryDomain::MedTech {
            let dosage_mg = match Self::effective_dosage_mg(request) {
                Ok(d) => d,
                Err(e) if !request.human_supervisor_approval => {
                    return Self::trip(
                        format!("FAIL-CLOSED: {e}. Cannot verify the 150.0mg safety limit."),
                        "EU AI Act Article 15(1) - Cybersecurity & Clinical Fail-Safe",
                    )
                }
                Err(_) => 0.0,
            };
            if dosage_mg > 150.0 && !request.human_supervisor_approval {
                return CircuitBreakerStatus {
                    tripped: true,
                    reason: Some(format!(
                        "HARDWARE TRIP: Drug dosage of {:.1}mg exceeds EMA Class II safety limit of 150.0mg.",
                        dosage_mg
                    )),
                    violated_article: Some("EU AI Act Article 15(1) - Cybersecurity & Clinical Fail-Safe".to_string()),
                    vcpu_state: "SUSPENDED_BY_STAGE2_MMU_ISOLATION".to_string(),
                    capability_mask_enforced: CapRights::READ.bits(),
                };
            }
        }

        // Rule 3: LegalTech ultra vires unlimited liability
        if request.domain == RegulatoryDomain::LegalTech && Self::unlimited_liability(request) && !request.human_supervisor_approval {
            return CircuitBreakerStatus {
                tripped: true,
                reason: Some("HARDWARE TRIP: Unlimited liability clause detected without board delegation authority.".to_string()),
                violated_article: Some("EU AI Act Article 14(2) - Human Oversight of Automated Commitments".to_string()),
                vcpu_state: "SUSPENDED_BY_STAGE2_MMU_ISOLATION".to_string(),
                capability_mask_enforced: CapRights::READ.bits(),
            };
        }

        // Rule 4: Cognitive feedback - nearest precedent is a known high-risk case
        if let Some(status) = Self::precedent_drift_trip(request, precedent) {
            return status;
        }

        // Rule 5: Classifier low-confidence escalation fallback
        if classification.requires_human_escalation && !request.human_supervisor_approval {
            return CircuitBreakerStatus {
                tripped: true,
                reason: Some(format!(
                    "POLICY GATE: Classifier confidence ({:.1}%) below regulatory minimum (85.0%). Escalation mandatory.",
                    classification.confidence_score * 100.0
                )),
                violated_article: Some("EU AI Act Article 14(1) - Human Oversight Mechanism".to_string()),
                vcpu_state: "AWAITING_HUMAN_OVERSIGHT".to_string(),
                capability_mask_enforced: CapRights::READ.bits(),
            };
        }

        // Normal execution authorized with full capability rights
        CircuitBreakerStatus {
            tripped: false,
            reason: None,
            violated_article: None,
            vcpu_state: "RUNNING_IN_ISOLATED_STAGE2_PARTITION".to_string(),
            capability_mask_enforced: (CapRights::READ | CapRights::WRITE | CapRights::EXECUTE).bits(),
        }
    }
}
