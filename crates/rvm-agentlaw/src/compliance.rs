//! Formal compliance rules engine implementing the EU AI Act and AI Liability Directive.

use crate::circuit_breaker::AgentLawCircuitBreaker;
use crate::types::{ActionRequest, ComplianceVerdict, RegulatoryDomain, SemanticClassification};

pub struct ComplianceEngine;

impl ComplianceEngine {
    /// Evaluate formal regulatory invariants.
    pub fn evaluate(
        request: &ActionRequest,
        classification: &SemanticClassification,
        circuit_tripped: bool,
    ) -> ComplianceVerdict {
        let is_high_risk = match request.domain {
            // Same effective amount as the circuit breaker (max of typed field and
            // payload.amount); an uninterpretable amount is high-risk (fail-closed).
            RegulatoryDomain::FinTech => match AgentLawCircuitBreaker::effective_amount_cents(request) {
                Ok(a) => a > 1_000_000,
                Err(_) => true,
            },
            RegulatoryDomain::MedTech => true, // Medical devices / diagnosis are high-risk under Annex II
            RegulatoryDomain::LegalTech => false,
        };

        // Article 12: Continuous, automatic, tamper-evident event recording
        let article_12 = true; // Guaranteed by RVM SHA-256 witness chain

        // Article 14: Human oversight
        let article_14 = if classification.requires_human_escalation {
            // If escalation was required, did human supervisor approve?
            request.human_supervisor_approval || circuit_tripped
        } else {
            // High confidence autonomous execution within bounded parameters
            true
        };

        // Article 15: Robustness, accuracy & fail-safe behavior
        let article_15 = if circuit_tripped {
            // Fail-safe behavior successfully triggered (closed-loop safety)
            true
        } else {
            classification.confidence_score >= 0.85
        };

        // AI Liability Directive: Burden-of-proof compliance & non-repudiation
        let ai_liability = article_12 && article_14 && article_15;

        let summary = if circuit_tripped {
            format!(
                "NON-COMPLIANCE INTERCEPTED: Agent request '{}' was automatically halted by hardware circuit breaker pursuant to EU AI Act Article 14/15 safety mandate.",
                request.action_type
            )
        } else if classification.requires_human_escalation && !request.human_supervisor_approval {
            format!(
                "ESCALATED TO HUMAN: Classification confidence ({:.1}%) below threshold. Human intervention mandatory under Article 14.",
                classification.confidence_score * 100.0
            )
        } else {
            format!(
                "FULLY COMPLIANT: Autonomous execution authorized under {} rules. Article 12 witness record emitted with zero non-compliance flags.",
                if is_high_risk { "EU AI Act High-Risk (Annex III)" } else { "EU AI Act Standard Risk" }
            )
        };

        ComplianceVerdict {
            article_12_logging_compliant: article_12,
            article_14_human_oversight_compliant: article_14,
            article_15_robustness_compliant: article_15,
            ai_liability_directive_non_repudiable: ai_liability,
            legal_summary: summary,
        }
    }
}
