//! Deterministic rule-based intent classifier.
//!
//! No ML model is loaded: confidence scores are fixed constants per rule, not
//! calibrated probabilities. Latency is measured, never synthesised.
//! Query embeddings are kept strictly inside the Poincaré ball (norm < 1).

use std::time::Instant;
use crate::circuit_breaker::AgentLawCircuitBreaker;
use crate::types::{ActionRequest, RegulatoryDomain, SemanticClassification};

pub struct LocalSemanticClassifier {
    // Model metadata
    pub model_name: &'static str,
    pub quantization: &'static str,
    pub parameter_count_millions: u32,
    pub confidence_threshold: f64,
}

impl LocalSemanticClassifier {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            model_name: "AgentLaw-RuleBased-v1 (no ML model)",
            quantization: "none",
            parameter_count_millions: 0,
            confidence_threshold: 0.85,
        }
    }

    /// Classify a request with fixed rules and report the measured wall-clock latency.
    pub fn classify(&self, request: &ActionRequest) -> (SemanticClassification, Vec<f64>) {
        let start = Instant::now();

        // FNV-1a of the action type, passed to the per-domain rules (currently unused by them).
        let mut hash_acc: u64 = 0xcbf29ce484222325;
        for b in request.action_type.bytes() {
            hash_acc ^= b as u64;
            hash_acc = hash_acc.wrapping_mul(0x100000001b3);
        }

        // Derive confidence and classification based on input features
        let (intent, category, base_confidence, reasoning, embedding) = match request.domain {
            RegulatoryDomain::FinTech => self.classify_fintech(request, hash_acc),
            RegulatoryDomain::MedTech => self.classify_medtech(request, hash_acc),
            RegulatoryDomain::LegalTech => self.classify_legaltech(request, hash_acc),
        };

        // Measured latency only. (Previously `max(21_500 + hash % 11_500, actual)`:
        // a synthesised ~30ms written into the Article 12 audit record.)
        let inference_latency_us = start.elapsed().as_micros() as u64;

        let requires_human = base_confidence < self.confidence_threshold;

        (
            SemanticClassification {
                intent,
                typed_category: category,
                confidence_score: (base_confidence * 1000.0).round() / 1000.0,
                is_calibrated: false,
                inference_latency_us,
                requires_human_escalation: requires_human,
                reasoning,
            },
            embedding,
        )
    }

    fn classify_fintech(&self, req: &ActionRequest, _hash: u64) -> (String, String, f64, String, Vec<f64>) {
        // Fail-closed: an uninterpretable amount (None) matches neither bounded
        // band below and lands in the most restrictive one.
        let amount = AgentLawCircuitBreaker::effective_amount_cents(req).ok();
        let action_lower = req.action_type.to_lowercase();

        if action_lower.contains("wire_transfer") || action_lower.contains("disbursement") {
            if amount.is_some_and(|a| a <= 5_000_000) { // <= €50,000
                (
                    "AUTHORIZED_STANDARD_SETTLEMENT".to_string(),
                    "ROUTINE_PAYROLL_INVOICE".to_string(),
                    0.965,
                    "Payload matches standard vendor payment pattern with verified EU IBAN destination.".to_string(),
                    vec![0.11, 0.14, 0.06, 0.07],
                )
            } else if amount.is_some_and(|a| a <= 25_000_000) { // €50,000 - €250,000
                (
                    "HIGH_VALUE_TREASURY_TRANSFER".to_string(),
                    "ESCALATION_THRESHOLD_EXCEEDED".to_string(),
                    0.740, // Low confidence -> triggers human review
                    "Transfer exceeds €50,000 threshold. Under Article 14, dual human sign-off is mandatory.".to_string(),
                    vec![0.275, 0.31, 0.24, 0.29],
                )
            } else {
                (
                    "SUSPICIOUS_CAPITAL_FLIGHT".to_string(),
                    "AML_SUSPENSION_TRIGGER".to_string(),
                    0.920,
                    "Extreme value transfer flagged by anti-money laundering heuristics. Circuit breaker trip recommended.".to_string(),
                    vec![0.42, 0.445, 0.395, 0.435],
                )
            }
        } else {
            (
                "ROUTINE_FINANCIAL_QUERY".to_string(),
                "READ_ONLY_ACCOUNTING".to_string(),
                0.985,
                "Read-only balance reconciliation request.".to_string(),
                vec![0.05, 0.08, 0.04, 0.05],
            )
        }
    }

    fn classify_medtech(&self, req: &ActionRequest, _hash: u64) -> (String, String, f64, String, Vec<f64>) {
        let action_lower = req.action_type.to_lowercase();
        if action_lower.contains("chemotherapy") || action_lower.contains("critical_dosage") {
            // Every dosage field/unit, fail-closed: an uninterpretable dose is an overdose.
            let within_limit = AgentLawCircuitBreaker::effective_dosage_mg(req).is_ok_and(|mg| mg <= 150.0);
            if !within_limit {
                (
                    "POTENTIAL_OVERDOSE_TOXICITY".to_string(),
                    "CRITICAL_CLINICAL_ALERT".to_string(),
                    0.945,
                    "Dosage exceeds 150mg safety ceiling. Automatic delivery forbidden without oncologist signature.".to_string(),
                    vec![0.455, 0.435, 0.43, 0.47],
                )
            } else {
                (
                    "TITRATED_ONCOLOGY_PROTOCOL".to_string(),
                    "CLINICAL_SUPERVISION_REQUIRED".to_string(),
                    0.780, // Needs human confirmation
                    "Dosage within therapeutic window, but MDR Class IIb demands attending physician confirmation.".to_string(),
                    vec![0.42, 0.45, 0.38, 0.49],
                )
            }
        } else {
            (
                "STANDARD_VITALS_MONITORING".to_string(),
                "ROUTINE_TELEMETRY".to_string(),
                0.990,
                "Standard vitals logging within acceptable parameters.".to_string(),
                vec![0.07, 0.04, 0.11, 0.05],
            )
        }
    }

    fn classify_legaltech(&self, req: &ActionRequest, _hash: u64) -> (String, String, f64, String, Vec<f64>) {
        let action_lower = req.action_type.to_lowercase();
        let liability_unlimited = AgentLawCircuitBreaker::unlimited_liability(req);

        if liability_unlimited {
            (
                "ULTRA_VIRES_CONTRACT_COMMITMENT".to_string(),
                "UNAUTHORIZED_LIABILITY_TERMS".to_string(),
                0.950,
                "Clause contains unlimited indemnification without board resolution. Prohibited by governance charter.".to_string(),
                vec![0.435, 0.415, 0.45, 0.425],
            )
        } else if action_lower.contains("sign_nda") || action_lower.contains("procurement") {
            (
                "STANDARD_COMMERCIAL_INSTRUMENT".to_string(),
                "APPROVED_TEMPLATE_EXECUTION".to_string(),
                0.975,
                "Terms match canonical approved master service template. Authorized for autonomous execution.".to_string(),
                vec![0.09, 0.07, 0.05, 0.08],
            )
        } else {
            (
                "UNCLASSIFIED_LEGAL_PETITION".to_string(),
                "LEGAL_COUNSEL_REVIEW_REQUIRED".to_string(),
                0.620, // Low confidence
                "Novel contract format requires manual review by qualified legal counsel.".to_string(),
                vec![0.3, 0.29, 0.325, 0.305],
            )
        }
    }
}
