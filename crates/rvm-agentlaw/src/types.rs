//! Data types and schemas for the AgentLaw compliance engine.

use serde::{Deserialize, Serialize};

/// Regulated business domain governed by the EU AI Act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegulatoryDomain {
    /// High-risk financial systems (AML, credit, automated settlement)
    FinTech,
    /// Critical healthcare & clinical decision support systems
    MedTech,
    /// Automated contracting, procurement, and legal delegation
    LegalTech,
}

impl RegulatoryDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FinTech => "FinTech",
            Self::MedTech => "MedTech",
            Self::LegalTech => "LegalTech",
        }
    }

    pub fn eu_ai_act_classification(&self) -> &'static str {
        match self {
            Self::FinTech => "High-Risk System (Annex III, Section 5 - Essential Public & Financial Services)",
            Self::MedTech => "High-Risk Medical Device / Clinical Diagnostic System (Annex II / MDR)",
            Self::LegalTech => "Specific Risk / Binding Legal Commitment Automation (Article 12/14/50)",
        }
    }
}

/// Incoming action request submitted to an autonomous agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub domain: RegulatoryDomain,
    pub action_type: String,
    pub payload: serde_json::Value,
    pub requested_amount_cents: Option<u64>,
    pub human_supervisor_approval: bool,
    pub timestamp_utc: u64,
}

/// Local rule-based classifier output (deterministic, no ML model).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticClassification {
    pub intent: String,
    pub typed_category: String,
    pub confidence_score: f64,
    pub is_calibrated: bool,
    pub inference_latency_us: u64,
    pub requires_human_escalation: bool,
    pub reasoning: String,
}

/// Cognitive memory precedent hit (Poincaré hyperbolic distance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPrecedent {
    pub precedent_id: String,
    pub description: String,
    /// Raw Poincaré geodesic distance d_H(query, precedent), unrounded.
    pub poincare_distance: f64,
    /// Ranking score actually used: distance / max(temporal_weight, 0.1).
    pub recency_adjusted_score: f64,
    pub temporal_weight: f64,
    pub outcome_status: String,
    pub query_embedding: Vec<f64>,
    pub precedent_embedding: Vec<f64>,
}

/// Status of the RVM hardware-enforced circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStatus {
    pub tripped: bool,
    pub reason: Option<String>,
    pub violated_article: Option<String>,
    pub vcpu_state: String,
    pub capability_mask_enforced: u8,
}

/// Cryptographic witness record view emitted by RVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRecordView {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub action_kind: u8,
    pub action_name: String,
    pub partition_id: u16,
    pub record_hash_hex: String,
    pub prev_hash_hex: String,
    pub chain_hash_hex: String,
    pub is_tampered: bool,
}

/// Overall execution result of an agent task governed by AgentLaw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub request_id: String,
    pub tenant_id: String,
    pub domain: RegulatoryDomain,
    pub status: ExecutionStatus,
    pub classification: SemanticClassification,
    pub memory_precedent: Option<MemoryPrecedent>,
    pub circuit_breaker: CircuitBreakerStatus,
    pub witness_record: WitnessRecordView,
    pub tee_attestation: TeeAttestationReceipt,
    pub compliance_verdict: ComplianceVerdict,
    pub total_pipeline_duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    ApprovedAndExecuted,
    RefusedByCircuitBreaker,
    EscalatedToHumanSupervisor,
}

/// EU AI Act Compliance Verdict breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceVerdict {
    pub article_12_logging_compliant: bool,
    pub article_14_human_oversight_compliant: bool,
    pub article_15_robustness_compliant: bool,
    pub ai_liability_directive_non_repudiable: bool,
    pub legal_summary: String,
}

/// Software attestation receipt (Ed25519). Verifiable by any third party:
/// `Ed25519.verify(public_key_hex, signed_payload_hex, signature_hex)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationReceipt {
    pub platform: String,
    pub enclave_measurement_hex: String,
    pub root_anchor_hash_hex: String,
    pub public_key_hex: String,
    /// Exact signed bytes: domain prefix || measurement || chain_hash || seq || timestamp_ns.
    pub signed_payload_hex: String,
    pub signature_hex: String,
    pub verified: bool,
}

/// Tamper detection verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperVerificationReport {
    pub total_records_evaluated: usize,
    pub chain_valid: bool,
    pub broken_sequence: Option<u64>,
    pub detected_tamper_indices: Vec<usize>,
    pub verification_time_us: u64,
    pub status_message: String,
}

/// Incoming synchronization payload from Substrate-Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstrateSyncPayload {
    pub source: String,
    pub precedent_id: String,
    pub domain: RegulatoryDomain,
    pub description: String,
    pub embedding: Vec<f64>,
    pub outcome: String,
    pub active_inference_uncertainty: Option<f64>,
}

/// Response returned to Substrate-Core upon sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstrateSyncResponse {
    pub status: String,
    pub synced_id: String,
    pub total_precedents: usize,
    pub poincare_norm: f64,
    pub witness_sequence: u64,
    pub root_anchor_hex: String,
}

