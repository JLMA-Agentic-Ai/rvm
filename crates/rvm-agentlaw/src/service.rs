//! AgentLaw compliance pipeline with tenant-isolated, optionally durable audit chains.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::attestation::AttestationSigner;
use crate::auth::validate_tenant_id;
use crate::circuit_breaker::AgentLawCircuitBreaker;
use crate::classifier::LocalSemanticClassifier;
use crate::compliance::ComplianceEngine;
use crate::kernel_bridge::KernelBridge;
use crate::memory::{CognitiveMemoryEngine, SyncRejection};
use crate::types::{ActionRequest, ExecutionReceipt, ExecutionStatus, SubstrateSyncPayload, SubstrateSyncResponse};

/// Why a substrate sync was not applied.
#[derive(Debug)]
pub enum SyncError {
    /// Input refused at the boundary (HTTP 422).
    Rejected(SyncRejection),
    /// Internal failure, e.g. the witness ledger could not be written (HTTP 500).
    Internal(String),
}

pub struct AgentLawService {
    pub classifier: LocalSemanticClassifier,
    pub memory: RwLock<CognitiveMemoryEngine>,
    pub circuit_breaker: AgentLawCircuitBreaker,
    signer: Arc<AttestationSigner>,
    /// `Some(dir)` -> each tenant's chain is persisted to `dir/witness_ledger/<tenant>.log`.
    data_dir: Option<PathBuf>,
    chains: Mutex<HashMap<String, Arc<KernelBridge>>>,
}

impl AgentLawService {
    /// Non-durable service (tests / demos). Panics if no signing key can be obtained.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let signer = AttestationSigner::from_env_or_generate().expect("AgentLaw: cannot obtain an Ed25519 signing key");
        Self::build(Arc::new(signer), None)
    }

    /// Durable service: tenant chains are loaded from, verified against and fsync'd to `data_dir`.
    pub fn with_data_dir(data_dir: impl Into<PathBuf>, signer: Arc<AttestationSigner>) -> Self {
        Self::build(signer, Some(data_dir.into()))
    }

    fn build(signer: Arc<AttestationSigner>, data_dir: Option<PathBuf>) -> Self {
        Self {
            classifier: LocalSemanticClassifier::new(),
            memory: RwLock::new(CognitiveMemoryEngine::new()),
            circuit_breaker: AgentLawCircuitBreaker::new(),
            signer,
            data_dir,
            chains: Mutex::new(HashMap::new()),
        }
    }

    pub fn public_key_hex(&self) -> String {
        self.signer.public_key_hex()
    }

    pub fn ledger_path(&self, tenant_id: &str) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("witness_ledger").join(format!("{tenant_id}.log")))
    }

    /// The tenant's audit chain, opened (and re-verified from disk) on first use.
    /// A brand-new chain is seeded with the two genesis boot records.
    pub fn chain(&self, tenant_id: &str) -> Result<Arc<KernelBridge>, String> {
        validate_tenant_id(tenant_id)?;
        let mut chains = self.chains.lock().map_err(|_| "chain registry mutex poisoned".to_string())?;
        if let Some(c) = chains.get(tenant_id) {
            return Ok(Arc::clone(c));
        }
        let bridge = match self.ledger_path(tenant_id) {
            Some(path) => KernelBridge::open_persistent(tenant_id, &path, Arc::clone(&self.signer))?,
            None => KernelBridge::ephemeral(tenant_id, Arc::clone(&self.signer)),
        };
        if bridge.witness_count() == 0 {
            bridge.emit_witness_record(1, "KERNEL_BOOT_PHASE_POWER_ON", 0, b"INIT_POWER_ON")?;
            bridge.emit_witness_record(2, "SECURITY_GATE_POLICY_INITIALIZED", 0, b"EU_AI_ACT_POLICY_V1")?;
        }
        let bridge = Arc::new(bridge);
        chains.insert(tenant_id.to_string(), Arc::clone(&bridge));
        Ok(bridge)
    }

    /// Execute the complete compliance pipeline on `request.tenant_id`'s chain.
    /// Any internal failure (ledger write, lock poisoning, encoding) is an error:
    /// no receipt, no approval.
    pub fn dispatch_action(&self, request: ActionRequest) -> Result<ExecutionReceipt, String> {
        let pipeline_start = Instant::now();
        let chain = self.chain(&request.tenant_id)?;

        // Step 1: deterministic local classifier
        let (classification, query_vec) = self.classifier.classify(&request);

        // Step 2: tenant-scoped hyperbolic precedent lookup
        let memory_precedent = self
            .memory
            .read()
            .map_err(|_| "memory RwLock poisoned".to_string())?
            .find_nearest_analog_for(Some(&request.tenant_id), request.domain, &query_vec, request.timestamp_utc);

        // Step 3: circuit breaker, fed by the nearest precedent (cognitive feedback)
        let cb_status = self.circuit_breaker.evaluate_with_precedent(&request, &classification, memory_precedent.as_ref());
        let circuit_tripped = cb_status.tripped;
        let escalated = classification.requires_human_escalation && !request.human_supervisor_approval;

        // Step 4: Article 12 witness record (durable before acknowledged)
        let action_name = if circuit_tripped {
            format!("CIRCUIT_BREAKER_HALT_{}", request.action_type.to_uppercase())
        } else if escalated {
            format!("ESCALATION_PAUSE_{}", request.action_type.to_uppercase())
        } else {
            format!("AUTHORIZED_EXECUTION_{}", request.action_type.to_uppercase())
        };
        let action_kind = if circuit_tripped { 0xfe } else { 0x05 };
        let payload_json = serde_json::to_vec(&request.payload).map_err(|e| format!("cannot encode payload: {e}"))?;
        let (witness_record, tee_attestation) = chain.emit_witness_record(action_kind, &action_name, 1, &payload_json)?;

        // Step 5: legal verdict
        let compliance_verdict = ComplianceEngine::evaluate(&request, &classification, circuit_tripped);
        let status = if circuit_tripped {
            ExecutionStatus::RefusedByCircuitBreaker
        } else if escalated {
            ExecutionStatus::EscalatedToHumanSupervisor
        } else {
            ExecutionStatus::ApprovedAndExecuted
        };

        Ok(ExecutionReceipt {
            request_id: request.request_id,
            tenant_id: request.tenant_id,
            domain: request.domain,
            status,
            classification,
            memory_precedent,
            circuit_breaker: cb_status,
            witness_record,
            tee_attestation,
            compliance_verdict,
            total_pipeline_duration_us: pipeline_start.elapsed().as_micros() as u64,
        })
    }

    /// Sync a Substrate-Core precedent into `tenant_id`'s memory scope.
    /// Validated first, witnessed second, committed last (under one write lock).
    pub fn sync_precedent(&self, tenant_id: &str, payload: SubstrateSyncPayload, now_utc: u64) -> Result<SubstrateSyncResponse, SyncError> {
        let chain = self.chain(tenant_id).map_err(SyncError::Internal)?;
        let mut mem = self.memory.write().map_err(|_| SyncError::Internal("memory RwLock poisoned".into()))?;
        let norm = mem
            .check_sync(Some(tenant_id), &payload.precedent_id, &payload.embedding)
            .map_err(SyncError::Rejected)?;

        let sync_bytes = serde_json::to_vec(&serde_json::json!({
            "synced_id": payload.precedent_id,
            "source": payload.source,
            "domain": payload.domain.as_str(),
            "embedding": payload.embedding,
            "outcome": payload.outcome,
            "uncertainty": payload.active_inference_uncertainty,
        }))
        .map_err(|e| SyncError::Internal(format!("cannot encode sync record: {e}")))?;
        let (witness, _) = chain
            .emit_witness_record(0x06, "SUBSTRATE_CORE_MEMORY_SYNC", 1, &sync_bytes)
            .map_err(SyncError::Internal)?;

        mem.sync_live_precedent_for(
            Some(tenant_id),
            payload.precedent_id.clone(),
            payload.domain,
            payload.description,
            payload.embedding,
            now_utc,
            payload.outcome,
        )
        .map_err(SyncError::Rejected)?;

        Ok(SubstrateSyncResponse {
            status: "SYNCHRONIZED_WITH_RVM_COGNITIVE_MEMORY".to_string(),
            synced_id: payload.precedent_id,
            total_precedents: mem.visible_precedent_count(Some(tenant_id)),
            poincare_norm: norm,
            witness_sequence: witness.sequence,
            root_anchor_hex: witness.chain_hash_hex,
        })
    }
}
