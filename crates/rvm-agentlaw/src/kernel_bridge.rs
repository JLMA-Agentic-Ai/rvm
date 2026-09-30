//! Per-tenant SHA-256 witness chain + Ed25519 software attestation.
//!
//! The chain is a local SHA-256 hash chain (it does not use `rvm-witness`).
//! Each record's tip is signed with Ed25519 (`attestation.rs`), so any third
//! party can verify it with the published public key. When opened with a
//! ledger path, every record is fsync'd to disk before it is acknowledged and
//! the whole chain is re-verified on reload.

use std::path::Path;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::attestation::{attestation_message, verify_bytes, AttestationSigner, SOFTWARE_MEASUREMENT};
use crate::ledger::{LedgerFile, LedgerRecord, LEDGER_VERSION};
use crate::types::{TeeAttestationReceipt, WitnessRecordView};

/// Honest platform label for every attestation this bridge emits.
pub const TEE_PLATFORM_LABEL: &str =
    "SOFTWARE-EMULATED TEE (Ed25519 software key in process memory; verify with public_key_hex) - NOT hardware-backed";

/// Tenant of chains built with [`KernelBridge::new`].
pub const DEFAULT_TENANT: &str = "default";

pub struct KernelBridge {
    inner: Mutex<KernelBridgeInner>,
}

#[derive(Clone)]
pub struct StoredWitnessEntry {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub action_kind: u8,
    pub action_name: String,
    pub partition_id: u16,
    pub payload_bytes: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
    pub chain_hash: [u8; 32],
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
    pub is_tampered: bool,
}

/// Ed25519 attestation over the current tip.
#[derive(Debug, Clone)]
pub struct TipAttestation {
    pub measurement_hex: String,
    pub public_key_hex: String,
    pub signed_payload_hex: String,
    pub signature_hex: String,
    pub verified: bool,
}

struct KernelBridgeInner {
    tenant_id: String,
    sequence_counter: u64,
    genesis_hash: [u8; 32],
    current_chain_hash: [u8; 32],
    records: Vec<StoredWitnessEntry>,
    signer: Arc<AttestationSigner>,
    ledger: Option<LedgerFile>,
}

/// Genesis anchor, domain-separated per tenant so chains cannot be spliced across tenants.
pub fn genesis_hash_for(tenant_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"RVM-AGENTLAW-GENESIS-ANCHOR-2026-EU-AI-ACT");
    h.update([0u8]);
    h.update(tenant_id.as_bytes());
    h.finalize().into()
}

/// SHA-256(seq || ts || kind || partition || len(name) || name || payload).
/// `action_name` is bound so the persisted verdict label cannot be rewritten.
fn record_hash(seq: u64, ts: u64, kind: u8, partition: u16, name: &str, payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(ts.to_le_bytes());
    h.update([kind]);
    h.update(partition.to_le_bytes());
    h.update((name.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.update(payload);
    h.finalize().into()
}

/// SHA-256(prev_hash || record_hash).
fn chain_hash(prev: &[u8; 32], record: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(record);
    h.finalize().into()
}

fn report_data(chain: &[u8; 32], a: u64, b: u64) -> [u8; 64] {
    let mut r = [0u8; 64];
    r[0..32].copy_from_slice(chain);
    r[32..40].copy_from_slice(&a.to_le_bytes());
    r[40..48].copy_from_slice(&b.to_le_bytes());
    r
}

fn now_ns() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock before UNIX epoch: {e}"))
        .and_then(|d| u64::try_from(d.as_nanos()).map_err(|_| "timestamp overflow".to_string()))
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{what} is not 32 bytes of hex"))
}

impl KernelBridge {
    /// In-memory chain for [`DEFAULT_TENANT`] with a fresh (or `AGENTLAW_TEE_KEY_HEX`) key.
    /// Panics if no key can be obtained — it never falls back to a constant.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let signer = AttestationSigner::from_env_or_generate().expect("AgentLaw: cannot obtain an Ed25519 signing key");
        Self::ephemeral(DEFAULT_TENANT, Arc::new(signer))
    }

    /// In-memory (non-durable) chain for `tenant_id`.
    pub fn ephemeral(tenant_id: &str, signer: Arc<AttestationSigner>) -> Self {
        let genesis = genesis_hash_for(tenant_id);
        Self {
            inner: Mutex::new(KernelBridgeInner {
                tenant_id: tenant_id.to_string(),
                sequence_counter: 0,
                genesis_hash: genesis,
                current_chain_hash: genesis,
                records: Vec::new(),
                signer,
                ledger: None,
            }),
        }
    }

    /// Durable chain backed by `ledger_path`. Every existing record is re-verified
    /// (hashes, linkage, contiguity, Ed25519 signature); any defect is an error.
    pub fn open_persistent(tenant_id: &str, ledger_path: &Path, signer: Arc<AttestationSigner>) -> Result<Self, String> {
        let (ledger, persisted) = LedgerFile::open(ledger_path)?;
        let genesis = genesis_hash_for(tenant_id);
        let mut running = genesis;
        let mut records = Vec::with_capacity(persisted.len());
        for (i, p) in persisted.iter().enumerate() {
            let at = |m: &str| format!("ledger {} record #{}: {m}", ledger_path.display(), i + 1);
            if p.tenant_id != tenant_id {
                return Err(at(&format!("tenant '{}' != '{}'", p.tenant_id, tenant_id)));
            }
            if p.sequence != i as u64 + 1 {
                return Err(at(&format!("sequence {} is not contiguous", p.sequence)));
            }
            let payload = hex::decode(&p.payload_hex).map_err(|_| at("payload_hex is not hex"))?;
            let prev = hex32(&p.prev_hash_hex, "prev_hash").map_err(|e| at(&e))?;
            let rec = hex32(&p.record_hash_hex, "record_hash").map_err(|e| at(&e))?;
            let chain = hex32(&p.chain_hash_hex, "chain_hash").map_err(|e| at(&e))?;
            let pk = hex32(&p.public_key_hex, "public_key").map_err(|e| at(&e))?;
            let sig: [u8; 64] = hex::decode(&p.signature_hex)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| at("signature is not 64 bytes of hex"))?;
            if prev != running {
                return Err(at("prev_hash does not link to the previous record"));
            }
            if rec != record_hash(p.sequence, p.timestamp_ns, p.action_kind, p.partition_id, &p.action_name, &payload) {
                return Err(at("record_hash mismatch (record content altered)"));
            }
            if chain != chain_hash(&prev, &rec) {
                return Err(at("chain_hash mismatch"));
            }
            let msg = attestation_message(&report_data(&chain, p.sequence, p.timestamp_ns));
            if !verify_bytes(&pk, &msg, &sig) {
                return Err(at("Ed25519 signature invalid"));
            }
            running = chain;
            records.push(StoredWitnessEntry {
                sequence: p.sequence,
                timestamp_ns: p.timestamp_ns,
                action_kind: p.action_kind,
                action_name: p.action_name.clone(),
                partition_id: p.partition_id,
                payload_bytes: payload,
                prev_hash: prev,
                record_hash: rec,
                chain_hash: chain,
                public_key: pk,
                signature: sig,
                is_tampered: false,
            });
        }
        Ok(Self {
            inner: Mutex::new(KernelBridgeInner {
                tenant_id: tenant_id.to_string(),
                sequence_counter: records.len() as u64,
                genesis_hash: genesis,
                current_chain_hash: running,
                records,
                signer,
                ledger: Some(ledger),
            }),
        })
    }

    /// Emit a witness record. With a ledger, the record is fsync'd BEFORE it is
    /// committed in memory; on any error nothing is committed.
    pub fn emit_witness_record(
        &self,
        action_kind: u8,
        action_name: &str,
        partition_id: u16,
        payload_bytes: &[u8],
    ) -> Result<(WitnessRecordView, TeeAttestationReceipt), String> {
        let mut inner = self.inner.lock().map_err(|_| "KernelBridge mutex poisoned".to_string())?;

        let seq = inner.sequence_counter + 1;
        let timestamp_ns = now_ns()?;
        let prev_hash = inner.current_chain_hash;
        let rec_hash = record_hash(seq, timestamp_ns, action_kind, partition_id, action_name, payload_bytes);
        let chain = chain_hash(&prev_hash, &rec_hash);

        let att = inner.signer.attest(&report_data(&chain, seq, timestamp_ns));
        let verified = verify_bytes(&att.public_key, &att.message, &att.signature);
        if !verified {
            return Err("Ed25519 self-verification of the new witness record failed".to_string());
        }

        let stored = StoredWitnessEntry {
            sequence: seq,
            timestamp_ns,
            action_kind,
            action_name: action_name.to_string(),
            partition_id,
            payload_bytes: payload_bytes.to_vec(),
            prev_hash,
            record_hash: rec_hash,
            chain_hash: chain,
            public_key: att.public_key,
            signature: att.signature,
            is_tampered: false,
        };

        let tenant_id = inner.tenant_id.clone();
        if let Some(ledger) = inner.ledger.as_mut() {
            ledger.append(&LedgerRecord {
                v: LEDGER_VERSION,
                tenant_id,
                sequence: seq,
                timestamp_ns,
                action_kind,
                action_name: action_name.to_string(),
                partition_id,
                payload_hex: hex::encode(payload_bytes),
                prev_hash_hex: hex::encode(prev_hash),
                record_hash_hex: hex::encode(rec_hash),
                chain_hash_hex: hex::encode(chain),
                public_key_hex: hex::encode(att.public_key),
                signature_hex: hex::encode(att.signature),
            })?;
        }

        // Commit only after the durable write succeeded.
        inner.sequence_counter = seq;
        inner.current_chain_hash = chain;
        let view = Self::view(&stored);
        inner.records.push(stored);

        let attestation = TeeAttestationReceipt {
            platform: TEE_PLATFORM_LABEL.to_string(),
            enclave_measurement_hex: hex::encode(SOFTWARE_MEASUREMENT),
            root_anchor_hash_hex: hex::encode(chain),
            public_key_hex: hex::encode(att.public_key),
            signed_payload_hex: hex::encode(&att.message),
            signature_hex: hex::encode(att.signature),
            verified,
        };
        Ok((view, attestation))
    }

    fn view(r: &StoredWitnessEntry) -> WitnessRecordView {
        WitnessRecordView {
            sequence: r.sequence,
            timestamp_ns: r.timestamp_ns,
            action_kind: r.action_kind,
            action_name: r.action_name.clone(),
            partition_id: r.partition_id,
            record_hash_hex: hex::encode(r.record_hash),
            prev_hash_hex: hex::encode(r.prev_hash),
            chain_hash_hex: hex::encode(r.chain_hash),
            is_tampered: r.is_tampered,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, KernelBridgeInner> {
        // Poisoning means a panic mid-update: propagate (fail closed) rather than read torn state.
        self.inner.lock().expect("KernelBridge mutex poisoned")
    }

    /// Retrieve all records in the witness ledger.
    pub fn get_all_records(&self) -> Vec<WitnessRecordView> {
        self.lock().records.iter().map(Self::view).collect()
    }

    pub fn tenant_id(&self) -> String {
        self.lock().tenant_id.clone()
    }

    pub fn public_key_hex(&self) -> String {
        self.lock().signer.public_key_hex()
    }

    pub fn is_durable(&self) -> bool {
        self.lock().ledger.is_some()
    }

    /// Get current tip chain hash.
    pub fn current_chain_hash_hex(&self) -> String {
        hex::encode(self.lock().current_chain_hash)
    }

    /// Total count of witness records emitted.
    pub fn witness_count(&self) -> usize {
        self.lock().records.len()
    }

    /// Independent in-memory copy (same key) for destructive simulations, so
    /// demo tamper tests never corrupt the live chain or its on-disk ledger.
    pub fn fork_for_simulation(&self) -> KernelBridge {
        let inner = self.lock();
        KernelBridge {
            inner: Mutex::new(KernelBridgeInner {
                tenant_id: inner.tenant_id.clone(),
                sequence_counter: inner.sequence_counter,
                genesis_hash: inner.genesis_hash,
                current_chain_hash: inner.current_chain_hash,
                records: inner.records.clone(),
                signer: Arc::clone(&inner.signer),
                ledger: None,
            }),
        }
    }

    /// Ed25519 attestation over the current tip: report_data = tip hash || record count.
    pub fn attest_tip(&self) -> TipAttestation {
        let inner = self.lock();
        let att = inner.signer.attest(&report_data(&inner.current_chain_hash, inner.records.len() as u64, 0));
        TipAttestation {
            measurement_hex: hex::encode(SOFTWARE_MEASUREMENT),
            public_key_hex: hex::encode(att.public_key),
            signed_payload_hex: hex::encode(&att.message),
            signature_hex: hex::encode(att.signature),
            verified: verify_bytes(&att.public_key, &att.message, &att.signature),
        }
    }

    /// Test/demo hook: drop the newest record WITHOUT touching the tip anchor
    /// (models an attacker truncating the log).
    pub fn inject_truncation(&self) -> Result<(), &'static str> {
        self.lock().records.pop().map(|_| ()).ok_or("Chain is empty")
    }

    /// Tamper injection test: deliberately flip bits in an older record to prove detection.
    pub fn inject_tamper(&self, index: usize) -> Result<(), &'static str> {
        let mut inner = self.lock();
        let record = inner.records.get_mut(index).ok_or("Index out of bounds")?;
        if record.payload_bytes.is_empty() {
            record.payload_bytes.push(0xfe);
        } else {
            record.payload_bytes[0] ^= 0xff;
        }
        record.is_tampered = true;
        Ok(())
    }

    /// Verify the entire chain from genesis to tip: record/chain hashes, linkage,
    /// sequence contiguity, per-record Ed25519 signature, and that the last record
    /// matches the retained tip anchor (detects tail truncation). The `is_tampered`
    /// display flag is never consulted.
    pub fn verify_chain_integrity(&self) -> (bool, Option<u64>, Vec<usize>) {
        let inner = self.lock();
        let mut running = inner.genesis_hash;
        let mut broken_sequence = None;
        let mut tampered_indices = Vec::new();

        for (idx, r) in inner.records.iter().enumerate() {
            let rec = record_hash(r.sequence, r.timestamp_ns, r.action_kind, r.partition_id, &r.action_name, &r.payload_bytes);
            let chain = chain_hash(&r.prev_hash, &rec);
            let msg = attestation_message(&report_data(&r.chain_hash, r.sequence, r.timestamp_ns));
            let ok = r.prev_hash == running
                && r.record_hash == rec
                && r.chain_hash == chain
                && r.sequence == idx as u64 + 1
                && verify_bytes(&r.public_key, &msg, &r.signature);
            if !ok {
                tampered_indices.push(idx);
                broken_sequence.get_or_insert(r.sequence);
            }
            running = r.chain_hash;
        }

        if running != inner.current_chain_hash || inner.records.len() as u64 != inner.sequence_counter {
            broken_sequence.get_or_insert(inner.records.len() as u64 + 1);
            tampered_indices.push(inner.records.len());
        }

        (tampered_indices.is_empty(), broken_sequence, tampered_indices)
    }
}

/// Minimal hex codec.
pub mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Input was not strict hex.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InvalidHex;

    /// Strict decode: even length, `[0-9a-fA-F]` only.
    pub fn decode(s: &str) -> Result<Vec<u8>, InvalidHex> {
        let b = s.as_bytes();
        if b.len() % 2 != 0 {
            return Err(InvalidHex);
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(InvalidHex),
        };
        b.chunks(2).map(|p| Ok(nib(p[0])? << 4 | nib(p[1])?)).collect()
    }
}
