//! Asymmetric (Ed25519) attestation of witness-chain tips.
//!
//! Replaces the HMAC-SHA256 `SoftwareTeeProvider` quote: an HMAC tag can only be
//! checked by someone holding the secret key, so it proved nothing to a third
//! party. An Ed25519 signature is verifiable with `public_key_hex` alone.
//!
//! The key lives in process memory — this is a SOFTWARE attestation, not a
//! hardware TEE quote.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::kernel_bridge::hex;

/// Domain-separation prefix of every signed attestation message.
pub const ATTESTATION_DOMAIN: &[u8] = b"AGENTLAW-ATTEST-ED25519-V1\0";

/// Placeholder measurement: there is no enclave to measure.
pub const SOFTWARE_MEASUREMENT: [u8; 32] = [0x5a; 32];

/// Env var holding the 32-byte Ed25519 seed as 64 hex chars.
pub const SIGNING_SEED_ENV: &str = "AGENTLAW_TEE_KEY_HEX";

/// Ed25519 signer for witness-tip attestations.
pub struct AttestationSigner {
    signing_key: SigningKey,
}

/// A signed attestation: everything a third party needs to verify it.
#[derive(Debug, Clone)]
pub struct SignedAttestation {
    pub public_key: [u8; 32],
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

impl AttestationSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing_key: SigningKey::from_bytes(&seed) }
    }

    /// Fresh key from the OS CSPRNG. Errors (never falls back to a constant) if unavailable.
    pub fn generate() -> Result<Self, String> {
        use std::io::Read;
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .map_err(|e| format!("OS CSPRNG unavailable ({e}); refusing to use a constant key"))?;
        Ok(Self::from_seed(seed))
    }

    /// Seed from `AGENTLAW_TEE_KEY_HEX` when set (malformed -> error), else a fresh key.
    pub fn from_env_or_generate() -> Result<Self, String> {
        match std::env::var(SIGNING_SEED_ENV) {
            Ok(h) => {
                let seed: [u8; 32] = hex::decode(&h)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| format!("{SIGNING_SEED_ENV} must be exactly 64 hex chars"))?;
                Ok(Self::from_seed(seed))
            }
            Err(std::env::VarError::NotPresent) => Self::generate(),
            Err(e) => Err(format!("{SIGNING_SEED_ENV} unreadable: {e}")),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Sign `ATTESTATION_DOMAIN || measurement || report_data`.
    pub fn attest(&self, report_data: &[u8; 64]) -> SignedAttestation {
        let message = attestation_message(report_data);
        let signature = self.signing_key.sign(&message).to_bytes();
        SignedAttestation { public_key: self.public_key(), message, signature }
    }
}

/// The exact byte string that is signed for a given report.
pub fn attestation_message(report_data: &[u8; 64]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 96);
    m.extend_from_slice(ATTESTATION_DOMAIN);
    m.extend_from_slice(&SOFTWARE_MEASUREMENT);
    m.extend_from_slice(report_data);
    m
}

/// Verify raw bytes. Uses `verify_strict` (rejects malleable / small-order keys).
pub fn verify_bytes(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(public_key) {
        Ok(vk) => vk.verify_strict(message, &Signature::from_bytes(signature)).is_ok(),
        Err(_) => false,
    }
}

/// Third-party verification from the hex fields published in receipts and
/// certificates. Needs no secret. Any malformed field -> `false`.
pub fn verify_attestation_hex(public_key_hex: &str, message_hex: &str, signature_hex: &str) -> bool {
    let pk: Option<[u8; 32]> = hex::decode(public_key_hex).ok().and_then(|b| b.try_into().ok());
    let sig: Option<[u8; 64]> = hex::decode(signature_hex).ok().and_then(|b| b.try_into().ok());
    match (pk, sig, hex::decode(message_hex)) {
        (Some(pk), Some(sig), Ok(msg)) => verify_bytes(&pk, &msg, &sig),
        _ => false,
    }
}
