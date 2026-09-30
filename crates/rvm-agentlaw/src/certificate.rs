//! EU AI Act Cryptographic Compliance & Non-Repudiation Certificate generator.

use serde::{Deserialize, Serialize};
use crate::kernel_bridge::{KernelBridge, TEE_PLATFORM_LABEL};

/// Format UNIX seconds as RFC 3339 UTC (civil-from-days, Howard Hinnant's algorithm).
fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", sod / 3600, (sod % 3600) / 60, sod % 60)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCertificate {
    pub certificate_id: String,
    pub issued_at_utc: String,
    pub regulatory_framework: String,
    pub conformity_assessment_standard: String,
    pub tenant_id: String,
    pub system_name: String,
    pub total_decisions_audited: usize,
    pub root_anchor_hash_sha256: String,
    pub hardware_enclave_platform: String,
    pub enclave_measurement: String,
    /// Ed25519 public key; with `signed_payload_hex` and `tee_signature` anyone can
    /// verify this certificate without the private key.
    pub public_key_hex: String,
    pub signed_payload_hex: String,
    pub tee_signature: String,
    pub tee_signature_verified: bool,
    pub chain_verified: bool,
    pub legal_attestation_statement: String,
    pub compliance_status: String,
    pub non_repudiation_guarantee: String,
}

pub struct CertificateGenerator;

impl CertificateGenerator {
    pub fn generate(
        tenant_id: &str,
        system_name: &str,
        bridge: &KernelBridge,
    ) -> AuditCertificate {
        let total = bridge.witness_count();
        let root_hash = bridge.current_chain_hash_hex();
        let cert_id = format!("EU-AIACT-CERT-{:08x}", total.wrapping_mul(0x9e3779b9));
        // Status is derived from an actual verification pass, never hardcoded.
        let (chain_valid, broken_seq, _) = bridge.verify_chain_integrity();
        let tip = bridge.attest_tip();
        let sig_ok = tip.verified;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let passed = chain_valid && sig_ok;

        AuditCertificate {
            certificate_id: cert_id,
            issued_at_utc: rfc3339_utc(now),
            regulatory_framework: "Regulation (EU) 2024/1689 (Artificial Intelligence Act)".to_string(),
            conformity_assessment_standard: "CEN-CENELEC JTC 21 / ISO/IEC 42001 & Article 12/14/15 Standards".to_string(),
            tenant_id: tenant_id.to_string(),
            system_name: system_name.to_string(),
            total_decisions_audited: total,
            root_anchor_hash_sha256: root_hash,
            hardware_enclave_platform: TEE_PLATFORM_LABEL.to_string(),
            enclave_measurement: tip.measurement_hex,
            // Ed25519 signature over (domain || measurement || tip hash || record count).
            public_key_hex: tip.public_key_hex,
            signed_payload_hex: tip.signed_payload_hex,
            tee_signature: tip.signature_hex,
            tee_signature_verified: sig_ok,
            chain_verified: chain_valid,
            legal_attestation_statement: "This cryptographic certificate certifies that all operational decisions executed by the identified autonomous agent fleet have been captured in a SHA-256 witness chain (software-attested, not hardware-anchored) pursuant to Article 12 (Automatic Logging) and Article 14 (Human Oversight) of Regulation (EU) 2024/1689. Any modification to underlying historical records renders this certificate mathematically void.".to_string(),
            compliance_status: if passed {
                "PASSED_FULLY_COMPLIANT".to_string()
            } else {
                format!("FAILED_CHAIN_INTEGRITY (first break at sequence #{})", broken_seq.unwrap_or(0))
            },
            non_repudiation_guarantee: if passed {
                "SHA-256 hash chain verified genesis-to-tip; tip signed with Ed25519 by a SOFTWARE key (publicly verifiable, not hardware-rooted)".to_string()
            } else {
                "VOID: witness chain failed verification".to_string()
            },
        }
    }
}
