//! Adversarial tamper detection engine for legal non-repudiation proofs.

use std::time::Instant;
use crate::kernel_bridge::KernelBridge;
use crate::types::TamperVerificationReport;

pub struct TamperEngine;

impl TamperEngine {
    /// Verify all records in the cryptographic witness chain.
    pub fn verify(bridge: &KernelBridge) -> TamperVerificationReport {
        let start = Instant::now();
        let (chain_valid, broken_seq, tampered_indices) = bridge.verify_chain_integrity();
        let elapsed_us = start.elapsed().as_micros() as u64;

        let total_records = bridge.witness_count();

        let status_message = if chain_valid {
            format!(
                "MATHEMATICALLY UNBROKEN: All {} records verified against SHA-256 chain anchors. Genesis-to-tip integrity: 100%.",
                total_records
            )
        } else {
            format!(
                "CRITICAL TAMPER DETECTED: Hash chain divergence at Sequence #{}. Tampered record indices: {:?}. Database sabotage prevented from corrupting audit trail.",
                broken_seq.unwrap_or(0),
                tampered_indices
            )
        };

        TamperVerificationReport {
            total_records_evaluated: total_records,
            chain_valid,
            broken_sequence: broken_seq,
            detected_tamper_indices: tampered_indices,
            verification_time_us: elapsed_us,
            status_message,
        }
    }

    /// Simulate an adversarial database hack where a rogue admin or attacker alters a historical record.
    pub fn simulate_tamper(bridge: &KernelBridge, record_index: usize) -> Result<TamperVerificationReport, &'static str> {
        bridge.inject_tamper(record_index)?;
        Ok(Self::verify(bridge))
    }
}
