//! AgentLaw: Hardware-Enforced EU AI Act Compliance & Non-Repudiation Appliance

pub mod attestation;
pub mod auth;
pub mod certificate;
pub mod circuit_breaker;
pub mod classifier;
pub mod compliance;
pub mod kernel_bridge;
pub mod ledger;
pub mod memory;
pub mod server;
pub mod service;
pub mod tamper_engine;
pub mod types;
pub mod ui;

pub use attestation::{verify_attestation_hex, AttestationSigner};
pub use auth::ApiKeys;
pub use certificate::{AuditCertificate, CertificateGenerator};
pub use circuit_breaker::AgentLawCircuitBreaker;
pub use classifier::LocalSemanticClassifier;
pub use compliance::ComplianceEngine;
pub use kernel_bridge::KernelBridge;
pub use memory::{poincare_distance, CognitiveMemoryEngine};
pub use server::{run_server, serve, ServerConfig};
pub use service::{AgentLawService, SyncError};
pub use tamper_engine::TamperEngine;
pub use types::*;
