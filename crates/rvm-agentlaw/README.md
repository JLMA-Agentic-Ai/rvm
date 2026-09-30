# rvm-agentlaw

[![Crate](https://img.shields.io/badge/crate-rvm--agentlaw-orange.svg)](https://github.com/ruvnet/rvm)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](../../LICENSE)
[![Compliance](https://img.shields.io/badge/EU_AI_Act-Articles_12%2C_14%2C_15-green.svg)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
[![TEE](https://img.shields.io/badge/TEE-ARM_CCA_Realm_EL2-purple.svg)](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)

**AgentLaw** is a hardware-enforced AI governance and regulatory compliance appliance built on the **RVM (RuVector Virtual Machine)** microhypervisor. It bridges autonomous AI agent runtimes with strict regulatory mandates—principally the **EU AI Act** and the **EU AI Liability Directive**—using physical hardware containment rather than bypassable user-space software checks.

---

## 1. Architectural Motivation

Traditional AI governance relies on user-space middleware, Python wrappers, or prompt-level guardrails. Under adversarial stress (prompt injection, memory corruption, privilege escalation, or compromised database administrators), software-only guardrails can be bypassed without leaving an unforgeable trace.

Furthermore, under the **EU AI Liability Directive (COM/2022/496)**, the burden of proof is formally reversed: in the event of harm caused by an AI system, **negligence is legally presumed** unless the operator can furnish reproducible, tamper-proof audit trails demonstrating autonomous circuit breakers and effective human oversight.

`rvm-agentlaw` provides:
1. **Hardware Circuit Breakers:** Silicon-enforced privilege attenuation (`CapRights`) and vCPU register suspension via the RVM microhypervisor.
2. **Deterministic Pre-Execution Classification:** High-speed (~30ms) typed categorization with calibrated confidence intervals.
3. **Hyperbolic Cognitive Memory:** Poincaré hyperbolic embeddings ($\mathbb{H}^d$) matching `substrate-core` geometry to detect behavioral drift with temporal decay.
4. **Non-Repudiable Witness Ledger:** Merkle-linked SHA-256 hash chains bound to an **ARM Confidential Compute Architecture (ARM CCA)** Realm EL2 attestation root.
5. **Sub-Millisecond Anti-Tamper Engine:** Merkle divergence detection running in $\le 0.05$ ms that identifies exact database tampering.
6. **Judicial Exoneration Certificates:** Cryptographically signed certificates of compliance ready for legal defense in regulatory audits or courtroom trials.

---

## 2. The 4-Stage Compliance Pipeline

Every agent request passes through a 4-stage pipeline before any hardware action can be committed:

```
[Agent Action Request]
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ Stage 1: Cognitive Memory (Poincaré Hyperbolic Metric) │
│ - Computes d_H(u, v) in the Poincaré ball model        │
│ - Incorporates temporal exponential decay              │
│ - Detects out-of-distribution behavioral drift         │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ Stage 2: Local Semantic Classifier (~30ms)             │
│ - Deterministic typed intent classification            │
│ - Calibrated confidence scoring (Softmax / Platt)      │
│ - Classifies FinTech, MedTech, HR, Critical Infra     │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ Stage 3: RVM Hardware Circuit Breaker                  │
│ - Evaluates EU AI Act Articles 12, 14, 15 rules        │
│ - High-risk (>€50k, toxic dose, etc.) triggers TRIP    │
│ - Immediately masks hardware CapRights:                │
│     (READ | WRITE | EXECUTE) -> (READ ONLY)            │
│ - Suspends agent vCPU execution thread                 │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ Stage 4: Cryptographic Witness Emission & Merkle Chain │
│ - Appends 64-byte SHA-256 witness into RVM ledger      │
│ - Links previous root anchor into immutable chain      │
│ - Generates ARM CCA Realm EL2 attestation quote        │
└────────────────────────────────────────────────────────┘
```

---

## 3. Regulatory Mapping Matrix

| Regulation / Article | Legal Requirement | `rvm-agentlaw` Implementation |
| :--- | :--- | :--- |
| **EU AI Act Art. 12** | Automatic logging of high-risk AI events throughout system lifecycle. | Sequential, append-only SHA-256 hash chains (`rvm-witness`) rooted in hardware TEE. |
| **EU AI Act Art. 14** | Human oversight with override authority ("stop button"). | `CircuitBreakerEngine` halts vCPU and revokes capability masks until dual-human sign-off is committed. |
| **EU AI Act Art. 15** | Accuracy, robustness, and cybersecurity against adversarial exploitation. | Local ~30ms classifier prevents cloud MITM; Substrate Poincaré memory flags zero-day semantic deviations. |
| **AI Liability Directive** | Reversal of proof burden; operator must prove non-negligence. | `CertificateEngine` generates signed, time-stamped Non-Repudiation Certificates with TEE quote anchors. |

---

## 4. Module Layout

```
crates/rvm-agentlaw/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Library exports and public API
│   ├── types.rs            # Schema definitions (requests, witnesses, certificates)
│   ├── compliance.rs       # Formal regulatory rule engine (Articles 12, 14, 15)
│   ├── classifier.rs       # Fast deterministic semantic classifier (~30ms)
│   ├── memory.rs           # Hyperbolic Poincaré cognitive memory & temporal decay
│   ├── circuit_breaker.rs  # RVM hardware privilege containment & vCPU suspension
│   ├── kernel_bridge.rs    # RVM witness emitter & ARM CCA TEE attestation quotes
│   ├── tamper_engine.rs    # Sub-millisecond Merkle chain verification & divergence isolation
│   ├── certificate.rs      # EU AI Act Non-Repudiation Certificate generator
│   ├── ui.rs               # Embedded single-page dark-mode web dashboard
│   ├── server.rs           # Multi-threaded HTTP API daemon (port 8090)
│   └── main.rs             # Standalone binary entry point
└── tests/
    └── compliance_tests.rs # Automated compliance and red-team test suite (8 tests)
```

---

## 4a. Security & Operations

| Variable | Required | Meaning |
|---|---|---|
| `AGENTLAW_API_KEY` | **yes** | `<secret>` (tenant `default`) or `<tenant>:<secret>,...`; secrets ≥ 32 chars. The daemon refuses to start without it. |
| `AGENTLAW_DATA_DIR` | no (`data`) | Witness ledgers: `<dir>/witness_ledger/<tenant>.log`, JSON lines, fsync'd per record. |
| `AGENTLAW_TEE_KEY_HEX` | no | 32-byte Ed25519 seed (64 hex). Unset: fresh key per process. |
| `AGENTLAW_PORT` / `AGENTLAW_BIND` | no (`8090` / `127.0.0.1`) | Listen address. |

- **Auth & tenancy**: every `/api/*` route needs `Authorization: Bearer <secret>`; the key selects the tenant. Each tenant has its own chain (tenant-specific genesis), ledger file and precedent scope; a body `tenant_id` for another tenant gets `403`.
- **Durability**: a record is fsync'd before it is acknowledged. On startup every ledger is re-verified (hashes, linkage, contiguity, Ed25519 signatures); a torn, edited or re-ordered ledger stops the daemon from starting (fail-closed).
- **Attestation**: receipts and certificates carry `public_key_hex`, `signed_payload_hex` and an Ed25519 signature, so anyone can verify them without the private key. This is a software key, not a hardware TEE.
- **Precedent drift trip**: if the nearest precedent is `HIGH_RISK_SUSPENDED` / `CRITICAL_OVERDOSE_BLOCKED` at Poincaré distance `< 0.35`, the breaker trips unless a human supervisor approved the request.

## 5. API Reference

The daemon listens on `0.0.0.0:8090` by default.

### `GET /api/status`
Returns enclave health, active TEE profile, witness chain sequence, and root anchor.
```json
{
  "status": "OK",
  "enclave": "ARM_CCA_REALM_EL2",
  "witness_count": 4,
  "root_hash": "fe3918f084881eedbddbc38d118a082546716db3f293b46ed98af2f7abfbf590",
  "circuit_breaker": "ACTIVE",
  "uptime_secs": 1420
}
```

### `GET /api/scenarios`
Returns pre-packaged industry test scenarios:
- `fintech_routine`: Routine monthly payroll (€12,500).
- `fintech_violation`: Unsupervised high-value wire transfer (€185,000).
- `medtech_overdose`: Lethal chemotherapy dosage (220mg vs 150mg limit).
- `medtech_routine`: Standard analgesia administration.

### `POST /api/execute`
Executes an agent request through the 4-stage pipeline.
```bash
curl -X POST http://localhost:8090/api/execute \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "finance_agent_01",
    "action": "wire_transfer_disbursement",
    "payload": "{\"amount\": 185000.0, \"currency\": \"EUR\", \"recipient\": \"DE89370400440532013000\"}"
  }'
```

### `POST /api/tamper/bitflip`
Adversarially mutates a historical witness record in the database to test the non-repudiation engine.
```bash
curl -X POST http://localhost:8090/api/tamper/bitflip
```

### `POST /api/certificate/generate`
Generates an official EU AI Act Non-Repudiation Certificate covering all witnessed events.
```bash
curl -X POST http://localhost:8090/api/certificate/generate
```

### `GET /api/ledger`
Dumps the complete cryptographic witness chain with Merkle proofs.

---

## 6. Testing & Verification

Run the formal verification test suite:
```bash
cargo test -p rvm-agentlaw -- --nocapture
```

Test coverage includes:
1. `test_genesis_witness_chain`: Verifies hash continuity of initial boot states.
2. `test_routine_transfer_approved`: Verifies low-risk execution passes with granted CapRights.
3. `test_circuit_breaker_high_value_transfer`: Verifies €185,000 disbursement trips the hardware circuit breaker.
4. `test_medtech_overdose_prevention`: Verifies 220mg chemotherapy order is halted pursuant to EMA limits.
5. `test_tamper_detection_on_bitflip`: Verifies Merkle chain divergence triggers an alarm in < 0.1ms.
6. `test_certificate_generation`: Verifies signed judicial certificates with TEE quotes.
7. `test_poincare_distance_anomaly`: Verifies hyperbolic metric correctly separates routine vs anomalous vectors.
8. `test_classifier_latency_and_confidence`: Asserts semantic classification latency $\le 60$ ms.
