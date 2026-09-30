//! Lockstep parity: `rvm_agentlaw::poincare_distance` vs substrate-core's
//! `poincareDistance()` (packages/substrate-core/src/prediction-bridge.ts).
//!
//! The fixture is produced by running the REAL TypeScript implementation
//! (`tests/fixtures/gen_poincare_parity.mjs`), so this test fails if either
//! side drifts. Regenerate the fixture whenever the TS function changes.

use rvm_agentlaw::memory::{poincare_distance, POINCARE_EPS};

#[derive(serde::Deserialize)]
struct Case {
    tag: String,
    u: Vec<f64>,
    v: Vec<f64>,
    eps: f64,
    ts: f64,
}

#[derive(serde::Deserialize)]
struct Fixture {
    count: usize,
    cases: Vec<Case>,
}

fn load() -> Fixture {
    let raw = include_str!("fixtures/poincare_parity_ts.json");
    serde_json::from_str(raw).expect("parity fixture must parse")
}

#[test]
fn rust_matches_typescript_on_every_fixture_case() {
    let fx = load();
    assert_eq!(fx.cases.len(), fx.count);
    assert!(fx.count > 500, "fixture too small to be meaningful");

    let mut worst = (0.0f64, String::new());
    for (i, c) in fx.cases.iter().enumerate() {
        let rs = poincare_distance(&c.u, &c.v, c.eps);
        assert!(rs.is_finite(), "case {i} ({}) produced non-finite {rs}", c.tag);
        let abs = (rs - c.ts).abs();
        let rel = abs / c.ts.abs().max(1e-300);
        // Absolute 1e-12 or relative 1e-12, whichever is looser: both sides are
        // IEEE-754 f64 with identical summation order, only acosh() may differ by ulps.
        assert!(
            abs <= 1e-12 || rel <= 1e-12,
            "case {i} ({}) diverges: rust={rs:e} ts={:e} abs={abs:e} rel={rel:e}",
            c.tag,
            c.ts
        );
        if abs > worst.0 {
            worst = (abs, c.tag.clone());
        }
    }
    eprintln!("poincare parity: {} cases, worst abs err {:e} ({})", fx.count, worst.0, worst.1);
}

#[test]
fn memory_engine_uses_substrate_core_default_eps() {
    // substrate-core's poincareDistance default is eps = 1e-5, aligned with the
    // kernel's POINCARE_MAX_NORM = 1 - 1e-5 (manifold.rs). The memory engine
    // must use the same shell or near-rim distances diverge.
    assert_eq!(POINCARE_EPS, 1e-5);
}

#[test]
fn invalid_inputs_fail_closed() {
    // Mismatched / empty / non-finite inputs must never look like "identical" (0.0).
    assert_eq!(poincare_distance(&[], &[], POINCARE_EPS), f64::MAX);
    assert_eq!(poincare_distance(&[0.1, 0.2], &[0.1], POINCARE_EPS), f64::MAX);
    assert_eq!(poincare_distance(&[f64::NAN, 0.0], &[0.0, 0.0], POINCARE_EPS), f64::MAX);
    assert_eq!(poincare_distance(&[f64::INFINITY, 0.0], &[0.0, 0.0], POINCARE_EPS), f64::MAX);
}
