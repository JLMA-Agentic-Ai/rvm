//! Bearer-token authentication and tenant binding.
//!
//! `AGENTLAW_API_KEY` is REQUIRED (the daemon refuses to start without it):
//! - `<secret>`                          -> one key bound to tenant `default`
//! - `<tenant>:<secret>[,<tenant>:<secret>...]` -> one key per tenant
//!
//! The authenticated key determines the tenant; a request can never select
//! another tenant's audit chain or memory scope.

use sha2::{Digest, Sha256};

use crate::kernel_bridge::DEFAULT_TENANT;
use crate::memory::MAX_TENANT_SCOPES;

/// Maximum configured tenants: one precedent scope each, plus the shared scope,
/// so every configured tenant is guaranteed its own precedent quota.
pub const MAX_TENANTS: usize = MAX_TENANT_SCOPES - 1;

pub const API_KEY_ENV: &str = "AGENTLAW_API_KEY";

/// Minimum secret length (e.g. `openssl rand -hex 32` yields 64).
pub const MIN_SECRET_LEN: usize = 32;

/// Tenant ids double as ledger file names, so the alphabet is restricted
/// (no path separators, no leading dot): `[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}`.
pub fn validate_tenant_id(t: &str) -> Result<(), String> {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
    if t.is_empty() || t.len() > 64 || t.starts_with('.') || !t.chars().all(ok_char) {
        return Err(format!("invalid tenant id '{t}' (1-64 chars of [A-Za-z0-9._-], no leading '.')"));
    }
    Ok(())
}

/// Configured API keys (stored as SHA-256 digests only).
#[derive(Clone)]
pub struct ApiKeys {
    entries: Vec<(String, [u8; 32])>,
}

fn digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Constant-time equality of two digests.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl ApiKeys {
    /// Read and parse `AGENTLAW_API_KEY`. Missing / empty / malformed -> error.
    pub fn from_env() -> Result<Self, String> {
        let raw = std::env::var(API_KEY_ENV)
            .map_err(|_| format!("{API_KEY_ENV} is not set; refusing to serve an unauthenticated API"))?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(format!("{API_KEY_ENV} is empty"));
        }
        let pairs: Vec<(String, String)> = if raw.contains(':') {
            raw.split(',')
                .map(|item| {
                    let (t, s) = item
                        .trim()
                        .split_once(':')
                        .ok_or_else(|| format!("{API_KEY_ENV}: entry '{}' is not <tenant>:<secret>", item.trim()))?;
                    Ok((t.trim().to_string(), s.trim().to_string()))
                })
                .collect::<Result<_, String>>()?
        } else {
            vec![(DEFAULT_TENANT.to_string(), raw.to_string())]
        };

        if pairs.len() > MAX_TENANTS {
            return Err(format!("{API_KEY_ENV}: {} tenants configured, maximum is {MAX_TENANTS}", pairs.len()));
        }
        let mut entries: Vec<(String, [u8; 32])> = Vec::with_capacity(pairs.len());
        for (tenant, secret) in pairs {
            validate_tenant_id(&tenant)?;
            if secret.len() < MIN_SECRET_LEN {
                return Err(format!("{API_KEY_ENV}: secret for tenant '{tenant}' is shorter than {MIN_SECRET_LEN} chars"));
            }
            let d = digest(&secret);
            if entries.iter().any(|(t, e)| t == &tenant || ct_eq(e, &d)) {
                return Err(format!("{API_KEY_ENV}: duplicate tenant or secret for '{tenant}'"));
            }
            entries.push((tenant, d));
        }
        Ok(Self { entries })
    }

    /// Resolve an `Authorization` header value to its tenant. Every configured
    /// key is compared (no early exit) in constant time.
    pub fn authenticate(&self, authorization: Option<&str>) -> Option<String> {
        let header = authorization?.trim();
        let (scheme, token) = header.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        let d = digest(token);
        let mut found = None;
        for (tenant, key) in &self.entries {
            if ct_eq(key, &d) {
                found = Some(tenant.clone());
            }
        }
        found
    }

    pub fn tenants(&self) -> Vec<String> {
        self.entries.iter().map(|(t, _)| t.clone()).collect()
    }
}
