//! Durable append-only witness ledger: one JSON object per line, fsync'd per append.
//!
//! Fail-closed semantics:
//! - a record is appended and `fsync`ed BEFORE it is committed in memory, so an
//!   acknowledged witness record always survives a process restart;
//! - a failed append poisons the ledger (a torn line may be on disk) and every
//!   later append is refused;
//! - on reload, a torn / unparsable / unknown-field line is an error, never skipped.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Current on-disk record version.
pub const LEDGER_VERSION: u32 = 1;

/// One persisted witness record (all binary fields hex-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    pub v: u32,
    pub tenant_id: String,
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub action_kind: u8,
    pub action_name: String,
    pub partition_id: u16,
    pub payload_hex: String,
    pub prev_hash_hex: String,
    pub record_hash_hex: String,
    pub chain_hash_hex: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// Append handle to a ledger file.
pub struct LedgerFile {
    path: PathBuf,
    file: File,
    poisoned: bool,
}

impl LedgerFile {
    /// Open (creating if absent) and return every record already on disk.
    pub fn open(path: &Path) -> Result<(Self, Vec<LedgerRecord>), String> {
        let parent = path.parent().ok_or_else(|| format!("ledger path {} has no parent", path.display()))?;
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        let existed = path.exists();

        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("cannot open ledger {}: {e}", path.display()))?;

        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .map_err(|e| format!("cannot read ledger {}: {e}", path.display()))?;
        if !raw.is_empty() && !raw.ends_with('\n') {
            return Err(format!(
                "ledger {} ends with a torn (unterminated) record; refusing to start",
                path.display()
            ));
        }
        let mut records = Vec::new();
        for (i, line) in raw.lines().enumerate() {
            let rec: LedgerRecord = serde_json::from_str(line)
                .map_err(|e| format!("ledger {} line {}: unparsable record: {e}", path.display(), i + 1))?;
            if rec.v != LEDGER_VERSION {
                return Err(format!("ledger {} line {}: unsupported version {}", path.display(), i + 1, rec.v));
            }
            records.push(rec);
        }

        if !existed {
            // Persist the new directory entry itself.
            File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|e| format!("cannot fsync ledger directory {}: {e}", parent.display()))?;
        }

        Ok((Self { path: path.to_path_buf(), file, poisoned: false }, records))
    }

    /// Append one record and fsync it. Any failure poisons this handle.
    pub fn append(&mut self, record: &LedgerRecord) -> Result<(), String> {
        if self.poisoned {
            return Err(format!("ledger {} is poisoned by an earlier write failure", self.path.display()));
        }
        let mut line = serde_json::to_string(record).map_err(|e| format!("cannot encode ledger record: {e}"))?;
        line.push('\n');
        let res = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.sync_data())
            .map_err(|e| format!("ledger {} append/fsync failed: {e}", self.path.display()));
        if res.is_err() {
            self.poisoned = true;
        }
        res
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
