// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_core::session::ticket::{TicketEngine, TicketKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A wrapper around `TicketEngine` that persists master keys to disk.
///
/// Addresses RR-02 (Ticket Master Key Persistence).
pub struct FileTicketEngine {
    engine: TicketEngine,
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct TicketKeyState {
    key: [u8; 32],
    counter: u64,
}

#[derive(Serialize, Deserialize)]
struct EngineState {
    current: TicketKeyState,
    previous: Option<TicketKeyState>,
}

/// Errors that can occur when loading or persisting a `FileTicketEngine`.
#[non_exhaustive]
#[derive(Debug)]
pub enum TicketEngineError {
    /// The key file exists but could not be read.
    Io(std::io::Error),
    /// The key file exists but its contents are corrupt or tampered.
    ///
    /// SEC-02: Silent re-keying on a bad key file would invalidate all
    /// outstanding session tickets. Callers must decide whether to abort or
    /// rotate.
    Corrupt(String),
}

impl std::fmt::Display for TicketEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error reading ticket key file: {e}"),
            Self::Corrupt(msg) => write!(f, "ticket key file corrupt or tampered: {msg}"),
        }
    }
}

impl std::error::Error for TicketEngineError {}

impl FileTicketEngine {
    /// Create a new file-backed ticket engine.
    ///
    /// If the file exists its contents are loaded; a parse failure returns
    /// `Err(TicketEngineError::Corrupt)` rather than silently re-keying
    /// (SEC-02). If the file does not exist fresh keys are generated and
    /// persisted.
    ///
    /// # Errors
    /// Returns `Err` if the key file exists but cannot be read or parsed.
    pub fn new(path: PathBuf) -> Result<Self, TicketEngineError> {
        if path.exists() {
            let data = fs::read(&path).map_err(TicketEngineError::Io)?;
            let state = serde_json::from_slice::<EngineState>(&data)
                .map_err(|e| TicketEngineError::Corrupt(e.to_string()))?;
            let current = TicketKey::from_parts(state.current.key, state.current.counter);
            let previous = state
                .previous
                .map(|p| TicketKey::from_parts(p.key, p.counter));
            return Ok(Self {
                engine: TicketEngine::from_parts(current, previous),
                path,
            });
        }

        // No existing file — generate fresh keys and persist.
        let engine = TicketEngine::new(TicketKey::generate());
        let this = Self { engine, path };
        this.persist().map_err(TicketEngineError::Io)?;
        Ok(this)
    }

    /// Access the underlying engine.
    pub const fn engine(&self) -> &TicketEngine {
        &self.engine
    }

    /// Access the underlying engine mutably.
    pub const fn engine_mut(&mut self) -> &mut TicketEngine {
        &mut self.engine
    }

    /// Rotate keys and persist.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if persistence fails.
    pub fn rotate(&mut self) -> std::io::Result<()> {
        self.engine.rotate();
        self.persist()
    }

    /// Persist the current keys to disk.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writing to disk fails or serialization fails.
    pub fn persist(&self) -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let (current, previous) = self.engine.to_parts();
        let (c_key, c_val) = current.to_parts();
        let state = EngineState {
            current: TicketKeyState {
                key: c_key,
                counter: c_val,
            },
            previous: previous.map(|p| {
                let (k, v) = p.to_parts();
                TicketKeyState { key: k, counter: v }
            }),
        };

        let data = serde_json::to_vec(&state).map_err(std::io::Error::other)?;

        // Atomic write with secure permissions (0600)
        let mut tmp_path = self.path.clone();
        tmp_path.set_extension("tmp");

        #[cfg(unix)]
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            let mut file = options.open(&tmp_path)?;
            file.write_all(&data)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp_path, data)?;
        }

        fs::rename(&tmp_path, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── FileTicketEngine::new — happy path ────────────────────────────────

    #[test]
    fn creates_new_engine_when_file_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ticket.key");
        let engine = FileTicketEngine::new(path.clone());
        assert!(
            engine.is_ok(),
            "should create new engine: {:?}",
            engine.err()
        );
        assert!(path.exists(), "key file should be written");
    }

    #[test]
    fn reloads_existing_engine() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ticket.key");
        // Create and drop first instance (persists key).
        let _ = FileTicketEngine::new(path.clone()).unwrap();
        // Second load should succeed and use the same key.
        let engine2 = FileTicketEngine::new(path);
        assert!(
            engine2.is_ok(),
            "should reload persisted engine: {:?}",
            engine2.err()
        );
    }

    // ── FileTicketEngine::new — SEC-02: corrupt key surfaces as Err ───────

    #[test]
    fn corrupt_key_file_returns_err_not_silently_rekeyed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ticket.key");
        // Write garbage content.
        fs::write(&path, b"not valid json at all!!!").unwrap();
        let result = FileTicketEngine::new(path);
        assert!(
            matches!(result, Err(TicketEngineError::Corrupt(_))),
            "corrupt file should return Corrupt, not Ok; got {:?}",
            result.err()
        );
    }

    #[test]
    fn empty_key_file_returns_err_corrupt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ticket.key");
        fs::write(&path, b"").unwrap();
        let result = FileTicketEngine::new(path);
        assert!(
            matches!(result, Err(TicketEngineError::Corrupt(_))),
            "empty file should return Corrupt; got {:?}",
            result.err()
        );
    }

    // ── persist() file permissions (Unix only) ────────────────────────────

    #[cfg(unix)]
    #[test]
    fn key_file_has_owner_only_permissions() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempdir().unwrap();
        let path = dir.path().join("ticket.key");
        FileTicketEngine::new(path.clone()).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode should be 0o600, got {mode:o}");
    }
}
