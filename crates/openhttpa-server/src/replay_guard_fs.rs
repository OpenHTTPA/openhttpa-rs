// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_core::replay_guard::ReplayGuard;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

/// A file-backed wrapper around `ReplayGuard` for persistent anti-replay protection.
pub struct FileReplayGuard<const W: usize = 64> {
    guard: ReplayGuard<W>,
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct ReplayState {
    highest: u64,
    window: Vec<u64>,
}

impl<const W: usize> FileReplayGuard<W> {
    /// Create a new file-backed replay guard. Loads state from `path` if it exists.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        let guard = ReplayGuard::new();
        if path.exists() {
            if let Ok(data) = fs::read(&path) {
                if let Ok(state) = serde_json::from_slice::<ReplayState>(&data) {
                    if state.window.len() == W {
                        let mut window = [0u64; W];
                        window.copy_from_slice(&state.window);
                        guard.import_state(state.highest, window);
                    }
                }
            }
        }
        Self { guard, path }
    }

    /// Check if a nonce is valid.
    ///
    /// # Errors
    /// Returns `ReplayError::Replay` if the nonce has already been seen, or
    /// `ReplayError::TooOld` if it falls outside the window.
    pub fn check(&self, nonce: u64) -> Result<(), openhttpa_core::replay_guard::ReplayError> {
        self.guard.check(nonce)
    }

    /// Accept a nonce and persist the new state to disk.
    ///
    /// # Errors
    /// Returns an `io::Error` if the state could not be persisted to disk.
    #[must_use = "persisting replay state may fail; dropping this error leaves the guard out of sync with disk"]
    pub fn accept(&self, nonce: u64) -> std::io::Result<()> {
        self.guard.accept(nonce);
        self.persist()
    }

    fn persist(&self) -> std::io::Result<()> {
        let (highest, window) = self.guard.export_state();
        let state = ReplayState {
            highest,
            window: window.to_vec(),
        };
        let data = serde_json::to_vec(&state).map_err(std::io::Error::other)?;

        // [Expert Recommendation: Atomic Writes]
        // Write to a temporary file first, then rename to ensure atomicity.
        let mut tmp_path = self.path.clone();
        tmp_path.set_extension("tmp");

        // FS-PERM-01: use OpenOptions + mode(0o600) on Unix so the replay
        // state file is readable only by the owner — not world-readable.
        // Matches the pattern used by FileNonceStorage and FileTicketEngine.
        let tmp_file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp_path)?
            }
            #[cfg(not(unix))]
            {
                fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp_path)?
            }
        };
        {
            let mut f = tmp_file;
            f.write_all(&data)?;
        }
        fs::rename(&tmp_path, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_file_replay_guard_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("replay.json");

        {
            let guard = FileReplayGuard::<4>::new(path.clone());
            guard.accept(100).unwrap();
            guard.accept(101).unwrap();
        }

        // Re-load from same file
        let guard = FileReplayGuard::<4>::new(path);
        assert!(guard.check(100).is_err()); // Replay
        assert!(guard.check(101).is_err()); // Replay
        assert!(guard.check(102).is_ok()); // Fresh
    }

    #[test]
    fn test_file_replay_guard_window() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("replay_window.json");

        let guard = FileReplayGuard::<1>::new(path); // Window = 1*64 = 64
        guard.accept(1000).unwrap();

        // 1000 - 64 = 936. So 935 should be too old.
        assert!(guard.check(935).is_err());
        assert!(guard.check(950).is_ok());
    }
}
