// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_crypto::hkdf::SessionKeys;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper around [`SessionKeys`] that prevents accidental logging or leakage
/// of raw key material.
///
/// This struct implements [`Debug`] by redacting all sensitive fields, while
/// still allowing [`Serialize`] and [`Deserialize`] for session persistence.
/// The internal [`SessionKeys`] remains protected by [`Zeroize`].
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SealedSessionKeys(SessionKeys);

impl SealedSessionKeys {
    /// Create a new sealed wrapper around session keys.
    #[must_use]
    pub const fn new(keys: SessionKeys) -> Self {
        Self(keys)
    }

    /// Access the underlying session keys.
    ///
    /// # Security
    /// Use this sparingly and only at the point of cryptographic operation.
    /// Never log or store the returned reference.
    #[must_use]
    pub const fn unseal(&self) -> &SessionKeys {
        &self.0
    }
}

impl std::fmt::Debug for SealedSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSessionKeys")
            .field("master_secret", &"[REDACTED]")
            .field("client_write_key", &"[REDACTED]")
            .field("server_write_key", &"[REDACTED]")
            .field("client_write_iv", &"[REDACTED]")
            .field("server_write_iv", &"[REDACTED]")
            .field("client_mac_key", &"[REDACTED]")
            .field("server_mac_key", &"[REDACTED]")
            .finish()
    }
}

impl From<SessionKeys> for SealedSessionKeys {
    fn from(keys: SessionKeys) -> Self {
        Self::new(keys)
    }
}
