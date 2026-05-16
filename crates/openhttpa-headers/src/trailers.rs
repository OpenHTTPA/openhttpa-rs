// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! `Attest-Ticket` request trailer and `Attest-Binder` response trailer.
//!
//! Per the `OpenHTTPA` protocol:
//!
//! * **`Attest-Ticket`** — carried as a trailing header on the last `TrR`
//!   request. It contains the session nonce and a MAC covering the request
//!   body.
//! * **`Attest-Binder`** — carried as a trailing header on the last `TrR`
//!   response. It contains a MAC that binds the response body to the session.
//!
//! Both values are base64-encoded binary blobs.

use base64ct::{Base64, Encoding as _};
use http::{HeaderMap, HeaderValue};
use thiserror::Error;

use crate::{HDR_ATTEST_BINDER, HDR_ATTEST_TICKET};

/// Errors related to trailer decoding.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum TrailerError {
    #[error("missing trailer: {name}")]
    Missing { name: String },
    #[error("invalid trailer value for {name}: {reason}")]
    Invalid { name: String, reason: String },
}

// ─── Attest-Ticket ───────────────────────────────────────────────────────────

/// Encodes the `Attest-Ticket` trailing header.
///
/// `nonce` is the 64-bit monotonic counter, `mac` is the HMAC-SHA-384 of the
/// canonicalised request. Optional `salt` is used for 0-RTT key derivation.
#[must_use]
pub fn encode_attest_ticket(nonce: u64, mac: &[u8], salt: Option<[u8; 16]>) -> HeaderValue {
    let mut payload = nonce.to_be_bytes().to_vec();
    if let Some(s) = salt {
        payload.push(1u8); // 0-RTT mode
        payload.extend_from_slice(&s);
    } else {
        payload.push(0u8); // 1-RTT mode
    }
    payload.extend_from_slice(mac);
    HeaderValue::from_str(&Base64::encode_string(&payload)).unwrap_or(HeaderValue::from_static(""))
}

/// Decoded payload from an `Attest-Ticket` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTicket {
    /// 64-bit monotonic counter.
    pub nonce: u64,
    /// HMAC-SHA-384 MAC covering the request.
    pub mac: Vec<u8>,
    /// Optional salt for 0-RTT key derivation (SA-05).
    pub salt: Option<[u8; 16]>,
}

/// Decodes the `Attest-Ticket` trailing header from a [`HeaderMap`].
///
/// # Panics
/// Never panics in practice; the slice length is verified to be ≥ 9 before
/// the `try_into().unwrap()` calls.
///
/// # Errors
/// Returns [`Err`] if the trailer is missing, contains invalid UTF-8, fails
/// base64 decoding, or the decoded payload is too short.
pub fn decode_attest_ticket(map: &HeaderMap) -> Result<DecodedTicket, TrailerError> {
    let val = map
        .get(&*HDR_ATTEST_TICKET)
        .ok_or_else(|| TrailerError::Missing {
            name: "attest-ticket".to_owned(),
        })?;
    let s = val.to_str().map_err(|e| TrailerError::Invalid {
        name: "attest-ticket".to_owned(),
        reason: e.to_string(),
    })?;
    let bytes = Base64::decode_vec(s).map_err(|e| TrailerError::Invalid {
        name: "attest-ticket".to_owned(),
        reason: e.to_string(),
    })?;
    if bytes.len() < 9 {
        return Err(TrailerError::Invalid {
            name: "attest-ticket".to_owned(),
            reason: "payload too short".to_owned(),
        });
    }
    let nonce = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let mode = bytes[8];
    if mode == 1 {
        if bytes.len() < 9 + 16 {
            return Err(TrailerError::Invalid {
                name: "attest-ticket".to_owned(),
                reason: "0-RTT salt missing".to_owned(),
            });
        }
        let salt = bytes[9..25].try_into().unwrap();
        let mac = bytes[25..].to_vec();
        Ok(DecodedTicket {
            nonce,
            mac,
            salt: Some(salt),
        })
    } else {
        let mac = bytes[9..].to_vec();
        Ok(DecodedTicket {
            nonce,
            mac,
            salt: None,
        })
    }
}

// ─── Attest-Binder ───────────────────────────────────────────────────────────

/// Encodes the `Attest-Binder` trailing header.
///
/// `request_nonce` mirrors the ticket nonce; `mac` covers the response.
#[must_use]
pub fn encode_attest_binder(request_nonce: u64, mac: &[u8]) -> HeaderValue {
    let mut payload = request_nonce.to_be_bytes().to_vec();
    payload.extend_from_slice(mac);
    HeaderValue::from_str(&Base64::encode_string(&payload)).unwrap_or(HeaderValue::from_static(""))
}

/// Decode the `Attest-Binder` trailing header. Returns `(request_nonce, mac)`.
///
/// # Panics
/// Never panics in practice; the slice length is verified to be ≥ 8 before
/// the `try_into().unwrap()` call.
///
/// # Errors
/// Returns [`Err`] if the trailer is missing, contains invalid UTF-8, fails
/// base64 decoding, or the decoded payload is too short.
pub fn decode_attest_binder(map: &HeaderMap) -> Result<(u64, Vec<u8>), TrailerError> {
    let val = map
        .get(&*HDR_ATTEST_BINDER)
        .ok_or_else(|| TrailerError::Missing {
            name: "attest-binder".to_owned(),
        })?;
    let s = val.to_str().map_err(|e| TrailerError::Invalid {
        name: "attest-binder".to_owned(),
        reason: e.to_string(),
    })?;
    let bytes = Base64::decode_vec(s).map_err(|e| TrailerError::Invalid {
        name: "attest-binder".to_owned(),
        reason: e.to_string(),
    })?;
    if bytes.len() < 8 {
        return Err(TrailerError::Invalid {
            name: "attest-binder".to_owned(),
            reason: "payload too short".to_owned(),
        });
    }
    let nonce = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    Ok((nonce, bytes[8..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trip() {
        let mac = vec![0x01u8; 48];
        let hv = encode_attest_ticket(42, &mac, None);
        let mut map = HeaderMap::new();
        map.insert(HDR_ATTEST_TICKET.clone(), hv);
        let decoded = decode_attest_ticket(&map).unwrap();
        assert_eq!(decoded.nonce, 42);
        assert_eq!(decoded.mac, mac);
        assert_eq!(decoded.salt, None);
    }

    #[test]
    fn ticket_0rtt_round_trip() {
        let mac = vec![0xAAu8; 48];
        let salt = [0xBBu8; 16];
        let hv = encode_attest_ticket(123, &mac, Some(salt));
        let mut map = HeaderMap::new();
        map.insert(HDR_ATTEST_TICKET.clone(), hv);
        let decoded = decode_attest_ticket(&map).unwrap();
        assert_eq!(decoded.nonce, 123);
        assert_eq!(decoded.mac, mac);
        assert_eq!(decoded.salt, Some(salt));
    }

    #[test]
    fn binder_round_trip() {
        let mac = vec![0x02u8; 48];
        let hv = encode_attest_binder(7, &mac);
        let mut map = HeaderMap::new();
        map.insert(HDR_ATTEST_BINDER.clone(), hv);
        let (nonce, decoded_mac) = decode_attest_binder(&map).unwrap();
        assert_eq!(nonce, 7);
        assert_eq!(decoded_mac, mac);
    }
}
