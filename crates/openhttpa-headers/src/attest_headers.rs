// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Typed encode/decode for all `Attest-*` HTTP header fields.
//!
//! **IETF-02 / IANA registration TODO**: The `Attest-*` header field names
//! defined in this module (`Attest-Cipher-Suites`, `Attest-Random`,
//! `Attest-Key-Shares`, `Attest-Challenge`, `Attest-Quotes`, etc.) should be
//! registered in the IANA "Hypertext Transfer Protocol (HTTP) Field Name
//! Registry" (RFC 9110 §16.3.1) once the `OpenHTTPA` specification is submitted
//! to the IETF.  Until that point, the `Attest-` prefix serves as a vendor
//! prefix that is unlikely to conflict with standardised fields.
//!
//! ## Encoding rules
//!
//! All header values follow **RFC 8941 Structured Field Values** (SFV):
//!
//! | Field kind              | SFV type          | Example wire value                     |
//! |-------------------------|-------------------|----------------------------------------|
//! | Binary blobs (keys, nonces) | `Item` – `Byte Sequence` | `:aGVsbG8=:` |
//! | String token lists      | `List` of `Token` | `X25519_ML_KEM768, openhttpa`            |
//! | Scalar strings          | `Item` – `Token`  | `new`                                  |
//! | Integer values          | `Item` – `Integer`| `3600`                                 |
//!
//! The `sfv` crate (version 0.14) handles the SFV serialisation and parsing.
//! Binary items use **base64url** (no-padding) encoding as mandated by RFC 8941
//! §4.1.8 — this is handled transparently by the `ByteSequence` variant.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use openhttpa_headers::attest_headers::{AtHsRequestHeaders, AtHsResponseHeaders};
//! use openhttpa_proto::{AtbCreation, CipherSuite, ProtocolVersion};
//! use http::HeaderMap;
//!
//! // Build and encode request headers (client side).
//! let req = AtHsRequestHeaders {
//!     cipher_suites: vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
//!     random: vec![0u8; 32],
//!     versions: vec![ProtocolVersion::V2],
//!     key_shares_json: b"{}".to_vec(),
//!     date: "2026-04-27T00:00:00Z".to_owned(),
//!     base_creation: AtbCreation::New,
//!     direct_attestation: true,
//!     allow_untrusted_requests: false,
//!     client_quotes: vec![],
//!     challenge: Some(vec![0u8; 32]),
//!     signatures: vec![],
//!     ticket: None,
//!     provenance: None,
//! };
//! let header_map: HeaderMap = req.encode();
//!
//! // Decode on the server side.
//! let decoded = AtHsRequestHeaders::decode(&header_map).unwrap();
//! ```

use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use sfv::{BareItem, Dictionary, FieldType, Item, List, ListEntry, Parser, Token};
use thiserror::Error;

use openhttpa_proto::{
    AtbCreation, AtbId, AtbTermination, AttestQuote, AttestSecret, CipherSuite, ProtocolVersion,
    ProvenanceChain, QuoteType, SessionTicket, TrustedCargo,
};

// ─── Header name constants ────────────────────────────────────────────────────
// All header names are lowercase per RFC 7230 and stored as lazily-initialised
// statics so they are interned once and reused without allocation.

macro_rules! header_name {
    ($ident:ident, $value:expr) => {
        /// RFC 8941 header field name constant.
        pub static $ident: std::sync::LazyLock<HeaderName> =
            std::sync::LazyLock::new(|| HeaderName::from_static($value));
    };
}

header_name!(HDR_ATTEST_CIPHER_SUITES, "attest-cipher-suites");
header_name!(
    HDR_ATTEST_SUPPORTED_CIPHER_SUITES,
    "attest-supported-cipher-suites"
);
header_name!(HDR_ATTEST_CIPHER_SUITE, "attest-cipher-suite");
header_name!(HDR_ATTEST_SUPPORTED_GROUPS, "attest-supported-groups");
header_name!(HDR_ATTEST_KEY_SHARES, "attest-key-shares");
header_name!(HDR_ATTEST_KEY_SHARE, "attest-key-share");
header_name!(HDR_ATTEST_RANDOM, "attest-random");
header_name!(HDR_ATTEST_POLICIES, "attest-policies");
header_name!(HDR_ATTEST_BASE_CREATION, "attest-base-creation");
header_name!(HDR_ATTEST_BLOCKLIST, "attest-blocklist");
header_name!(HDR_ATTEST_VERSIONS, "attest-versions");
header_name!(HDR_ATTEST_SUPPORTED_VERSIONS, "attest-supported-versions");
header_name!(HDR_ATTEST_DATE, "attest-date");
header_name!(HDR_ATTEST_SIGNATURES, "attest-signatures");
header_name!(HDR_ATTEST_SERVER_SIGNATURES, "attest-server-signatures");
header_name!(HDR_ATTEST_TRANSPORT, "attest-transport");
header_name!(HDR_ATTEST_QUOTES, "attest-quotes");
header_name!(HDR_ATTEST_BASE_ID, "attest-base-id");
header_name!(HDR_ATTEST_VERSION, "attest-version");
header_name!(HDR_ATTEST_EXPIRES, "attest-expires");
header_name!(HDR_ATTEST_SECRETS, "attest-secrets");
header_name!(HDR_ATTEST_CARGO, "attest-cargo");
header_name!(HDR_ATTEST_TICKET, "attest-ticket");
header_name!(HDR_ATTEST_BINDER, "attest-binder");
header_name!(HDR_ATTEST_BASE_TERMINATION, "attest-base-termination");
header_name!(HDR_ATTEST_CHALLENGE, "attest-challenge");
header_name!(HDR_ATTEST_PROVENANCE, "attest-provenance");
header_name!(HDR_ATTEST_TICKET_RESUMPTION, "attest-ticket-resumption");
header_name!(HDR_ATTEST_ZK_PROOF, "attest-zk-proof");
header_name!(HDR_ATTEST_AI_PROVENANCE_PROOF, "attest-ai-provenance-proof");

// ─── AHL canonicalization ────────────────────────────────────────────────────

const MAX_AHL_HEADERS: usize = 64;
const MAX_AHL_HEADER_NAME_LEN: usize = 256;
const MAX_AHL_HEADER_VALUE_LEN: usize = 4096;

/// Construct a canonical byte representation of the request/response context,
/// including the HTTP method, URI path, and all `Attest-*` headers.
///
/// This AHL (Attest Header List) is used as the input to the MAC calculation
/// for `Attest-Ticket` and `Attest-Binder`. Binding the method and path
/// prevents semantic re-routing attacks (C-AHL-1).
/// Canonicalise the Attested Header List (AHL) into a byte stream for MAC
/// calculation or quote QUDD binding.
///
/// Implements length-prefixed encoding (C-AHL-1) to ensure semantic integrity
/// and prevent injection.
///
/// # Errors
/// Returns [`HeaderError::TooManyHeaders`] or [`HeaderError::ValueTooLong`] if
/// limits are exceeded.
pub fn canonicalize_ahl(
    method: &str,
    path: &str,
    query: Option<&str>,
    map: &HeaderMap,
) -> Result<Vec<u8>, HeaderError> {
    let mut ahl = Vec::new();
    update_ahl(method, path, query, map, |chunk| {
        ahl.extend_from_slice(chunk);
    })?;

    Ok(ahl)
}

/// Update a streaming hasher or buffer with the canonicalised AHL bytes.
///
/// This avoids allocating a large intermediate `Vec<u8>` when only a digest is
/// needed (e.g. for MAC verification).
///
/// # Errors
/// Returns [`HeaderError`] if limits are exceeded.
pub fn update_ahl<F>(
    method: &str,
    path: &str,
    query: Option<&str>,
    map: &HeaderMap,
    mut update: F,
) -> Result<(), HeaderError>
where
    F: FnMut(&[u8]),
{
    // 1. Bind Method (C-AHL-1)
    let m_upper = method.to_uppercase();
    update(m_upper.len().to_string().as_bytes());
    update(b":");
    update(m_upper.as_bytes());

    // 2. Bind Path (C-AHL-1)
    update(path.len().to_string().as_bytes());
    update(b":");
    update(path.as_bytes());

    // 2b. Bind Query (C-AHL-1) - NEW: Prevent query parameter manipulation.
    let q = query.unwrap_or("");
    update(q.len().to_string().as_bytes());
    update(b":");
    update(q.as_bytes());

    // Debug log for the base AHL (Method, Path, Query)
    // tracing::info!(method = %m_upper, path = %path, query = %q, "AHL base components updated");

    // 3. Bind Attest-* headers
    // Sort Attest-* headers by name for canonicalization.
    let mut names: Vec<_> = map
        .keys()
        .filter(|k| k.as_str().to_lowercase().starts_with("attest-"))
        .filter(|k| {
            let s = k.as_str().to_lowercase();
            s != "attest-ticket" && s != "attest-binder"
        })
        .collect();

    if names.len() > MAX_AHL_HEADERS {
        return Err(HeaderError::TooManyHeaders {
            max: MAX_AHL_HEADERS,
        });
    }

    names.sort_by_key(|n| n.as_str().to_lowercase());

    for name in names {
        // Use length-prefixing for name and value to prevent injection (C-AHL-1).
        // Enforce lowercase name to ensure canonical hashing regardless of transport casing.
        let name_str = name.as_str().to_lowercase();
        if name_str.len() > MAX_AHL_HEADER_NAME_LEN {
            return Err(HeaderError::ValueTooLong { name: name_str });
        }

        update(name_str.len().to_string().as_bytes());
        update(b":");
        update(name_str.as_bytes());

        // RFC 8941 §3.2: Join multiple values of the same header with commas.
        let values: Vec<_> = map
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();

        let val_str = values.join(",");
        if val_str.len() > MAX_AHL_HEADER_VALUE_LEN {
            return Err(HeaderError::ValueTooLong { name: name_str });
        }

        update(val_str.len().to_string().as_bytes());
        update(b":");
        update(val_str.as_bytes());

        // Debug log for each header included in AHL
        tracing::info!(name = %name_str, value = %val_str, "AHL header included");
    }
    Ok(())
}

// ─── Header errors ───────────────────────────────────────────────────────────

/// Errors that can occur when encoding or decoding `OpenHTTPA` `Attest-*` headers.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum HeaderError {
    /// A required header was absent from the request/response map.
    #[error("missing required header: {name}")]
    Missing { name: String },
    /// A header was present but contained an unparseable value.
    #[error("invalid header value for {name}: {reason}")]
    Invalid { name: String, reason: String },
    /// A binary header contained invalid base64url data.
    #[error("base64 decode error in header {name}: {reason}")]
    Base64 { name: String, reason: String },
    /// Too many headers provided in AHL (`DoS` protection).
    #[error("too many headers in AHL (max {max})")]
    TooManyHeaders { max: usize },
    /// Header name or value exceeds maximum allowed length.
    #[error("header {name} exceeds maximum length")]
    ValueTooLong { name: String },
}

// ─── RFC 8941 encoding helpers ───────────────────────────────────────────────

/// Encode a raw provenance chain (JSON bytes) as an RFC 8941 `Byte Sequence`.
#[must_use]
pub fn encode_attest_provenance(json_bytes: &[u8]) -> HeaderValue {
    encode_bytes_sfv(json_bytes)
}

/// Encode a byte slice as an RFC 8941 `Byte Sequence` (`:base64url:`) item.
///
/// The `sfv` crate uses standard base64url (RFC 4648 §5) with no padding,
/// matching the RFC 8941 §4.1.8 wire format.
fn encode_bytes_sfv(bytes: &[u8]) -> HeaderValue {
    let item = Item::new(BareItem::ByteSequence(bytes.to_vec()));
    let serialized = item.serialize();
    HeaderValue::from_str(&serialized).unwrap_or_else(|_| HeaderValue::from_static("::"))
}

/// Decode an RFC 8941 `Byte Sequence` header value back to raw bytes.
fn decode_bytes_sfv(map: &HeaderMap, name: &HeaderName) -> Result<Vec<u8>, HeaderError> {
    let val = map.get(name).ok_or_else(|| HeaderError::Missing {
        name: name.to_string(),
    })?;
    let s = val.to_str().map_err(|e| HeaderError::Invalid {
        name: name.to_string(),
        reason: e.to_string(),
    })?;

    let item: Item = Parser::new(s).parse().map_err(|e| HeaderError::Invalid {
        name: name.to_string(),
        reason: e.to_string(),
    })?;

    item.bare_item
        .as_byte_sequence()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| HeaderError::Invalid {
            name: name.to_string(),
            reason: "expected a Byte Sequence item".to_owned(),
        })
}

/// Encode a slice of `Display`-able values as an RFC 8941 `List` of `Token`
/// items.  Each value's `Display` string must satisfy the SFV token grammar
/// (start with `[A-Za-z*]`; subsequent chars from `[A-Za-z0-9:.!#$%&'*+-^_|~]`).
fn encode_token_list(values: &[impl std::fmt::Display]) -> HeaderValue {
    let list: List = values
        .iter()
        .map(|v| {
            let s = v.to_string();
            // Build Token, falling back to a quoted string if the value is not
            // a valid SFV token (e.g. contains characters outside the grammar).
            let bare = Token::from_string(s.clone()).map_or_else(
                |(_, _)| {
                    sfv::String::from_string(s).map_or_else(
                        |(_, _)| BareItem::Token(Token::from_string("unknown".to_owned()).unwrap()),
                        BareItem::String,
                    )
                },
                BareItem::Token,
            );
            ListEntry::Item(Item::new(bare))
        })
        .collect();

    list.serialize().map_or_else(
        || HeaderValue::from_static(""),
        |s| HeaderValue::from_str(&s).unwrap_or_else(|_| HeaderValue::from_static("")),
    )
}

/// Decode an RFC 8941 `List` of `Token` (or string) items into a `Vec<String>`.
fn decode_token_list_strings(
    map: &HeaderMap,
    name: &HeaderName,
) -> Result<Vec<String>, HeaderError> {
    let values: Vec<_> = map
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if values.is_empty() {
        return Err(HeaderError::Missing {
            name: name.to_string(),
        });
    }
    let s = values.join(",");

    // An SFV list may serialize to an empty string for zero items.
    if s.trim().is_empty() {
        return Ok(vec![]);
    }

    let list: List = Parser::new(&s).parse().map_err(|e| HeaderError::Invalid {
        name: name.to_string(),
        reason: e.to_string(),
    })?;

    Ok(list
        .into_iter()
        .filter_map(|entry| match entry {
            ListEntry::Item(item) => {
                // Accept both Token and String bare items.
                if let Some(tok) = item.bare_item.as_token() {
                    Some(tok.as_str().to_owned())
                } else {
                    item.bare_item.as_string().map(|s| s.as_str().to_owned())
                }
            }
            ListEntry::InnerList(_) => None,
        })
        .collect())
}

/// Encode an integer as an RFC 8941 `Item` of type `Integer`.
///
/// SFV integers are limited to range [-999,999,999,999,999, 999,999,999,999,999].
fn encode_integer_sfv(n: u64) -> HeaderValue {
    const MAX_SFV_INT: i64 = 999_999_999_999_999;
    let val = i64::try_from(n).unwrap_or(i64::MAX).min(MAX_SFV_INT);
    let item = Item::new(BareItem::Integer(
        sfv::Integer::try_from(val).unwrap_or_default(),
    ));
    HeaderValue::from_str(&item.serialize()).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

/// Encode a token string (e.g. `"new"`, `"openhttpa"`) as an RFC 8941 `Token`
/// item. Used for scalar enum-like fields.
fn encode_token_sfv(s: &str) -> HeaderValue {
    let bare = Token::from_string(s.to_owned()).map_or_else(
        |(_, original)| {
            sfv::String::from_string(original).map_or_else(
                |(_, _)| BareItem::Token(Token::from_string("unknown".to_owned()).unwrap()),
                BareItem::String,
            )
        },
        BareItem::Token,
    );
    let item = Item::new(bare);
    HeaderValue::from_str(&item.serialize()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Decode an RFC 8941 `List` of `Inner List` items into a `Vec<AttestQuote>`.
fn decode_quotes_sfv(map: &HeaderMap, name: &HeaderName) -> Result<Vec<AttestQuote>, HeaderError> {
    let values: Vec<_> = map
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if values.is_empty() {
        return Ok(vec![]);
    }
    let s = values.join(",");
    if s.trim().is_empty() {
        return Ok(vec![]);
    }

    let list: List = Parser::new(&s).parse().map_err(|e| HeaderError::Invalid {
        name: name.to_string(),
        reason: e.to_string(),
    })?;
    let mut quotes = vec![];

    for entry in list {
        if let ListEntry::InnerList(il) = entry {
            if il.items.len() >= 2 {
                let type_str = il.items[0]
                    .bare_item
                    .as_token()
                    .map_or("unknown", |t| t.as_str());
                let bytes = il.items[1]
                    .bare_item
                    .as_byte_sequence()
                    .map_or_else(Vec::new, <[u8]>::to_vec);

                let quote_type = type_str
                    .parse::<QuoteType>()
                    .unwrap_or_else(|_| QuoteType::Unknown(type_str.to_owned()));

                let mut collateral_uris = vec![];
                if il.items.len() > 2 {
                    for i in 2..il.items.len() {
                        if let Some(s) = il.items[i].bare_item.as_string() {
                            collateral_uris.push(s.as_str().to_owned());
                        }
                    }
                }

                quotes.push(AttestQuote {
                    quote_type,
                    raw: bytes.into(),
                    qudd: bytes::Bytes::new(),
                    collateral_uris,
                });
            }
        }
    }
    Ok(quotes)
}

/// Decode an RFC 8941 `Dictionary` into policy flags.
fn decode_policies_sfv(map: &HeaderMap, name: &HeaderName) -> (bool, bool) {
    let mut direct = true;
    let mut allow_untrusted = false;

    let values: Vec<_> = map
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !values.is_empty() {
        let val = values.join(",");
        if let Ok(dict) = Parser::new(&val).parse::<Dictionary>() {
            if let Some(ListEntry::Item(i)) = dict.get("direct") {
                if let Some(b) = i.bare_item.as_boolean() {
                    direct = b;
                }
            }
            if let Some(ListEntry::Item(i)) = dict.get("allow-untrusted") {
                if let Some(b) = i.bare_item.as_boolean() {
                    allow_untrusted = b;
                }
            }
        }
    }
    (direct, allow_untrusted)
}

// ─── AtHS request headers ────────────────────────────────────────────────────

/// The set of `Attest-*` headers sent by the client in the `AtHS` request.
///
/// These are the headers accompanying the `ATTEST` method request that
/// initiates the Attestation Handshake (`AtHS`) phase of the `OpenHTTPA` protocol.
///
/// # Encoding
///
/// | Field                 | Header name                | SFV type       |
/// |-----------------------|----------------------------|----------------|
/// | `cipher_suites`       | `Attest-Cipher-Suites`     | List of Tokens |
/// | `random`              | `Attest-Random`            | Byte Sequence  |
/// | `versions`            | `Attest-Versions`          | List of Tokens |
/// | `key_shares_json`     | `Attest-Key-Shares`        | Byte Sequence  |
/// | `date`                | `Attest-Date`              | String         |
/// | `base_creation`       | `Attest-Base-Creation`     | Token          |
/// | `direct_attestation`  | `Attest-Policies`          | Dictionary     |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtHsRequestHeaders {
    /// Ordered list of cipher suites supported by the client (most-preferred first).
    pub cipher_suites: Vec<CipherSuite>,
    /// 32-byte cryptographically random nonce generated by the client.
    /// Used in the transcript hash to prevent replay of the handshake.
    pub random: Vec<u8>,
    /// Protocol versions supported by the client (most-preferred first).
    pub versions: Vec<ProtocolVersion>,
    /// ECDHE + ML-KEM public key share bytes, JSON-encoded as a
    /// `{"ecdhe_public": "<base64>", "mlkem_public": "<base64>"}` object.
    pub key_shares_json: Vec<u8>,
    /// ISO 8601 UTC timestamp of the request (e.g. `2026-04-27T00:00:00Z`).
    pub date: String,
    /// Requested `AtB` creation mode: `New`, `Reuse`, or `Shared`.
    pub base_creation: AtbCreation,
    /// When `true`, the client requests direct TEE attestation quotes.
    pub direct_attestation: bool,
    /// When `true`, the client permits `TServices` that cannot produce
    /// attestation quotes (useful in test/dev environments).
    pub allow_untrusted_requests: bool,
    /// Optional client-side TEE attestation quotes for mutual attestation
    /// (mHTTPA mode).  Empty in the common server-only attestation flow.
    pub client_quotes: Vec<AttestQuote>,
    /// Server-provided challenge (nonce) to ensure quote freshness (C-TEE-3).
    pub challenge: Option<Vec<u8>>,
    /// Optional client signatures over Attest Header Lists (AHLs), required
    /// when the `Attest-Policies` field requests signature binding.
    pub signatures: Vec<Vec<u8>>,
    /// Optional session ticket for resumption (Phase 5).
    pub ticket: Option<SessionTicket>,
    /// Optional provenance chain for multi-hop tracking (Phase 4).
    pub provenance: Option<ProvenanceChain>,
}

impl AtHsRequestHeaders {
    /// Encode this request into an HTTP [`HeaderMap`] using RFC 8941 SFV.
    ///
    /// Binary fields use the `Byte Sequence` SFV type (base64url no-padding),
    /// string-list fields use `List` of `Token` items.
    /// # Panics
    ///
    /// Never panics; all internal token strings are valid SFV token literals.
    pub fn encode(&self) -> HeaderMap {
        let mut map = HeaderMap::new();

        // RFC 8941 List of Token items for multi-valued string fields.
        map.insert(
            HDR_ATTEST_VERSIONS.clone(),
            encode_token_list(&self.versions),
        );
        map.insert(
            HDR_ATTEST_CIPHER_SUITES.clone(),
            encode_token_list(&self.cipher_suites),
        );

        // Binary fields as RFC 8941 Byte Sequence items (`:base64url:`).
        map.insert(HDR_ATTEST_RANDOM.clone(), encode_bytes_sfv(&self.random));
        map.insert(
            HDR_ATTEST_KEY_SHARES.clone(),
            encode_bytes_sfv(&self.key_shares_json),
        );

        // Policy flags as an SFV Dictionary (key=bool pairs).
        // e.g. `direct=?1, allow-untrusted=?0`
        let policies = format!(
            "direct=?{}, allow-untrusted=?{}",
            u8::from(self.direct_attestation),
            u8::from(self.allow_untrusted_requests),
        );
        map.insert(
            HDR_ATTEST_POLICIES.clone(),
            HeaderValue::from_str(&policies).unwrap_or(HeaderValue::from_static("")),
        );

        // Scalar string fields.
        map.insert(
            HDR_ATTEST_DATE.clone(),
            HeaderValue::from_str(&self.date).unwrap_or(HeaderValue::from_static("")),
        );

        // AtB creation mode as an SFV Token.
        let creation_str = match self.base_creation {
            AtbCreation::Reuse => "reuse",
            AtbCreation::Shared => "shared",
            _ => "new",
        };
        map.insert(
            HDR_ATTEST_BASE_CREATION.clone(),
            encode_token_sfv(creation_str),
        );

        // Quotes: encode as SFV List of Inner Lists — `(type :bytes: "uri1" ...), ...`
        if !self.client_quotes.is_empty() {
            let list: List = self
                .client_quotes
                .iter()
                .map(|q| {
                    let type_str = q.quote_type.to_string();
                    let type_item =
                        Item::new(BareItem::Token(Token::from_string(type_str).unwrap()));
                    let bytes_item = Item::new(BareItem::ByteSequence(q.raw.to_vec()));

                    let mut il_items = vec![type_item, bytes_item];
                    for uri in &q.collateral_uris {
                        il_items.push(Item::new(BareItem::String(
                            sfv::String::from_string(uri.clone()).unwrap(),
                        )));
                    }
                    ListEntry::InnerList(sfv::InnerList::new(il_items))
                })
                .collect();
            if let Some(s) = list.serialize() {
                if let Ok(hv) = HeaderValue::from_str(&s) {
                    map.insert(HDR_ATTEST_QUOTES.clone(), hv);
                }
            }
        }

        if let Some(ref c) = self.challenge {
            map.insert(HDR_ATTEST_CHALLENGE.clone(), encode_bytes_sfv(c));
        }

        if let Some(ref t) = self.ticket {
            if let Ok(json) = serde_json::to_vec(t) {
                map.insert(HDR_ATTEST_TICKET.clone(), encode_bytes_sfv(&json));
            }
        }

        if let Some(ref p) = self.provenance {
            if let Ok(json) = serde_json::to_vec(p) {
                map.insert(
                    HeaderName::from_static("attest-provenance"),
                    encode_bytes_sfv(&json),
                );
            }
        }

        map
    }

    /// Decode an HTTP [`HeaderMap`] into a structured `AtHsRequestHeaders`.
    ///
    /// # Errors
    /// Returns [`Err`] if a required header is absent or contains an invalid value.
    pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError> {
        // Binary fields.
        let random = decode_bytes_sfv(map, &HDR_ATTEST_RANDOM)?;
        let key_shares_json = decode_bytes_sfv(map, &HDR_ATTEST_KEY_SHARES)?;

        // Scalar fields with sensible defaults.
        let date = map
            .get(&*HDR_ATTEST_DATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();

        let base_creation = match map
            .get(&*HDR_ATTEST_BASE_CREATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("new")
            // Strip SFV token decoration if present
            .trim()
        {
            "reuse" => AtbCreation::Reuse,
            "shared" => AtbCreation::Shared,
            _ => AtbCreation::New,
        };

        // RFC 8941 List of Token items for cipher suites.
        let cipher_suite_strs = decode_token_list_strings(map, &HDR_ATTEST_CIPHER_SUITES)?;
        let cipher_suites: Vec<CipherSuite> = cipher_suite_strs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        if cipher_suites.is_empty() {
            return Err(HeaderError::Missing {
                name: HDR_ATTEST_CIPHER_SUITES.to_string(),
            });
        }

        // Protocol versions.
        let version_strs = decode_token_list_strings(map, &HDR_ATTEST_VERSIONS)?;
        let versions: Vec<ProtocolVersion> =
            version_strs.iter().filter_map(|s| s.parse().ok()).collect();
        if versions.is_empty() {
            return Err(HeaderError::Missing {
                name: HDR_ATTEST_VERSIONS.to_string(),
            });
        }

        let client_quotes = decode_quotes_sfv(map, &HDR_ATTEST_QUOTES)?;
        let (direct_attestation, allow_untrusted_requests) =
            decode_policies_sfv(map, &HDR_ATTEST_POLICIES);

        let challenge = decode_bytes_sfv(map, &HDR_ATTEST_CHALLENGE).ok();

        let ticket = decode_bytes_sfv(map, &HDR_ATTEST_TICKET)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let provenance = decode_bytes_sfv(map, &HeaderName::from_static("attest-provenance"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());

        Ok(Self {
            cipher_suites,
            random,
            versions,
            key_shares_json,
            date,
            base_creation,
            direct_attestation,
            allow_untrusted_requests,
            client_quotes,
            challenge,
            signatures: vec![],
            ticket,
            provenance,
        })
    }
}

// ─── AtHS response headers ───────────────────────────────────────────────────

/// The set of `Attest-*` headers sent by the `TService` in the `AtHS` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtHsResponseHeaders {
    /// The selected cipher suite.
    pub cipher_suite: CipherSuite,
    /// 32-byte random nonce from the server.
    pub random: Vec<u8>,
    /// Server's ECDHE + PQC key share (JSON-encoded).
    pub key_share_json: Vec<u8>,
    /// Allocated `AtB` identifier.
    pub base_id: AtbId,
    /// Selected HTTPA version.
    pub version: ProtocolVersion,
    /// `AtB` TTL (seconds).
    pub expires_secs: u64,
    /// Server's TEE attestation quotes.
    pub quotes: Vec<AttestQuote>,
    /// Optional server-provisioned secrets.
    pub secrets: Vec<AttestSecret>,
    /// Optional trusted cargo.
    pub cargo: Option<TrustedCargo>,
    /// Optional ticket for future session resumption.
    pub ticket_resumption: Option<SessionTicket>,
    /// Optional ML-DSA (Post-Quantum) signatures over the transcript hash from the server.
    pub server_signatures: Vec<Vec<u8>>,
    /// Optional ZK proof (succinct receipt) covering the attestation.
    pub zk_proof: Option<Vec<u8>>,
}

impl AtHsResponseHeaders {
    /// Encode this response into an HTTP [`HeaderMap`] using RFC 8941 SFV.
    ///
    /// - Binary fields (random, key share) → `Byte Sequence` items.
    /// - Scalar string fields (cipher suite, version) → `Token` items.
    /// - Integer field (expires) → `Integer` item.
    /// - Quotes → RFC 8941 `List` of `Inner List` items, each inner list
    ///   containing `(type_token bytes_sequence)`.
    ///
    /// # Panics
    /// Never panics; all internal token strings are valid SFV token literals.
    pub fn encode(&self) -> HeaderMap {
        let mut map = HeaderMap::new();

        map.insert(
            HDR_ATTEST_VERSION.clone(),
            encode_token_sfv(&self.version.to_string()),
        );
        map.insert(
            HDR_ATTEST_CIPHER_SUITE.clone(),
            encode_token_sfv(&self.cipher_suite.to_string()),
        );
        map.insert(HDR_ATTEST_RANDOM.clone(), encode_bytes_sfv(&self.random));
        map.insert(
            HDR_ATTEST_KEY_SHARE.clone(),
            encode_bytes_sfv(&self.key_share_json),
        );

        // AtB identifier is a UUID string — not a valid SFV token due to `-`
        // characters at fixed positions (hyphens are valid in tokens).
        map.insert(
            HDR_ATTEST_BASE_ID.clone(),
            HeaderValue::from_str(&self.base_id.to_string())
                .unwrap_or(HeaderValue::from_static("")),
        );

        // Expires as RFC 8941 Integer item.
        map.insert(
            HDR_ATTEST_EXPIRES.clone(),
            encode_integer_sfv(self.expires_secs),
        );

        // Quotes: encode as SFV List of Inner Lists — `(type :bytes: "uri1" ...), ...`
        // so decoders can easily extract both the TEE type and the raw bytes.
        if !self.quotes.is_empty() {
            let list: List = self
                .quotes
                .iter()
                .map(|q| {
                    let type_str = q.quote_type.to_string();
                    let type_item =
                        Item::new(BareItem::Token(Token::from_string(type_str).unwrap()));
                    let bytes_item = Item::new(BareItem::ByteSequence(q.raw.to_vec()));

                    let mut il_items = vec![type_item, bytes_item];
                    for uri in &q.collateral_uris {
                        il_items.push(Item::new(BareItem::String(
                            sfv::String::from_string(uri.clone()).unwrap(),
                        )));
                    }
                    ListEntry::InnerList(sfv::InnerList::new(il_items))
                })
                .collect();
            if let Some(s) = list.serialize() {
                if let Ok(hv) = HeaderValue::from_str(&s) {
                    map.insert(HDR_ATTEST_QUOTES.clone(), hv);
                }
            }
        }

        if let Some(ref t) = self.ticket_resumption {
            if let Ok(json) = serde_json::to_vec(t) {
                map.insert(
                    HeaderName::from_static("attest-ticket-resumption"),
                    encode_bytes_sfv(&json),
                );
            }
        }

        if !self.server_signatures.is_empty() {
            let list: List = self
                .server_signatures
                .iter()
                .map(|sig| ListEntry::Item(Item::new(BareItem::ByteSequence(sig.clone()))))
                .collect();
            if let Some(s) = list.serialize() {
                if let Ok(hv) = HeaderValue::from_str(&s) {
                    map.insert(HDR_ATTEST_SERVER_SIGNATURES.clone(), hv);
                }
            }
        }

        if let Some(ref proof) = self.zk_proof {
            map.insert(HDR_ATTEST_ZK_PROOF.clone(), encode_bytes_sfv(proof));
        }

        map
    }

    /// Decode an HTTP [`HeaderMap`] into a structured `AtHsResponseHeaders`.
    ///
    /// # Errors
    /// Returns [`Err`] if a required header is absent or contains an invalid value.
    pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError> {
        let random = decode_bytes_sfv(map, &HDR_ATTEST_RANDOM)?;
        let key_share_json = decode_bytes_sfv(map, &HDR_ATTEST_KEY_SHARE)?;

        let base_id_str = map
            .get(&*HDR_ATTEST_BASE_ID)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| HeaderError::Missing {
                name: "attest-base-id".to_owned(),
            })?;
        let base_id: AtbId =
            base_id_str
                .parse()
                .map_err(|e: uuid::Error| HeaderError::Invalid {
                    name: "attest-base-id".to_owned(),
                    reason: e.to_string(),
                })?;

        // `Attest-Expires` may be an SFV Integer (new format) or a plain decimal
        // string (legacy fallback) — accept both.
        let expires_secs: u64 = map
            .get(&*HDR_ATTEST_EXPIRES)
            .and_then(|v| v.to_str().ok())
            .map_or(3600, |s| {
                // Try SFV Integer parse first.
                Parser::new(s)
                    .parse::<Item>()
                    .ok()
                    .and_then(|item| item.bare_item.as_integer().map(|n| u64::try_from(n).unwrap_or(3600)))
                    // Fall back to plain u64 parse (e.g. "3600").
                    .or_else(|| s.trim().parse::<u64>().ok())
                    .unwrap_or(3600)
            });

        // Cipher suite: SFV Token or plain string.
        let cs_str = map
            .get(&*HDR_ATTEST_CIPHER_SUITE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| HeaderError::Missing {
                name: HDR_ATTEST_CIPHER_SUITE.to_string(),
            })?;
        let cipher_suite =
            cs_str
                .trim()
                .parse::<CipherSuite>()
                .map_err(|()| HeaderError::Invalid {
                    name: HDR_ATTEST_CIPHER_SUITE.to_string(),
                    reason: "unrecognised cipher suite".to_owned(),
                })?;

        // Version: SFV Token or plain string.
        let ver_str = map
            .get(&*HDR_ATTEST_VERSION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| HeaderError::Missing {
                name: HDR_ATTEST_VERSION.to_string(),
            })?;
        let version =
            ver_str
                .trim()
                .parse::<ProtocolVersion>()
                .map_err(|()| HeaderError::Invalid {
                    name: HDR_ATTEST_VERSION.to_string(),
                    reason: "unrecognised protocol version".to_owned(),
                })?;

        let quotes = decode_quotes_sfv(map, &HDR_ATTEST_QUOTES)?;

        let ticket_resumption =
            decode_bytes_sfv(map, &HeaderName::from_static("attest-ticket-resumption"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());

        let mut server_signatures = vec![];
        if let Some(val) = map
            .get(&*HDR_ATTEST_SERVER_SIGNATURES)
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(list) = Parser::new(val).parse::<List>() {
                for entry in list {
                    if let ListEntry::Item(item) = entry {
                        if let Some(bytes) = item.bare_item.as_byte_sequence() {
                            server_signatures.push(bytes.to_vec());
                        }
                    }
                }
            }
        }

        let zk_proof = decode_bytes_sfv(map, &HDR_ATTEST_ZK_PROOF).ok();

        Ok(Self {
            cipher_suite,
            random,
            key_share_json,
            base_id,
            version,
            expires_secs,
            quotes,
            secrets: vec![],
            cargo: None,
            ticket_resumption,
            server_signatures,
            zk_proof,
        })
    }
}

// ─── TrR request headers ─────────────────────────────────────────────────────

/// Attest headers present in a Trusted Request (`TrR`).
///
/// These headers are added to every HTTP request sent over an established `AtB`
/// channel (i.e. post-handshake requests).  The `base_id` binds the request
/// to its `AtB` session, and `termination` optionally signals intent to close
/// or clean up the session.
#[derive(Debug, Clone)]
pub struct TrRequestHeaders {
    /// Identifier of the `AtB` this request belongs to.
    pub base_id: AtbId,
    /// Optional trusted cargo bytes attached to the request.
    pub cargo: Option<Vec<u8>>,
    /// Optional session termination hint.
    pub termination: Option<AtbTermination>,
}

impl TrRequestHeaders {
    /// Encode these headers into an existing [`HeaderMap`].
    ///
    /// `Attest-Base-Termination` is omitted when `termination` is `None`.
    pub fn encode(&self, map: &mut HeaderMap) {
        map.insert(
            HDR_ATTEST_BASE_ID.clone(),
            HeaderValue::from_str(&self.base_id.to_string())
                .unwrap_or(HeaderValue::from_static("")),
        );
        if let Some(term) = self.termination {
            let s = match term {
                AtbTermination::Destroy => "destroy",
                AtbTermination::Keep => "keep",
                _ => "cleanup",
            };
            map.insert(HDR_ATTEST_BASE_TERMINATION.clone(), encode_token_sfv(s));
        }
    }

    /// Decode `Attest-*` headers from the map into a [`TrRequestHeaders`].
    ///
    /// # Errors
    /// Returns [`Err`] if the `Attest-Base-ID` header is missing or contains an invalid UUID.
    pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError> {
        let base_id_str = map
            .get(&*HDR_ATTEST_BASE_ID)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| HeaderError::Missing {
                name: "attest-base-id".to_owned(),
            })?;
        let base_id: AtbId =
            base_id_str
                .parse()
                .map_err(|e: uuid::Error| HeaderError::Invalid {
                    name: "attest-base-id".to_owned(),
                    reason: e.to_string(),
                })?;

        let termination = map
            .get(&*HDR_ATTEST_BASE_TERMINATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                // Accept both plain token strings and SFV-decorated tokens.
                match s.trim() {
                    "cleanup" => Some(AtbTermination::Cleanup),
                    "destroy" => Some(AtbTermination::Destroy),
                    "keep" => Some(AtbTermination::Keep),
                    _ => None,
                }
            });

        Ok(Self {
            base_id,
            cargo: None,
            termination,
        })
    }
}

// ─── Preflight response headers ──────────────────────────────────────────────

/// Headers sent by the server in response to an `OPTIONS` (preflight) request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResponseHeaders {
    /// Cipher suites supported by the server.
    pub cipher_suites: Vec<CipherSuite>,
    /// Protocol versions supported by the server.
    pub versions: Vec<ProtocolVersion>,
    /// Fresh challenge nonce for the client to bind in its handshake quote.
    pub challenge: Vec<u8>,
    /// When `true`, the server supports Oblivious `OpenHTTPA`.
    pub oblivious_supported: bool,
}

impl PreflightResponseHeaders {
    /// Encode preflight headers into a [`HeaderMap`].
    pub fn encode(&self) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            HDR_ATTEST_SUPPORTED_CIPHER_SUITES.clone(),
            encode_token_list(&self.cipher_suites),
        );
        map.insert(
            HDR_ATTEST_SUPPORTED_VERSIONS.clone(),
            encode_token_list(&self.versions),
        );
        map.insert(
            HDR_ATTEST_CHALLENGE.clone(),
            encode_bytes_sfv(&self.challenge),
        );

        if self.oblivious_supported {
            map.insert(HDR_ATTEST_TRANSPORT.clone(), encode_token_sfv("oblivious"));
        }

        map
    }

    /// Decode preflight headers from a [`HeaderMap`].
    ///
    /// # Errors
    /// Returns `HeaderError` if required headers are missing or malformed.
    pub fn decode(map: &HeaderMap) -> Result<Self, HeaderError> {
        let cipher_suites_strs =
            decode_token_list_strings(map, &HDR_ATTEST_SUPPORTED_CIPHER_SUITES)?;
        let cipher_suites = cipher_suites_strs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let versions_strs = decode_token_list_strings(map, &HDR_ATTEST_SUPPORTED_VERSIONS)?;
        let versions = versions_strs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let challenge = decode_bytes_sfv(map, &HDR_ATTEST_CHALLENGE)?;

        let oblivious_supported = map
            .get(&*HDR_ATTEST_TRANSPORT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("oblivious"));

        Ok(Self {
            cipher_suites,
            versions,
            challenge,
            oblivious_supported,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Helpers ──────────────────────────────────────────────────────────────

    fn make_aths_req() -> AtHsRequestHeaders {
        AtHsRequestHeaders {
            cipher_suites: vec![
                CipherSuite::X25519MlKem768Aes256GcmSha384,
                CipherSuite::X25519Aes256GcmSha384,
            ],
            random: vec![0xabu8; 32],
            versions: vec![ProtocolVersion::V2],
            key_shares_json: b"{\"ecdhe_public\":\"aGVsbG8=\",\"mlkem_public\":\"d29ybGQ=\"}"
                .to_vec(),
            date: "2026-04-27T00:00:00Z".to_owned(),
            base_creation: AtbCreation::New,
            direct_attestation: true,
            allow_untrusted_requests: false,
            client_quotes: vec![],
            challenge: Some(vec![0x42u8; 32]),
            signatures: vec![],
            ticket: None,
            provenance: None,
        }
    }

    // ─── AtHS request round-trip ──────────────────────────────────────────────

    #[test]
    fn aths_request_round_trip() {
        let headers = make_aths_req();
        let map = headers.encode();
        let decoded = AtHsRequestHeaders::decode(&map).unwrap();
        assert_eq!(decoded.random, headers.random);
        assert_eq!(decoded.key_shares_json, headers.key_shares_json);
        assert_eq!(decoded.date, headers.date);
        assert_eq!(decoded.cipher_suites, headers.cipher_suites);
        assert_eq!(decoded.versions, headers.versions);
        assert_eq!(decoded.base_creation, headers.base_creation);
    }

    /// Verify the binary headers are encoded as RFC 8941 Byte Sequences
    /// (`:base64url_no_pad:`) rather than plain base64.
    #[test]
    fn aths_request_binary_uses_sfv_byte_sequence_format() {
        let headers = make_aths_req();
        let map = headers.encode();
        // SFV Byte Sequence values are delimited by colons.
        let random_val = map.get(&*HDR_ATTEST_RANDOM).unwrap().to_str().unwrap();
        assert!(
            random_val.starts_with(':') && random_val.ends_with(':'),
            "expected ':...:', got {random_val:?}"
        );
        // The key-shares header should also be a Byte Sequence.
        let ks_val = map.get(&*HDR_ATTEST_KEY_SHARES).unwrap().to_str().unwrap();
        assert!(ks_val.starts_with(':') && ks_val.ends_with(':'));
    }

    /// Verify cipher suites are serialised as an RFC 8941 Token List,
    /// not a comma-separated plain string.
    #[test]
    fn aths_request_cipher_suites_are_sfv_token_list() {
        let headers = make_aths_req();
        let map = headers.encode();
        let val = map
            .get(&*HDR_ATTEST_CIPHER_SUITES)
            .unwrap()
            .to_str()
            .unwrap();
        // SFV List contains comma-separated tokens (no wrapping quotes / colons).
        // Tokens: [A-Za-z*] first char then [A-Za-z0-9:.!#$%&'*+-^_|~]
        assert!(
            val.contains("X25519_ML_KEM768_AES256GCM_SHA384"),
            "cipher suite token missing in {val:?}"
        );
        // There should be exactly one comma separating the two suites.
        assert_eq!(
            val.matches(',').count(),
            1,
            "expected one comma, got {val:?}"
        );
    }

    #[test]
    fn aths_request_decode_rejects_missing_cipher_suites() {
        let headers = make_aths_req();
        let mut map = headers.encode();
        map.remove(&*HDR_ATTEST_CIPHER_SUITES);
        let err = AtHsRequestHeaders::decode(&map).unwrap_err();
        assert!(matches!(err, HeaderError::Missing { .. }));
    }

    #[test]
    fn aths_request_decode_rejects_missing_random() {
        let headers = make_aths_req();
        let mut map = headers.encode();
        map.remove(&*HDR_ATTEST_RANDOM);
        assert!(matches!(
            AtHsRequestHeaders::decode(&map).unwrap_err(),
            HeaderError::Missing { .. }
        ));
    }

    #[test]
    fn aths_request_decode_rejects_missing_versions() {
        let headers = make_aths_req();
        let mut map = headers.encode();
        map.remove(&*HDR_ATTEST_VERSIONS);
        assert!(matches!(
            AtHsRequestHeaders::decode(&map).unwrap_err(),
            HeaderError::Missing { .. }
        ));
    }

    #[test]
    fn aths_request_decode_rejects_invalid_byte_sequence() {
        let headers = make_aths_req();
        let mut map = headers.encode();
        // Replace with a non-SFV value (plain base64 without colons).
        map.insert(
            HDR_ATTEST_RANDOM.clone(),
            HeaderValue::from_static("AAABBBCCC=="),
        );
        assert!(AtHsRequestHeaders::decode(&map).is_err());
    }

    // ─── AtHS response round-trip ─────────────────────────────────────────────

    #[test]
    fn aths_response_round_trip() {
        let atb_id = AtbId::new();
        let resp = AtHsResponseHeaders {
            cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
            random: vec![0xcdu8; 32],
            key_share_json: b"{}".to_vec(),
            base_id: atb_id.clone(),
            version: ProtocolVersion::V2,
            expires_secs: 3600,
            quotes: vec![],
            secrets: vec![],
            cargo: None,
            ticket_resumption: None,
            server_signatures: vec![],
            zk_proof: None,
        };
        let map = resp.encode();
        let decoded = AtHsResponseHeaders::decode(&map).unwrap();
        assert_eq!(decoded.base_id, atb_id);
        assert_eq!(decoded.expires_secs, 3600);
        assert_eq!(decoded.random, resp.random);
        assert_eq!(decoded.cipher_suite, resp.cipher_suite);
        assert_eq!(decoded.version, resp.version);
    }

    /// `Attest-Expires` must be serialised as an RFC 8941 Integer, not a plain
    /// decimal string.  RFC 8941 Integers have no surrounding delimiters.
    #[test]
    fn aths_response_expires_is_sfv_integer() {
        let atb_id = AtbId::new();
        let resp = AtHsResponseHeaders {
            cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
            random: vec![0u8; 32],
            key_share_json: b"{}".to_vec(),
            base_id: atb_id,
            version: ProtocolVersion::V2,
            expires_secs: 7200,
            quotes: vec![],
            secrets: vec![],
            cargo: None,
            ticket_resumption: None,
            server_signatures: vec![],
            zk_proof: None,
        };
        let map = resp.encode();
        let val = map.get(&*HDR_ATTEST_EXPIRES).unwrap().to_str().unwrap();
        // SFV Integer is just the decimal number.
        assert_eq!(val, "7200", "expected '7200', got {val:?}");
        // Ensure it round-trips.
        let decoded = AtHsResponseHeaders::decode(&map).unwrap();
        assert_eq!(decoded.expires_secs, 7200);
    }

    /// `Attest-Expires` with a legacy plain decimal value must still be decoded
    /// correctly (backwards compatibility).
    #[test]
    fn aths_response_expires_legacy_plain_decimal_accepted() {
        let atb_id = AtbId::new();
        let mut map = AtHsResponseHeaders {
            cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
            random: vec![0u8; 32],
            key_share_json: b"{}".to_vec(),
            base_id: atb_id,
            version: ProtocolVersion::V2,
            expires_secs: 3600,
            quotes: vec![],
            secrets: vec![],
            cargo: None,
            ticket_resumption: None,
            server_signatures: vec![],
            zk_proof: None,
        }
        .encode();
        // Overwrite with legacy plain decimal (no SFV markers).
        map.insert(HDR_ATTEST_EXPIRES.clone(), HeaderValue::from_static("1800"));
        let decoded = AtHsResponseHeaders::decode(&map).unwrap();
        assert_eq!(decoded.expires_secs, 1800);
    }

    #[test]
    fn aths_response_binary_uses_sfv_byte_sequence_format() {
        let atb_id = AtbId::new();
        let resp = AtHsResponseHeaders {
            cipher_suite: CipherSuite::X25519Aes256GcmSha384,
            random: vec![0xffu8; 32],
            key_share_json: b"{\"key\":\"value\"}".to_vec(),
            base_id: atb_id,
            version: ProtocolVersion::V2,
            expires_secs: 3600,
            quotes: vec![],
            secrets: vec![],
            cargo: None,
            ticket_resumption: None,
            server_signatures: vec![],
            zk_proof: None,
        };
        let map = resp.encode();
        for name in [&*HDR_ATTEST_RANDOM, &*HDR_ATTEST_KEY_SHARE] {
            let val = map.get(name).unwrap().to_str().unwrap();
            assert!(
                val.starts_with(':') && val.ends_with(':'),
                "header {name:?} should be SFV ByteSequence, got {val:?}"
            );
        }
    }

    // ─── TrR headers ─────────────────────────────────────────────────────────

    #[test]
    fn trr_headers_round_trip() {
        let atb_id = AtbId::new();
        let tr = TrRequestHeaders {
            base_id: atb_id.clone(),
            cargo: None,
            termination: Some(AtbTermination::Destroy),
        };
        let mut map = HeaderMap::new();
        tr.encode(&mut map);
        let decoded = TrRequestHeaders::decode(&map).unwrap();
        assert_eq!(decoded.base_id, atb_id);
        assert_eq!(decoded.termination, Some(AtbTermination::Destroy));
    }

    #[test]
    fn trr_headers_no_termination() {
        let atb_id = AtbId::new();
        let tr = TrRequestHeaders {
            base_id: atb_id.clone(),
            cargo: None,
            termination: None,
        };
        let mut map = HeaderMap::new();
        tr.encode(&mut map);
        let decoded = TrRequestHeaders::decode(&map).unwrap();
        assert_eq!(decoded.base_id, atb_id);
        assert_eq!(decoded.termination, None);
    }

    #[test]
    fn trr_headers_all_termination_values() {
        for term in [
            AtbTermination::Cleanup,
            AtbTermination::Destroy,
            AtbTermination::Keep,
        ] {
            let atb_id = AtbId::new();
            let tr = TrRequestHeaders {
                base_id: atb_id.clone(),
                cargo: None,
                termination: Some(term),
            };
            let mut map = HeaderMap::new();
            tr.encode(&mut map);
            let decoded = TrRequestHeaders::decode(&map).unwrap();
            assert_eq!(decoded.termination, Some(term), "failed for {term:?}");
        }
    }

    // ─── SFV helper unit tests ────────────────────────────────────────────────

    #[test]
    fn sfv_bytes_roundtrip_arbitrary() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let hv = encode_bytes_sfv(&data);
        let s = hv.to_str().unwrap();
        // Must be delimited by colons.
        assert!(s.starts_with(':') && s.ends_with(':'));
        // Decode back.
        let mut tmp = HeaderMap::new();
        tmp.insert(HDR_ATTEST_RANDOM.clone(), hv);
        let decoded = decode_bytes_sfv(&tmp, &HDR_ATTEST_RANDOM).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn sfv_token_list_roundtrip() {
        let suites = vec![
            CipherSuite::X25519MlKem768Aes256GcmSha384,
            CipherSuite::P384MlKem1024Aes256GcmSha384,
            CipherSuite::X25519Aes256GcmSha384,
        ];
        let hv = encode_token_list(&suites);
        let mut tmp = HeaderMap::new();
        tmp.insert(HDR_ATTEST_CIPHER_SUITES.clone(), hv);
        let decoded = decode_token_list_strings(&tmp, &HDR_ATTEST_CIPHER_SUITES).unwrap();
        let parsed: Vec<CipherSuite> = decoded.iter().filter_map(|s| s.parse().ok()).collect();
        assert_eq!(parsed, suites);
    }

    #[test]
    fn sfv_empty_bytes_roundtrips() {
        let hv = encode_bytes_sfv(&[]);
        let mut tmp = HeaderMap::new();
        tmp.insert(HDR_ATTEST_RANDOM.clone(), hv);
        let decoded = decode_bytes_sfv(&tmp, &HDR_ATTEST_RANDOM).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn aths_request_all_creation_modes_roundtrip() {
        for mode in [AtbCreation::New, AtbCreation::Reuse, AtbCreation::Shared] {
            let mut req = make_aths_req();
            req.base_creation = mode;
            let map = req.encode();
            let decoded = AtHsRequestHeaders::decode(&map).unwrap();
            assert_eq!(decoded.base_creation, mode, "failed for {mode:?}");
        }
    }
    #[test]
    fn sfv_malformed_token_fallback() {
        // SFV tokens cannot contain spaces or certain special chars.
        // encode_token_sfv should fall back to a quoted string or "unknown".
        let hv = encode_token_sfv("invalid token @");
        assert!(hv.to_str().unwrap().contains("\"invalid token @\""));
    }

    #[test]
    fn sfv_integer_overflow_clamping() {
        // SFV integers are limited to 15 digits.
        let large = 2_000_000_000_000_000u64;
        let hv = encode_integer_sfv(large);
        assert_eq!(hv.to_str().unwrap(), "999999999999999");
    }

    #[test]
    fn sfv_empty_bytes_colon_format() {
        let hv = encode_bytes_sfv(&[]);
        assert_eq!(hv.to_str().unwrap(), "::");
    }

    #[test]
    fn decode_token_list_with_empty_string() {
        let mut map = HeaderMap::new();
        map.insert(HDR_ATTEST_VERSIONS.clone(), HeaderValue::from_static("  "));
        let res = decode_token_list_strings(&map, &HDR_ATTEST_VERSIONS).unwrap();
        assert!(res.is_empty());
    }
}

// ─── Property-based tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod proptest_headers {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Arbitrary binary payloads (0–4096 bytes) must survive a
        /// `encode_bytes_sfv` → `decode_bytes_sfv` round-trip exactly.
        #[test]
        fn sfv_bytes_arbitrary_roundtrip(
            data in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let hv = encode_bytes_sfv(&data);
            let mut map = http::HeaderMap::new();
            map.insert(HDR_ATTEST_RANDOM.clone(), hv);
            let decoded = decode_bytes_sfv(&map, &HDR_ATTEST_RANDOM).unwrap();
            prop_assert_eq!(decoded, data);
        }

        /// A full `AtHsRequestHeaders` encode→decode round-trip must recover all
        /// fields for arbitrary random and key-share bytes.
        #[test]
        fn aths_request_full_roundtrip(
            random in proptest::collection::vec(any::<u8>(), 32..=32),
            ks_json in proptest::collection::vec(any::<u8>(), 1..=512),
        ) {
            let req = AtHsRequestHeaders {
                cipher_suites: vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
                random: random.clone(),
                versions: vec![ProtocolVersion::V2],
                key_shares_json: ks_json.clone(),
                date: "2026-01-01T00:00:00Z".to_owned(),
                base_creation: AtbCreation::New,
                direct_attestation: true,
                allow_untrusted_requests: false,
                client_quotes: vec![],
                challenge: Some(vec![0u8; 32]),
                signatures: vec![],
                ticket: None,
                provenance: None,
            };
            let map = req.encode();
            let decoded = AtHsRequestHeaders::decode(&map).unwrap();
            prop_assert_eq!(decoded.random, random);
            prop_assert_eq!(decoded.key_shares_json, ks_json);
        }

        /// A full `AtHsResponseHeaders` encode→decode round-trip must recover
        /// all fields for arbitrary random and key-share bytes.
        #[test]
        fn aths_response_full_roundtrip(
            random in proptest::collection::vec(any::<u8>(), 32..=32),
            ks_json in proptest::collection::vec(any::<u8>(), 1..=256),
            expires in 1u64..=86400u64,
        ) {
            let atb_id = AtbId::new();
            let resp = AtHsResponseHeaders {
                cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
                random: random.clone(),
                key_share_json: ks_json.clone(),
                base_id: atb_id.clone(),
                version: ProtocolVersion::V2,
                expires_secs: expires,
                quotes: vec![],
                secrets: vec![],
                cargo: None,
                ticket_resumption: None,
                server_signatures: vec![],
                zk_proof: None,
            };
            let map = resp.encode();
            let decoded = AtHsResponseHeaders::decode(&map).unwrap();
            prop_assert_eq!(decoded.random, random);
            prop_assert_eq!(decoded.key_share_json, ks_json);
            prop_assert_eq!(decoded.expires_secs, expires);
            prop_assert_eq!(decoded.base_id, atb_id);
        }

        #[test]
        fn aths_request_policy_roundtrip(
            direct in any::<bool>(),
            allow_untrusted in any::<bool>(),
        ) {
            let req = AtHsRequestHeaders {
                cipher_suites: vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
                random: vec![0u8; 32],
                versions: vec![ProtocolVersion::V2],
                key_shares_json: vec![0u8; 32],
                date: "2026-01-01T00:00:00Z".to_owned(),
                base_creation: AtbCreation::New,
                direct_attestation: direct,
                allow_untrusted_requests: allow_untrusted,
                client_quotes: vec![],
                challenge: Some(vec![0u8; 32]),
                signatures: vec![],
                ticket: None,
                provenance: None,
            };
            let map = req.encode();
            let decoded = AtHsRequestHeaders::decode(&map).unwrap();
            prop_assert_eq!(decoded.direct_attestation, direct);
            prop_assert_eq!(decoded.allow_untrusted_requests, allow_untrusted);
        }

        #[test]
        fn aths_response_large_expires_roundtrip(
            expires in any::<u64>(),
        ) {
            const MAX_SFV_INT: u64 = 999_999_999_999_999;
            let atb_id = AtbId::new();
            let resp = AtHsResponseHeaders {
                cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
                random: vec![0u8; 32],
                key_share_json: vec![0u8; 32],
                base_id: atb_id,
                version: ProtocolVersion::V2,
                expires_secs: expires,
                quotes: vec![],
                secrets: vec![],
                cargo: None,
                ticket_resumption: None,
                server_signatures: vec![],
                zk_proof: None,
            };
            let map = resp.encode();
            let decoded = AtHsResponseHeaders::decode(&map).unwrap();

            // Expected value is either original or clamped to SFV MAX
            let expected = expires.min(MAX_SFV_INT);
            prop_assert_eq!(decoded.expires_secs, expected);
        }

        #[test]
        fn ahl_canonicalize_multi_valued_headers(
            val1 in "[a-zA-Z0-9]{1,10}",
            val2 in "[a-zA-Z0-9]{1,10}"
        ) {
            let mut map = http::HeaderMap::new();
            map.append(&*HDR_ATTEST_CIPHER_SUITE, val1.parse().unwrap());
            map.append(&*HDR_ATTEST_CIPHER_SUITE, val2.parse().unwrap());

            let ahl = canonicalize_ahl("POST", "/api", None, &map).unwrap();
            let ahl_str = String::from_utf8(ahl).unwrap();

            // 1. Should contain Method and Path and empty Query (0:)
            prop_assert!(ahl_str.starts_with("4:POST4:/api0:"));

            // 2. Should contain "19:attest-cipher-suite:length:val1,val2"
            let expected_val = format!("{val1},{val2}");
            let expected = format!("19:attest-cipher-suite{}:{}", expected_val.len(), expected_val);
            prop_assert!(ahl_str.contains(&expected));
        }

        fn ahl_semantic_binding_prevents_rerouting(
            method1 in "GET|POST|PUT|DELETE",
            path1 in "/api/v1/[a-z]{5}",
            method2 in "GET|POST|PUT|DELETE",
            path2 in "/api/v1/[a-z]{5}",
        ) {
            prop_assume!(method1 != method2 || path1 != path2);
            let map = http::HeaderMap::new();

            let ahl1 = canonicalize_ahl(&method1, &path1, None, &map).unwrap();
            let ahl2 = canonicalize_ahl(&method2, &path2, None, &map).unwrap();

            // Different method/path MUST result in different AHL (H-01).
            prop_assert_ne!(ahl1, ahl2);
        }
    }

    #[test]
    fn ahl_limits_enforced() {
        let mut map = http::HeaderMap::new();

        // 1. Test too many headers
        for i in 0..65 {
            let name = format!("attest-h-{i}");
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "val".parse().unwrap(),
            );
        }
        let res = canonicalize_ahl("POST", "/api", None, &map);
        assert!(
            matches!(res, Err(HeaderError::TooManyHeaders { .. })),
            "Expected TooManyHeaders, got {res:?}"
        );

        // 2. Test name too long
        let mut map = http::HeaderMap::new();
        // Max is 256. "attest-" is 7. So 250 'a's makes it 257.
        let long_name = "attest-".to_string() + &"a".repeat(251);
        map.insert(
            http::HeaderName::from_bytes(long_name.as_bytes()).unwrap(),
            "val".parse().unwrap(),
        );
        let res = canonicalize_ahl("POST", "/api", None, &map);
        assert!(
            matches!(res, Err(HeaderError::ValueTooLong { .. })),
            "Expected ValueTooLong for name, got {res:?}"
        );

        // 3. Test value too long
        let mut map = http::HeaderMap::new();
        map.insert(
            http::HeaderName::from_static("attest-suite"),
            "a".repeat(5000).parse().unwrap(),
        );
        let res = canonicalize_ahl("POST", "/api", None, &map);
        assert!(
            matches!(res, Err(HeaderError::ValueTooLong { .. })),
            "Expected ValueTooLong for value, got {res:?}"
        );
    }
}
