// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! `OpenHTTPA` browser Wasm bindings.
//!
//! Exposes two `#[wasm_bindgen]` entry points for the demo frontend:
//!
//! 1. `openhttpa_initiate_attest()` — Generates client-side X25519 ephemeral key
//!    and ML-KEM-768 keypair using pure-Rust crypto.  Returns the public
//!    material as JSON for the browser to POST to `POST /api/attest`.
//!    Private material is held in a Wasm-side thread_local for the duration
//!    of the handshake.
//!
//! 2. `openhttpa_derive_session(server_json)` — Takes the server's
//!    `AttestResponse` JSON (from `POST /api/attest`), performs:
//!    - X25519 ECDH agreement
//!    - ML-KEM-768 decapsulation
//!    - IKM construction (exact same combiner as server)
//!    - HKDF-SHA256 to combined secret
//!    - HKDF-SHA384 to session keys
//!      Returns a `SessionProof` JSON with key sizes and the base_id.
//!
//! ## Security notes
//!
//! * `StaticSecret` is used for X25519 because it implements `Zeroize` and
//!   can be stored owned; the semantics are equivalent to an ephemeral key
//!   since the secret is consumed after one use and the thread_local is
//!   cleared immediately after `openhttpa_derive_session` is called.
//! * Only the first 16 bytes of the combined secret and first 8 bytes of the
//!   write key are returned to JavaScript for display — never the full secret.

use std::cell::{Cell, RefCell};

use aes_gcm::{
    Aes256Gcm, Nonce as GcmNonce,
    aead::{Aead, KeyInit, Payload},
};
use ml_kem::{
    Ciphertext, MlKem768,
    kem::{Kem, KeyExport},
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

mod crypto;

// ─── Thread-local client state ───────────────────────────────────────────────

/// Client-side private material held between `openhttpa_initiate_attest` and
/// `openhttpa_derive_session`.
struct ClientState {
    #[allow(dead_code)]
    client_random: [u8; 32],
    client_challenge: [u8; 48],
    ecdhe_secret: StaticSecret,
    ecdhe_public_bytes: [u8; 32],
    dk: <MlKem768 as Kem>::DecapsulationKey,
    ek_bytes: Vec<u8>,
}

/// Established session state.
struct SessionState {
    base_id: String,
    keys: crypto::SessionKeys,
    /// Monotonic counter for TLS 1.3-style nonce construction.
    /// In Wasm thread_local, Cell is safe.
    counter: Cell<u64>,
    /// Server read counter
    server_counter: Cell<u64>,
    /// WebSocket client counter
    ws_client_counter: Cell<u64>,
    /// WebSocket server counter
    ws_server_counter: Cell<u64>,
}

thread_local! {
    /// Holds the private key material between the two Wasm entry points.
    static CLIENT: RefCell<Option<ClientState>> = const { RefCell::new(None) };

    /// Holds the established session keys after a successful AtHS.
    static SESSION: RefCell<Option<SessionState>> = const { RefCell::new(None) };
}

// ─── JSON wire types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct InitiateResult {
    client_random: String,
    client_challenge: String,
    ecdhe_public: String,
    mlkem_public: String,
}

#[derive(Deserialize)]
struct AttestResponse {
    base_id: String,
    server_ecdhe_public: String,
    mlkem_ciphertext: String,
    server_random: String,
    server_mlkem_ek: String,
    transcript_hash: String,
    quotes: Vec<String>,
    expires_in: u64,
    #[allow(dead_code)]
    pub cipher_suite: String,
    #[allow(dead_code)]
    pub version: String,
}

#[derive(Serialize)]
struct SessionProof {
    base_id: String,
    combined_hex: String,
    client_write_key_hex: String,
    transcript_hash: String,
    quotes: Vec<String>,
    expires_in: u64,
}

// ─── Wasm entry points ───────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn openhttpa_unseal(base_id: &str, ciphertext_hex: &str) -> Result<String, JsValue> {
    SESSION.with(|s_ref| {
        let s_opt = s_ref.borrow();
        let s = s_opt
            .as_ref()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        // Hardened AAD: "openhttpa:" + base_id
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        // Implicit nonce from server_counter
        let count = s.server_counter.get();
        if count == u64::MAX {
            return Err(JsValue::from_str("server nonce counter overflow"));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.server_write_iv);
        let count_bytes = count.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }

        let ciphertext =
            hex::decode(ciphertext_hex).map_err(|_| JsValue::from_str("invalid ciphertext hex"))?;

        let nonce = GcmNonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&s.keys.server_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))?;

        s.server_counter.set(count + 1);

        String::from_utf8(plaintext).map_err(|e| JsValue::from_str(&format!("invalid utf8: {e}")))
    })
}

#[wasm_bindgen]
pub fn openhttpa_seal_ws(base_id: &str, plaintext: &str) -> Result<Vec<u8>, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        // Normalized AAD: "openhttpa:" + base_id_string (same as HTTP path)
        // WB2/CB2 fix: must match the server-side AAD construction.
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        // 1. Get current counter and increment.
        let count = s.ws_client_counter.get();
        if count == u64::MAX {
            return Err(JsValue::from_str("WS nonce counter overflow"));
        }
        s.ws_client_counter.set(count + 1);

        // 2. Build nonce: IV XOR counter.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.client_write_iv);
        let count_bytes = count.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        // 3. Encrypt: [MSG_TEXT (0x00)] || [plaintext]
        let mut data = Vec::with_capacity(1 + plaintext.len());
        data.push(0x00); // MSG_TEXT
        data.extend_from_slice(plaintext.as_bytes());

        let cipher = Aes256Gcm::new_from_slice(&s.keys.client_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &data,
                    aad: &aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

        // 4. Frame: [12-byte nonce] || [ciphertext]
        let mut frame = Vec::with_capacity(12 + ciphertext.len());
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    })
}
#[wasm_bindgen]
pub fn openhttpa_seal_ws_binary(base_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        // Normalized AAD: "openhttpa:" + base_id_string (same as HTTP path)
        // WB2/CB2 fix: must match the server-side AAD construction.
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        let count = s.ws_client_counter.get();
        if count == u64::MAX {
            return Err(JsValue::from_str("WS nonce counter overflow"));
        }
        s.ws_client_counter.set(count + 1);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.client_write_iv);
        let count_bytes = count.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        // 3. Encrypt: [MSG_BINARY (0x01)] || [plaintext]
        let mut data = Vec::with_capacity(1 + plaintext.len());
        data.push(0x01); // MSG_BINARY
        data.extend_from_slice(plaintext);

        let cipher = Aes256Gcm::new_from_slice(&s.keys.client_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &data,
                    aad: &aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

        let mut frame = Vec::with_capacity(12 + ciphertext.len());
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    })
}

#[wasm_bindgen]
pub fn openhttpa_unseal_ws(base_id: &str, frame: &[u8]) -> Result<String, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        if frame.len() < 12 + 16 {
            return Err(JsValue::from_str("frame too short"));
        }

        // Normalized AAD: "openhttpa:" + base_id_string (same as HTTP path)
        // WB2/CB2 fix: must match the server-side AAD construction.
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        let (nonce_bytes, ciphertext) = frame.split_at(12);

        // Anti-replay: Extract counter from nonce and verify it is > ws_server_counter
        let mut counter_bytes = [0u8; 8];
        for i in 0..8 {
            counter_bytes[i] = nonce_bytes[4 + i] ^ s.keys.server_write_iv[4 + i];
        }
        let received_counter = u64::from_be_bytes(counter_bytes);
        if received_counter <= s.ws_server_counter.get() {
            return Err(JsValue::from_str(&format!(
                "WS replay detected: counter {} <= {}",
                received_counter,
                s.ws_server_counter.get()
            )));
        }
        s.ws_server_counter.set(received_counter);

        let nonce = GcmNonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&s.keys.server_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))?;

        if plaintext.is_empty() {
            return Err(JsValue::from_str("empty plaintext"));
        }

        match plaintext[0] {
            0x00 => {
                // MSG_TEXT
                String::from_utf8(plaintext[1..].to_vec())
                    .map_err(|e| JsValue::from_str(&format!("invalid utf8: {e}")))
            }
            0x01 => {
                // MSG_BINARY
                Ok(hex::encode(&plaintext[1..]))
            }
            _ => Err(JsValue::from_str("unknown message type")),
        }
    })
}

#[wasm_bindgen]
pub fn openhttpa_ws_reset(base_id: &str) -> Result<(), JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        s.ws_client_counter.set(1);
        s.ws_server_counter.set(0);
        Ok(())
    })
}

#[wasm_bindgen]
pub fn openhttpa_initiate_attest() -> Result<String, JsValue> {
    let mut client_random = [0u8; 32];
    getrandom::fill(&mut client_random)
        .map_err(|e| JsValue::from_str(&format!("getrandom: {e}")))?;

    let mut client_challenge = [0u8; 48];
    getrandom::fill(&mut client_challenge)
        .map_err(|e| JsValue::from_str(&format!("getrandom: {e}")))?;

    let mut ecdhe_bytes = [0u8; 32];
    getrandom::fill(&mut ecdhe_bytes).map_err(|e| JsValue::from_str(&format!("getrandom: {e}")))?;
    let ecdhe_secret = StaticSecret::from(ecdhe_bytes);
    let ecdhe_public = PublicKey::from(&ecdhe_secret);
    let ecdhe_public_bytes = ecdhe_public.to_bytes();

    let mut seed = [0u8; 64];
    getrandom::fill(&mut seed).map_err(|e| JsValue::from_str(&format!("getrandom: {e}")))?;
    let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed.into());
    let ek = dk.encapsulation_key().clone();
    let ek_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ek.to_bytes()).to_vec();

    CLIENT.with(|c| {
        *c.borrow_mut() = Some(ClientState {
            client_random,
            client_challenge,
            ecdhe_secret,
            ecdhe_public_bytes,
            dk,
            ek_bytes: ek_bytes.clone(),
        });
    });

    let result = InitiateResult {
        client_random: hex::encode(client_random),
        client_challenge: hex::encode(client_challenge),
        ecdhe_public: hex::encode(ecdhe_public_bytes),
        mlkem_public: hex::encode(&ek_bytes),
    };

    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&format!("serialise: {e}")))
}

#[wasm_bindgen]
pub fn openhttpa_derive_session(server_json: &str) -> Result<String, JsValue> {
    let resp: AttestResponse = serde_json::from_str(server_json)
        .map_err(|e| JsValue::from_str(&format!("parse error: {e}")))?;

    let state = CLIENT.with(|c| c.borrow_mut().take()).ok_or_else(|| {
        JsValue::from_str("no pending attest — call openhttpa_initiate_attest first")
    })?;

    let server_ecdhe_pub_bytes: [u8; 32] = hex::decode(&resp.server_ecdhe_public)
        .map_err(|_| JsValue::from_str("invalid server_ecdhe_public hex"))?
        .try_into()
        .map_err(|_: Vec<u8>| JsValue::from_str("server_ecdhe_public must be 32 bytes"))?;

    let ct_bytes = hex::decode(&resp.mlkem_ciphertext)
        .map_err(|_| JsValue::from_str("invalid mlkem_ciphertext hex"))?;

    let transcript_bytes = hex::decode(&resp.transcript_hash)
        .map_err(|_| JsValue::from_str("invalid transcript_hash hex"))?;

    let server_ecdhe_pub = PublicKey::from(server_ecdhe_pub_bytes);
    let ecdhe_ss = state.ecdhe_secret.diffie_hellman(&server_ecdhe_pub);

    use ml_kem::kem::Decapsulate;
    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice()).map_err(|_| {
        JsValue::from_str("mlkem_ciphertext has wrong length (expected 1088 bytes)")
    })?;
    let mlkem_ss = state.dk.decapsulate(&ct);

    let combined = crypto::combine(
        ecdhe_ss.as_bytes(),
        mlkem_ss.as_ref(),
        &state.ecdhe_public_bytes,
        &server_ecdhe_pub_bytes,
        &state.ek_bytes,
        &ct_bytes,
    );

    let server_random_bytes: [u8; 32] = hex::decode(&resp.server_random)
        .map_err(|_| JsValue::from_str("invalid server_random hex"))?
        .try_into()
        .map_err(|_: Vec<u8>| JsValue::from_str("server_random must be 32 bytes"))?;

    let server_mlkem_ek_bytes = hex::decode(&resp.server_mlkem_ek)
        .map_err(|_| JsValue::from_str("invalid server_mlkem_ek hex"))?;

    // Hardened Transcript Verification (M-01)
    // The client MUST recompute the transcript hash from its own view of parameters
    // and compare it with the server's provided hash before deriving keys.
    let mut hasher = sha2::Sha384::new();

    // 1. Client Random
    hasher.update((state.client_random.len() as u64).to_be_bytes());
    hasher.update(state.client_random);

    // 2. Client Challenge (Hardened: 48 bytes)
    // Use the random challenge generated during initiation.
    hasher.update((state.client_challenge.len() as u64).to_be_bytes());
    hasher.update(state.client_challenge);

    // 3. Client Key Share (ECDHE)
    hasher.update((state.ecdhe_public_bytes.len() as u64).to_be_bytes());
    hasher.update(state.ecdhe_public_bytes);

    // 4. Client Key Share (ML-KEM EK)
    hasher.update((state.ek_bytes.len() as u64).to_be_bytes());
    hasher.update(&state.ek_bytes);

    // 5. Server Random
    hasher.update((server_random_bytes.len() as u64).to_be_bytes());
    hasher.update(server_random_bytes);

    // 6. Server Key Share (ECDHE)
    hasher.update((server_ecdhe_pub_bytes.len() as u64).to_be_bytes());
    hasher.update(server_ecdhe_pub_bytes);

    // 7. Server Key Share (ML-KEM CT)
    hasher.update((ct_bytes.len() as u64).to_be_bytes());
    hasher.update(&ct_bytes);

    // 8. Server Key Share (ML-KEM Public)
    hasher.update((server_mlkem_ek_bytes.len() as u64).to_be_bytes());
    hasher.update(&server_mlkem_ek_bytes);

    // 9. Negotiated Cipher Suite (2 bytes: X25519_MLKEM768_AES256GCM_SHA384 = 0x0001)
    hasher.update(1u16.to_be_bytes());

    // 10. Negotiated Protocol Version (1 byte: V2 = 0x02)
    hasher.update([0x02]);

    let calculated_transcript = hasher.finalize();
    if calculated_transcript.as_slice() != transcript_bytes.as_slice() {
        return Err(JsValue::from_str(&format!(
            "handshake transcript mismatch! potential MITM or server error.\nExpected: {}\nReceived: {}",
            hex::encode(calculated_transcript),
            resp.transcript_hash
        )));
    }

    let session_keys = crypto::derive_session_keys(&combined, &transcript_bytes);

    let proof = SessionProof {
        base_id: resp.base_id.clone(),
        combined_hex: hex::encode(&combined[..16]),
        client_write_key_hex: hex::encode(&session_keys.client_write_key[..8]),
        transcript_hash: resp.transcript_hash,
        quotes: resp.quotes,
        expires_in: resp.expires_in,
    };

    // Persist the session for encryption.
    SESSION.with(|s| {
        *s.borrow_mut() = Some(SessionState {
            base_id: resp.base_id,
            keys: session_keys,
            counter: Cell::new(1),
            server_counter: Cell::new(1),
            ws_client_counter: Cell::new(1),
            ws_server_counter: Cell::new(0), // Server starts at 1, so last_received=0
        });
    });

    serde_json::to_string(&proof).map_err(|e| JsValue::from_str(&format!("serialise: {e}")))
}

#[wasm_bindgen]
pub fn openhttpa_compute_ticket(
    base_id: &str,
    nonce: u64,
    method: &str,
    path: &str,
    query: Option<String>,
    headers_json: &str,
) -> Result<String, JsValue> {
    SESSION.with(|s_ref| {
        let s_opt = s_ref.borrow();
        let s = s_opt
            .as_ref()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        let headers: std::collections::HashMap<String, String> = serde_json::from_str(headers_json)
            .map_err(|e| JsValue::from_str(&format!("invalid headers JSON: {e}")))?;

        // Build a HeaderMap for canonicalization.
        let mut map = http::HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::try_from(k),
                http::HeaderValue::try_from(v),
            ) {
                map.insert(name, val);
            }
        }

        // RFC 7230 §5.4: use the Host header as the authority so the MAC
        // matches what the server extracts from the mandatory Host header
        // for HTTP/1.1 origin-form requests.
        let authority = map
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // SEC-04: An empty authority means zero binding against re-routing;
        // reject the request so callers get an explicit error rather than a
        // silently weak MAC.
        if authority.is_empty() {
            return Err(JsValue::from_str(
                "AHL error: missing Host header — required for authority binding",
            ));
        }
        // SEC-01: bind query so parameter manipulation is detected by the MAC.
        let ahl =
            openhttpa_headers::canonicalize_ahl(method, path, query.as_deref(), authority, &map)
                .map_err(|e| JsValue::from_str(&format!("AHL error: {e}")))?;

        // Compute HMAC-SHA-384.
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        type HmacSha384 = Hmac<Sha384>;

        let mut mac = <HmacSha384 as hmac::digest::KeyInit>::new_from_slice(&s.keys.client_mac_key)
            .map_err(|_| JsValue::from_str("HMAC init failed"))?;
        // Bind nonce and AHL to prevent replay and semantic re-routing (H-01/M-01).
        mac.update(&nonce.to_be_bytes());
        mac.update(&ahl);
        let result = mac.finalize().into_bytes();

        // Encode as standard binary trailer (M-02).
        let mut payload = nonce.to_be_bytes().to_vec();
        payload.push(0u8); // 1-RTT mode (SA-05 parity)
        payload.extend_from_slice(&result);
        use base64ct::{Base64, Encoding};
        Ok(Base64::encode_string(&payload))
    })
}

/// Encrypt a JSON payload using `OpenHTTPA` session keys.
///
/// Implements TLS 1.3 §5.3 nonce construction:
/// `nonce = write_iv ^ (counter as 96-bit BE, right-aligned)`
///
/// The returned JSON contains:
/// - `nonce`: hex-encoded 12-byte IV
/// - `counter`: monotonic counter value used to construct the nonce
/// - `ciphertext`: hex-encoded AEAD ciphertext (includes GCM authentication tag)
/// - `binder`: empty string — the `Attest-Ticket` MAC must be computed separately
///   via [`openhttpa_compute_ticket`], which binds the method, path, query, and
///   authority so the MAC covers the full request target.
///
/// # Design note
///
/// `openhttpa_seal` and `openhttpa_compute_ticket` are intentionally separate:
/// sealing (AEAD encryption) does not require knowledge of the HTTP routing
/// context, while ticket computation (HMAC over the AHL) does.  Callers MUST
/// invoke `openhttpa_compute_ticket` with the real `Host`, method, and path and
/// place the result in the `Attest-Ticket` header/trailer.
#[wasm_bindgen]
pub fn openhttpa_seal(base_id: &str, plaintext: &str) -> Result<String, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        // Hardened AAD: "openhttpa:" + base_id
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        // Get current counter and increment atomically.
        let count = s.counter.get();
        if count == u64::MAX {
            return Err(JsValue::from_str("nonce counter overflow"));
        }
        s.counter.set(count + 1);

        // Build nonce: IV XOR counter (TLS 1.3 §5.3).
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.client_write_iv);
        let count_bytes = count.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        // Encrypt payload.
        let cipher = Aes256Gcm::new_from_slice(&s.keys.client_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

        // Return ciphertext + counter.  The AHL ticket is computed separately by
        // openhttpa_compute_ticket so that the caller can supply the real Host,
        // method, path, and query string.  `binder` is kept as an empty string for
        // backward-compatibility with callers that destructure it.
        let res = serde_json::json!({
            "nonce":      hex::encode(nonce_bytes),
            "counter":    count,
            "ciphertext": hex::encode(ciphertext),
            "binder":     "",
        });
        serde_json::to_string(&res).map_err(|e| JsValue::from_str(&format!("serialise: {e}")))
    })
}

/// Encrypt a JSON payload and compute a real `Attest-Ticket` binder over the AHL.
///
/// This is the full form of `openhttpa_seal`; the short form calls this with
/// default method/path values for backward-compatibility.
#[wasm_bindgen]
pub fn openhttpa_seal_with_ahl(
    base_id: &str,
    plaintext: &str,
    method: &str,
    path: &str,
    query: Option<String>,
    headers_json: &str,
) -> Result<String, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        // Hardened AAD: "openhttpa:" + base_id
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        // 1. Get current counter and increment.
        let count = s.counter.get();
        if count == u64::MAX {
            return Err(JsValue::from_str("nonce counter overflow"));
        }
        s.counter.set(count + 1);

        // 2. Build nonce: IV XOR counter.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.client_write_iv);
        let count_bytes = count.to_be_bytes();
        // XOR the last 8 bytes of the 12-byte IV with the counter.
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        // 3. Encrypt.
        let cipher = Aes256Gcm::new_from_slice(&s.keys.client_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

        // 4. Compute a real Attest-Ticket binder (WB1 fix).
        // Parse headers for AHL canonicalization.
        let headers: std::collections::HashMap<String, String> = serde_json::from_str(headers_json)
            .map_err(|e| JsValue::from_str(&format!("invalid headers JSON: {e}")))?;
        let mut map = http::HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(name), Ok(val)) = (
                http::HeaderName::try_from(k),
                http::HeaderValue::try_from(v),
            ) {
                map.insert(name, val);
            }
        }
        // RFC 7230 §5.4: use the Host header as the authority.
        let authority = map
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // SEC-04: reject empty authority.
        if authority.is_empty() {
            return Err(JsValue::from_str(
                "AHL error: missing Host header — required for authority binding",
            ));
        }
        // SEC-01: bind query so parameter manipulation is detected.
        let ahl =
            openhttpa_headers::canonicalize_ahl(method, path, query.as_deref(), authority, &map)
                .map_err(|e| JsValue::from_str(&format!("AHL error: {e}")))?;

        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        type HmacSha384 = Hmac<Sha384>;

        let mut mac = <HmacSha384 as hmac::digest::KeyInit>::new_from_slice(&s.keys.client_mac_key)
            .map_err(|_| JsValue::from_str("HMAC init failed"))?;
        mac.update(&count.to_be_bytes());
        mac.update(&ahl);
        let hmac_result = mac.finalize().into_bytes();

        // Attest-Ticket binary trailer: BE_u64(counter) || 0x00 (1-RTT) || HMAC-SHA384
        let mut ticket_payload = count.to_be_bytes().to_vec();
        ticket_payload.push(0u8); // 1-RTT mode
        ticket_payload.extend_from_slice(&hmac_result);
        use base64ct::{Base64, Encoding};
        let ticket_b64 = Base64::encode_string(&ticket_payload);

        let res = serde_json::json!({
            "nonce": hex::encode(nonce_bytes),
            "counter": count,
            "ciphertext": hex::encode(ciphertext),
            "ticket": ticket_b64,
        });

        serde_json::to_string(&res).map_err(|e| JsValue::from_str(&format!("serialise: {e}")))
    })
}

#[wasm_bindgen]
pub fn openhttpa_seal_chunk(
    base_id: &str,
    plaintext: &str,
    prev_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        let prev_hash =
            hex::decode(prev_hash_hex).map_err(|_| JsValue::from_str("invalid hash hex"))?;
        let mut chunk_aad = aad.clone();
        chunk_aad.extend_from_slice(&prev_hash);

        let count = s.counter.get();
        s.counter.set(count + 1);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.client_write_iv);
        let count_bytes = count.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&s.keys.client_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &chunk_aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

        let mut hasher = sha2::Sha384::new();
        hasher.update(&prev_hash);
        hasher.update(&ciphertext);
        let next_hash = hasher.finalize();

        let res = serde_json::json!({
            "counter": count,
            "ciphertext": hex::encode(&ciphertext),
            "next_hash": hex::encode(next_hash),
        });

        serde_wasm_bindgen::to_value(&res)
            .map_err(|e| JsValue::from_str(&format!("json error: {e}")))
    })
}

#[wasm_bindgen]
pub fn openhttpa_unseal_chunk(
    base_id: &str,
    frame_bytes: &[u8],
    prev_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    SESSION.with(|s_ref| {
        let mut s_opt = s_ref.borrow_mut();
        let s = s_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active `OpenHTTPA` session"))?;

        if s.base_id != base_id {
            return Err(JsValue::from_str("base_id mismatch"));
        }

        if frame_bytes.len() < 8 {
            return Err(JsValue::from_str("frame too short"));
        }

        let counter = u64::from_be_bytes(frame_bytes[..8].try_into().unwrap());
        let ciphertext = &frame_bytes[8..];

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());

        let prev_hash =
            hex::decode(prev_hash_hex).map_err(|_| JsValue::from_str("invalid hash hex"))?;
        let mut chunk_aad = aad.clone();
        chunk_aad.extend_from_slice(&prev_hash);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&s.keys.server_write_iv);
        let count_bytes = counter.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&s.keys.server_write_key)
            .map_err(|e| JsValue::from_str(&format!("cipher init: {e}")))?;

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &chunk_aad,
                },
            )
            .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))?;

        // Update the server counter to prevent desync for subsequent non-streaming responses
        if counter >= s.server_counter.get() {
            s.server_counter.set(counter + 1);
        }

        let mut hasher = sha2::Sha384::new();
        hasher.update(&prev_hash);
        hasher.update(ciphertext);
        let next_hash = hasher.finalize();

        let res = serde_json::json!({
            "plaintext": String::from_utf8_lossy(&plaintext).into_owned(),
            "next_hash": hex::encode(next_hash),
        });

        serde_wasm_bindgen::to_value(&res)
            .map_err(|e| JsValue::from_str(&format!("json error: {e}")))
    })
}
