// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! C FFI bindings for `OpenHTTPA`.
//!
//! All exported functions are `extern "C"` and use primitive / pointer types
//! only.  Caller is responsible for freeing returned buffers with
//! [`openhttpa_free_string`].

#![allow(unsafe_code)] // intentional: C FFI
#![deny(warnings)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use tokio::runtime::Runtime;

use openhttpa_client::OpenHttpaClient;
use openhttpa_core::handshake::{AtHsExecutor, AtHsRequest, ClientKeyShare};
use openhttpa_core::session::{AttestSession, ReplayStrategy};
use openhttpa_crypto::aead::{AeadAlgorithm, AeadKey, AeadNonce};
use openhttpa_llm::{ChatMessage, Role};
use openhttpa_proto::{AtbId, CipherSuite, ProtocolVersion};
use openhttpa_server::AtbRegistry;

pub struct OpenHttpaCtx {
    pub rt: Runtime,
    pub registry: AtbRegistry,
    pub executor: AtHsExecutor,
    pub tee: std::sync::Arc<dyn openhttpa_tee::TeeProvider>,
}

#[unsafe(no_mangle)]
pub extern "C" fn openhttpa_ctx_new() -> *mut OpenHttpaCtx {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let registry = AtbRegistry::new();
    let executor = AtHsExecutor::with_config(vec![], vec![], true, false);
    let tee = openhttpa_tee::detect_best_provider(&openhttpa_tee::provider::TeeConfig::default())
        .unwrap();
    let ctx = Box::new(OpenHttpaCtx {
        rt,
        registry,
        executor,
        tee,
    });
    Box::into_raw(ctx)
}

/// Free an `OpenHttpaCtx`.
///
/// # Safety
///
/// The `ctx` must have been returned by `openhttpa_ctx_new` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_ctx_free(ctx: *mut OpenHttpaCtx) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn openhttpa_version() -> *mut c_char {
    let ver = env!("CARGO_PKG_VERSION");
    CString::new(ver)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Parse a string into a canonical ATB-ID.
///
/// # Safety
///
/// The `atb_id` pointer must be a valid, null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_parse_atb_id(atb_id: *const c_char) -> *mut c_char {
    if atb_id.is_null() {
        return std::ptr::null_mut();
    }
    let s = unsafe { CStr::from_ptr(atb_id) }.to_str().unwrap_or("");
    match s.parse::<uuid::Uuid>() {
        Ok(u) => CString::new(u.as_hyphenated().to_string())
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

// ─── Protocol ─────────────────────────────────────────────────────────────────

/// Perform a full `OpenHTTPA` attestation handshake.
///
/// # Safety
///
/// The `server_uri` pointer must be a valid, null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_attest_handshake(
    ctx: *mut OpenHttpaCtx,
    server_uri: *const c_char,
) -> *mut c_char {
    if server_uri.is_null() {
        return std::ptr::null_mut();
    }
    let uri_str = unsafe { CStr::from_ptr(server_uri) }.to_str().unwrap_or("");
    let uri: http::Uri = match uri_str.parse() {
        Ok(u) => u,
        Err(_) => return std::ptr::null_mut(),
    };
    let client = OpenHttpaClient::builder()
        .server_uri(uri)
        .require_preflight(true)
        .build();
    let ctx_ref = unsafe { &*ctx };
    match ctx_ref.rt.block_on(client.attest_handshake()) {
        Ok(session) => {
            let id = session.state().id.to_string();
            CString::new(id)
                .map(CString::into_raw)
                .unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Send a confidential chat message to an LLM via `OpenHTTPA`.
///
/// # Safety
///
/// All input pointers must be valid, null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_confidential_chat(
    ctx: *mut OpenHttpaCtx,
    server_uri: *const c_char,
    model: *const c_char,
    messages_json: *const c_char,
) -> *mut c_char {
    if server_uri.is_null() || model.is_null() || messages_json.is_null() {
        return std::ptr::null_mut();
    }
    let uri_str = unsafe { CStr::from_ptr(server_uri) }.to_str().unwrap_or("");
    let model_str = unsafe { CStr::from_ptr(model) }
        .to_str()
        .unwrap_or("llama3");
    let msgs_str = unsafe { CStr::from_ptr(messages_json) }
        .to_str()
        .unwrap_or("[]");

    let uri: http::Uri = match uri_str.parse() {
        Ok(u) => u,
        Err(_) => return std::ptr::null_mut(),
    };

    let raw_msgs: Vec<(String, String)> = match serde_json::from_str(msgs_str) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let msgs: Vec<ChatMessage> = raw_msgs
        .into_iter()
        .map(|(role, content)| ChatMessage {
            role: match role.as_str() {
                "system" => Role::System,
                "assistant" => Role::Assistant,
                _ => Role::User,
            },
            content,
        })
        .collect();

    let ctx_ref = unsafe { &*ctx };
    let result = ctx_ref.rt.block_on(async {
        openhttpa_llm::client::ConfidentialLlmClientBuilder::default()
            .server_uri(uri)
            .model(model_str)
            .build()
            .await?
            .chat(&msgs)
            .await
    });

    match result {
        Ok(reply) => CString::new(reply)
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

// ─── Server ───────────────────────────────────────────────────────────────────

/// Handle a server-side `OpenHTTPA` handshake request.
///
/// # Safety
///
/// The `request_json` pointer must be a valid, null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_server_handshake(
    ctx: *mut OpenHttpaCtx,
    request_json: *const c_char,
) -> *mut c_char {
    if request_json.is_null() {
        return std::ptr::null_mut();
    }
    let req_str = unsafe { CStr::from_ptr(request_json) }
        .to_str()
        .unwrap_or("");

    #[derive(serde::Deserialize)]
    struct HandshakeBody {
        client_random: String,
        client_challenge: String,
        ecdhe_public: String,
        mlkem_public: String,
    }

    let body: HandshakeBody = match serde_json::from_str(req_str) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let client_random = hex::decode(&body.client_random).unwrap_or_default();
    let client_challenge = hex::decode(&body.client_challenge).unwrap_or_default();
    if client_random.len() != 32 || client_challenge.len() != 48 {
        return std::ptr::null_mut();
    }

    let share = ClientKeyShare {
        ecdhe_public: hex::decode(&body.ecdhe_public).unwrap_or_default(),
        mlkem_public: hex::decode(&body.mlkem_public).unwrap_or_default(),
        signature_alg: Some(openhttpa_core::handshake::SIG_ALG_ML_DSA_65),
    };

    let mut cr = std::array::from_fn::<u8, 32, _>(|i| (i % 255) as u8);
    cr.copy_from_slice(&client_random);
    let mut cc = std::array::from_fn::<u8, 48, _>(|i| (i % 255) as u8);
    cc.copy_from_slice(&client_challenge);

    let hs_req = AtHsRequest {
        client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
        client_versions: &[ProtocolVersion::V2],
        client_random: &cr,
        client_challenge: &cc,
        client_share: &share,
        client_quotes: &[],
        atb_ttl_secs: 3600,
        provenance: None,
    };

    let ctx_ref = unsafe { &*ctx };
    let result = ctx_ref.rt.block_on(async {
        ctx_ref
            .executor
            .execute_server(&hs_req, Some(&*ctx_ref.tee), None, None)
            .await
    });

    match result {
        Ok((suite, version, server_share, hs_res)) => {
            let session = AttestSession::new(
                hs_res.atb_id.clone(),
                suite,
                version,
                hs_res.session_keys.clone(),
                hs_res.expires_at,
                ReplayStrategy::default(),
                hs_res.client_attestation_result.clone(),
            );
            let ctx_ref = unsafe { &*ctx };
            if ctx_ref.registry.insert(session).is_err() {
                return std::ptr::null_mut();
            }

            let resp = serde_json::json!({
                "base_id": hs_res.atb_id.to_string(),
                "server_ecdhe_public": hex::encode(server_share.ecdhe_public),
                "mlkem_ciphertext": hex::encode(server_share.mlkem_ciphertext),
                "transcript_hash": hex::encode(hs_res.transcript_hash),
            });

            CString::new(resp.to_string())
                .map(CString::into_raw)
                .unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypt a server-side `OpenHTTPA` request payload.
///
/// # Safety
///
/// Both `atb_id_str` and `ciphertext_hex` must be valid, null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_server_decrypt(
    ctx: *mut OpenHttpaCtx,
    atb_id_str: *const c_char,
    nonce_val: u64,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    let id_str = unsafe { CStr::from_ptr(atb_id_str) }.to_str().unwrap_or("");
    let id: AtbId = match id_str.parse() {
        Ok(i) => i,
        Err(_) => return std::ptr::null_mut(),
    };

    let ciphertext = match hex::decode(
        unsafe { CStr::from_ptr(ciphertext_hex) }
            .to_str()
            .unwrap_or(""),
    ) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let ctx_ref = unsafe { &*ctx };
    let session = match ctx_ref.registry.get(&id) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let result = session.with_keys_for_trr(nonce_val, |keys, _| {
        let mut nonce_bytes = std::array::from_fn::<u8, 12, _>(|i| (i % 255) as u8);
        nonce_bytes.copy_from_slice(&keys.client_write_iv);
        let count_bytes = nonce_val.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }

        let aead_nonce = AeadNonce(nonce_bytes);
        let aead_key =
            AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.client_write_key).map_err(|_| ())?;

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(id_str.as_bytes());

        let mut data = ciphertext.clone();
        let pt_slice = aead_key
            .open_in_place(&aead_nonce, &aad, &mut data)
            .map_err(|_| ())?;
        Ok::<Vec<u8>, ()>(pt_slice.to_vec())
    });

    match result {
        Ok(Ok(plaintext)) => CString::new(hex::encode(plaintext))
            .map(CString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

/// Encrypt a server-side `OpenHTTPA` response payload.
///
/// # Safety
///
/// Both `atb_id_str` and `plaintext_hex` must be valid, null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_server_encrypt(
    ctx: *mut OpenHttpaCtx,
    atb_id_str: *const c_char,
    plaintext_hex: *const c_char,
) -> *mut c_char {
    let id_str = unsafe { CStr::from_ptr(atb_id_str) }.to_str().unwrap_or("");
    let id: AtbId = match id_str.parse() {
        Ok(i) => i,
        Err(_) => return std::ptr::null_mut(),
    };

    let plaintext = match hex::decode(
        unsafe { CStr::from_ptr(plaintext_hex) }
            .to_str()
            .unwrap_or(""),
    ) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let ctx_ref = unsafe { &*ctx };
    let session = match ctx_ref.registry.get(&id) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let result = session.with_keys_for_trs(|keys, counter| {
        let mut nonce_bytes = std::array::from_fn::<u8, 12, _>(|i| (i % 255) as u8);
        nonce_bytes.copy_from_slice(&keys.server_write_iv);
        let count_bytes = counter.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }

        let aead_nonce = AeadNonce(nonce_bytes);
        let aead_key =
            AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.server_write_key).map_err(|_| ())?;

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(id_str.as_bytes());

        let mut data = plaintext.clone();
        aead_key
            .seal_in_place(&aead_nonce, &aad, &mut data)
            .map_err(|_| ())?;
        Ok::<(Vec<u8>, u64), ()>((data, counter))
    });

    match result {
        Ok(Ok((ciphertext, counter))) => {
            let resp = serde_json::json!({
                "ciphertext": hex::encode(ciphertext),
                "nonce": counter,
            });
            CString::new(resp.to_string())
                .map(CString::into_raw)
                .unwrap_or(std::ptr::null_mut())
        }
        _ => std::ptr::null_mut(),
    }
}

/// Free a string returned by any of the `openhttpa_*` functions.
///
/// # Safety
///
/// The `ptr` must have been returned by an `openhttpa_*` function and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn openhttpa_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn version_is_non_empty() {
        let ptr = openhttpa_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        assert!(!s.is_empty());
        unsafe { openhttpa_free_string(ptr) };
    }

    #[test]
    fn server_handshake_roundtrip() {
        let ctx = openhttpa_ctx_new();
        let client_random = std::array::from_fn::<u8, 32, _>(|i| (i % 255) as u8);
        let client_challenge = std::array::from_fn::<u8, 48, _>(|i| (i % 255) as u8);
        let client_pair = openhttpa_crypto::key_exchange::HybridKemPair::generate().unwrap();
        let client_pub = client_pair.public_key_share();

        let client_req = serde_json::json!({
            "client_random": hex::encode(client_random),
            "client_challenge": hex::encode(client_challenge),
            "ecdhe_public": hex::encode(client_pub.ecdhe_public),
            "mlkem_public": hex::encode(client_pub.mlkem_public),
        });

        let c_client_json = CString::new(client_req.to_string()).unwrap();
        let server_json_ptr = unsafe { openhttpa_server_handshake(ctx, c_client_json.as_ptr()) };
        assert!(!server_json_ptr.is_null());

        let server_json = unsafe { CStr::from_ptr(server_json_ptr).to_str().unwrap().to_owned() };
        unsafe { openhttpa_free_string(server_json_ptr) };

        let server_resp: serde_json::Value = serde_json::from_str(&server_json).unwrap();
        assert!(server_resp.get("base_id").is_some());
        unsafe { openhttpa_ctx_free(ctx) };
    }

    #[test]
    fn server_decrypt_encrypt_roundtrip() {
        let ctx = openhttpa_ctx_new(); // 1. Handshake
        let client_random = std::array::from_fn::<u8, 32, _>(|i| (i % 255) as u8);
        let client_challenge = std::array::from_fn::<u8, 48, _>(|i| (i % 255) as u8);
        let client_pair = openhttpa_crypto::key_exchange::HybridKemPair::generate().unwrap();
        let client_pub = client_pair.public_key_share();

        let client_req = serde_json::json!({
            "client_random": hex::encode(client_random),
            "client_challenge": hex::encode(client_challenge),
            "ecdhe_public": hex::encode(client_pub.ecdhe_public.clone()),
            "mlkem_public": hex::encode(client_pub.mlkem_public.clone()),
        });

        let server_json_ptr = unsafe {
            openhttpa_server_handshake(ctx, CString::new(client_req.to_string()).unwrap().as_ptr())
        };
        let server_json_str = unsafe { CStr::from_ptr(server_json_ptr).to_str().unwrap() };
        let server_resp: serde_json::Value = serde_json::from_str(server_json_str).unwrap();
        let base_id = server_resp["base_id"].as_str().unwrap().to_owned();
        let server_ecdhe =
            hex::decode(server_resp["server_ecdhe_public"].as_str().unwrap()).unwrap();
        let server_ct = hex::decode(server_resp["mlkem_ciphertext"].as_str().unwrap()).unwrap();
        let transcript_hash =
            hex::decode(server_resp["transcript_hash"].as_str().unwrap()).unwrap();
        unsafe { openhttpa_free_string(server_json_ptr) };

        // 2. Client-side key derivation (simulated)
        let server_ks = openhttpa_crypto::key_exchange::KeyShare {
            ecdhe_public: server_ecdhe,
            mlkem_public: vec![],
        };
        let ss = client_pair.client_combine(&server_ks, &server_ct).unwrap();
        let keys =
            openhttpa_crypto::hkdf::SessionKeys::derive(ss.as_bytes(), &transcript_hash).unwrap();

        // 3. Client Seal (TrR)
        let plaintext = b"Hello Server";
        let nonce_val = 1u64;
        let mut nonce_bytes = std::array::from_fn::<u8, 12, _>(|i| (i % 255) as u8);
        nonce_bytes.copy_from_slice(&keys.client_write_iv);
        let count_bytes = nonce_val.to_be_bytes();
        for (i, b) in count_bytes.iter().enumerate() {
            nonce_bytes[4 + i] ^= b;
        }
        let aead_nonce = AeadNonce(nonce_bytes);
        let aead_key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.client_write_key).unwrap();
        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id.as_bytes());
        let mut data = plaintext.to_vec();
        aead_key
            .seal_in_place(&aead_nonce, &aad, &mut data)
            .unwrap();

        // 4. Server Decrypt
        let c_id = CString::new(base_id.clone()).unwrap();
        let c_cipher = CString::new(hex::encode(data)).unwrap();
        let plain_hex_ptr =
            unsafe { openhttpa_server_decrypt(ctx, c_id.as_ptr(), nonce_val, c_cipher.as_ptr()) };
        assert!(!plain_hex_ptr.is_null());
        let plain_hex = unsafe { CStr::from_ptr(plain_hex_ptr).to_str().unwrap() };
        let decrypted = hex::decode(plain_hex).unwrap();
        assert_eq!(decrypted, plaintext);
        unsafe { openhttpa_free_string(plain_hex_ptr) };

        // 5. Server Encrypt (TrS)
        let c_reply = CString::new(hex::encode(b"Hello Client")).unwrap();
        let enc_json_ptr =
            unsafe { openhttpa_server_encrypt(ctx, c_id.as_ptr(), c_reply.as_ptr()) };
        let enc_json = unsafe { CStr::from_ptr(enc_json_ptr).to_str().unwrap() };
        let enc_val: serde_json::Value = serde_json::from_str(enc_json).unwrap();
        let s_ciphertext = hex::decode(enc_val["ciphertext"].as_str().unwrap()).unwrap();
        let s_nonce_val = enc_val["nonce"].as_u64().unwrap();
        unsafe { openhttpa_free_string(enc_json_ptr) };

        // 6. Client Unseal
        let mut s_nonce_bytes = std::array::from_fn::<u8, 12, _>(|i| (i % 255) as u8);
        s_nonce_bytes.copy_from_slice(&keys.server_write_iv);
        let s_count_bytes = s_nonce_val.to_be_bytes();
        for (i, b) in s_count_bytes.iter().enumerate() {
            s_nonce_bytes[4 + i] ^= b;
        }
        let s_aead_nonce = AeadNonce(s_nonce_bytes);
        let s_aead_key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.server_write_key).unwrap();
        let mut s_data = s_ciphertext;
        let s_decrypted = s_aead_key
            .open_in_place(&s_aead_nonce, &aad, &mut s_data)
            .unwrap();
        assert_eq!(s_decrypted, b"Hello Client");
        unsafe { openhttpa_ctx_free(ctx) };
    }
}
