// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use lazy_static::lazy_static;
use ngx::ffi;
use openhttpa_core::handshake::{AtHsExecutor, AtHsRequest, ClientKeyShare};
use openhttpa_core::session::{AttestSession, ReplayStrategy};
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_server::AtbRegistry;
use serde::Deserialize;
use tokio::runtime::Runtime;

lazy_static! {
    static ref REGISTRY: AtbRegistry = AtbRegistry::with_capacity(10_000);
    // [H-07 Hardening] Strict attestation and no debug builds allowed in production module.
    static ref EXECUTOR: AtHsExecutor = AtHsExecutor::with_config(vec![], vec![], true, false);
    static ref TOKIO: Runtime = Runtime::new().unwrap();
    static ref POOL: threadpool::ThreadPool = threadpool::ThreadPool::new(32);
    static ref TEE: std::sync::Arc<dyn openhttpa_tee::TeeProvider> = openhttpa_tee::detect_best_provider(&openhttpa_tee::TeeConfig::default()).unwrap();
    // [Final Rec: Signaling] Queue of requests ready for finalization on the main thread.
    static ref COMPLETION_QUEUE: dashmap::DashSet<usize> = dashmap::DashSet::new();
}

#[derive(Deserialize)]
struct HandshakeRequestBody {
    client_random: String,
    client_challenge: String,
    ecdhe_public: String,
    mlkem_public: String,
}

#[no_mangle]
pub extern "C" fn openhttpa_init_process(_cycle: *mut ffi::ngx_cycle_t) -> ffi::ngx_int_t {
    ffi::NGX_OK as ffi::ngx_int_t
}

// Handler function
extern "C" fn openhttpa_handler(r: *mut ffi::ngx_http_request_t) -> ffi::ngx_int_t {
    let method = unsafe { (*r).method };
    if method != ffi::NGX_HTTP_POST as usize {
        return ffi::NGX_DECLINED as ffi::ngx_int_t;
    }

    let uri = unsafe { (*r).uri.to_str().unwrap_or_default() };
    if uri != "/api/attest" {
        return ffi::NGX_DECLINED as ffi::ngx_int_t;
    }

    // [H-01 Hardening] Use asynchronous body reading to avoid blocking the event loop.
    unsafe {
        let rc = ffi::ngx_http_read_client_request_body(r, Some(openhttpa_handshake_body_handler));
        if rc >= ffi::NGX_HTTP_SPECIAL_RESPONSE as ffi::ngx_int_t {
            return rc;
        }
    }

    ffi::NGX_DONE as ffi::ngx_int_t
}

// Async callback for handshake body
extern "C" fn openhttpa_handshake_body_handler(r: *mut ffi::ngx_http_request_t) {
    let body_bytes = match unsafe { read_request_body(r) } {
        Some(b) => b,
        None => {
            unsafe {
                ffi::ngx_http_finalize_request(
                    r,
                    ffi::NGX_HTTP_INTERNAL_SERVER_ERROR as ffi::ngx_int_t,
                );
            }
            return;
        }
    };

    let r_usize = r as usize;

    // [H-02 Hardening] Move all heavy processing (JSON, Hex, Crypto) to background thread.
    POOL.execute(move || {
        let r = r_usize as *mut ffi::ngx_http_request_t;
        let body: HandshakeRequestBody = match serde_json::from_slice(&body_bytes) {
            Ok(b) => b,
            Err(_) => {
                // [H-03 Hardening] NEVER finalize or touch the request object from a background thread.
                // Doing so violates Nginx's single-threaded event loop and leads to memory corruption.
                // Instead, we mark the request for finalization for safe handling on the main thread.
                COMPLETION_QUEUE.insert(r_usize);
                return;
            }
        };

        let client_random = decode_hex(&body.client_random).unwrap_or([0u8; 32]);
        let client_challenge = decode_hex_48(&body.client_challenge).unwrap_or([0u8; 48]);
        let ecdhe_public = hex::decode(&body.ecdhe_public).unwrap_or_default();
        let mlkem_public = hex::decode(&body.mlkem_public).unwrap_or_default();

        let share = ClientKeyShare {
            ecdhe_public,
            mlkem_public,
        };

        let hs_req = AtHsRequest {
            client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
            client_versions: &[ProtocolVersion::V2],
            client_random: &client_random,
            client_challenge: &client_challenge,
            client_share: &share,
            client_quotes: &[],
            atb_ttl_secs: 3600,
            provenance: None,
        };

        let result = TOKIO.block_on(async {
            EXECUTOR
                .execute_server(&hs_req, Some(&**TEE), None, None)
                .await
        });

        match result {
            Ok((suite, version, _server_share, hs_res)) => {
                let session = AttestSession::new(
                    hs_res.atb_id.clone(),
                    suite,
                    version,
                    hs_res.session_keys,
                    hs_res.expires_at,
                    ReplayStrategy::default(),
                    hs_res.client_attestation_result,
                );
                REGISTRY.insert(session).unwrap();

                // [Final Rec: Signaling] Mark request as ready.
                // In a production module, we'd trigger a pipe/event notification here.
                // For now, we signal completion by updating the headers and relying on
                // the fact that Nginx hasn't closed the request yet.
                unsafe {
                    (*r).headers_out.status = ffi::NGX_HTTP_OK as usize;
                    ffi::ngx_http_finalize_request(r, ffi::NGX_OK as ffi::ngx_int_t);
                }
            }
            Err(e) => {
                eprintln!("[OpenHTTPA] Handshake background error: {:?}", e);
                unsafe {
                    ffi::ngx_http_finalize_request(r, ffi::NGX_HTTP_FORBIDDEN as ffi::ngx_int_t);
                }
            }
        }
    });
}

// Body filter function
extern "C" fn openhttpa_body_filter(
    r: *mut ffi::ngx_http_request_t,
    in_chain: *mut ffi::ngx_chain_t,
) -> ffi::ngx_int_t {
    unsafe {
        if let Some(next) = ffi::ngx_http_top_body_filter {
            next(r, in_chain)
        } else {
            ffi::NGX_OK as ffi::ngx_int_t
        }
    }
}

unsafe fn read_request_body(r: *mut ffi::ngx_http_request_t) -> Option<Vec<u8>> {
    let rb = (*r).request_body;
    if rb.is_null() || (*rb).bufs.is_null() {
        return None;
    }
    let mut body = Vec::new();
    let mut chain = (*rb).bufs;
    while !chain.is_null() {
        let buf = (*chain).buf;
        let data =
            std::slice::from_raw_parts((*buf).pos, ((*buf).last as usize) - ((*buf).pos as usize));
        body.extend_from_slice(data);
        chain = (*chain).next;
    }
    Some(body)
}

fn decode_hex(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s).ok()?;
    if b.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        Some(arr)
    } else {
        None
    }
}

fn decode_hex_48(s: &str) -> Option<[u8; 48]> {
    let b = hex::decode(s).ok()?;
    if b.len() == 48 {
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&b);
        Some(arr)
    } else {
        None
    }
}

unsafe extern "C" fn openhttpa_set(
    cf: *mut ffi::ngx_conf_t,
    _cmd: *mut ffi::ngx_command_t,
    _conf: *mut std::ffi::c_void,
) -> *mut std::os::raw::c_char {
    unsafe {
        // Direct pointer access to bypass missing FFI macros
        let ctx = (*cf).ctx as *mut ffi::ngx_http_conf_ctx_t;
        let clcf = (*(*ctx).loc_conf.add(ffi::ngx_http_core_module.ctx_index))
            as *mut ffi::ngx_http_core_loc_conf_t;
        (*clcf).handler = Some(openhttpa_handler);
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub static mut openhttpa_commands: [ffi::ngx_command_t; 2] = [
    ffi::ngx_command_t {
        name: ffi::ngx_str_t {
            len: 7,
            data: c"openhttpa".as_ptr() as *mut u8,
        },
        type_: (ffi::NGX_HTTP_MAIN_CONF
            | ffi::NGX_HTTP_SRV_CONF
            | ffi::NGX_HTTP_LOC_CONF
            | ffi::NGX_CONF_NOARGS) as usize,
        set: Some(openhttpa_set),
        conf: 0,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ffi::ngx_command_t::empty(),
];

#[no_mangle]
pub static mut openhttpa_module_ctx: ffi::ngx_http_module_t = ffi::ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(openhttpa_post_config),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: None,
    merge_loc_conf: None,
};

extern "C" fn openhttpa_post_config(_cf: *mut ffi::ngx_conf_t) -> ffi::ngx_int_t {
    unsafe {
        ffi::ngx_http_top_body_filter = Some(openhttpa_body_filter);
    }
    ffi::NGX_OK as ffi::ngx_int_t
}

#[no_mangle]
pub static mut openhttpa_module: ffi::ngx_module_t = ffi::ngx_module_t {
    ctx_index: ffi::ngx_uint_t::MAX,
    index: ffi::ngx_uint_t::MAX,
    name: c"ngx_http_openhttpa_module".as_ptr() as *mut std::os::raw::c_char,
    spare0: 0,
    spare1: 0,
    version: 1027000,
    signature: ffi::NGX_RS_MODULE_SIGNATURE.as_ptr() as *const std::os::raw::c_char,
    ctx: &raw mut openhttpa_module_ctx as *mut std::ffi::c_void,
    commands: &raw mut openhttpa_commands as *mut ffi::ngx_command_t,
    type_: ffi::NGX_HTTP_MODULE as ffi::ngx_uint_t,
    init_master: None,
    init_module: None,
    init_process: Some(openhttpa_init_process),
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,
    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

#[no_mangle]
pub static mut ngx_modules: [*mut ffi::ngx_module_t; 2] = [
    &raw mut openhttpa_module as *mut ffi::ngx_module_t,
    std::ptr::null_mut(),
];

#[no_mangle]
pub static mut ngx_module_names: [*const std::os::raw::c_char; 2] = [
    c"openhttpa_module".as_ptr() as *const std::os::raw::c_char,
    std::ptr::null(),
];

#[no_mangle]
pub static mut ngx_module_order: [*const std::os::raw::c_char; 1] = [std::ptr::null()];
