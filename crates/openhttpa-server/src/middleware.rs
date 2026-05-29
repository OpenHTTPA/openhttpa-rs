// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Tower middleware for trusted requests.
//!
//! [`TrRequestLayer`] validates the `Attest-Base-ID` header, checks the
//! session is alive and attested, and passes the request through.
//! Actual payload decryption is left to the inner handler which has access
//! to the session keys via [`crate::atb_registry::AtbRegistry`].

use std::task::{Context, Poll};

use axum::body::Body;
use http::{Request, Response};
use std::sync::Arc;
use tower::{Layer, Service};

use crate::atb_registry::AtbRegistry;
use bloomfilter::Bloom;
use openhttpa_core::replay_guard::{DistributedReplayGuard, ReplayError};
use std::sync::Mutex;

/// Tower [`Layer`] that injects `AtB` session validation before the inner service.
#[derive(Clone)]
pub struct TrRequestLayer {
    registry: AtbRegistry,
}

impl TrRequestLayer {
    #[must_use]
    pub const fn new(registry: AtbRegistry) -> Self {
        Self { registry }
    }
}

impl<S> Layer<S> for TrRequestLayer {
    type Service = TrRequestMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TrRequestMiddleware {
            inner,
            registry: self.registry.clone(),
        }
    }
}

/// The concrete middleware service produced by [`TrRequestLayer`].
#[derive(Clone)]
pub struct TrRequestMiddleware<S> {
    inner: S,
    registry: AtbRegistry,
}

impl<S> Service<Request<Body>> for TrRequestMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        use http::StatusCode;
        use openhttpa_headers::HDR_ATTEST_BASE_ID;
        use openhttpa_proto::AtbId;

        let registry = self.registry.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let base_id_hdr = req.headers().get(&*HDR_ATTEST_BASE_ID);
            let session = base_id_hdr
                .and_then(|val| val.to_str().ok())
                .and_then(|s| s.parse::<AtbId>().ok())
                .and_then(|id| registry.get(&id));

            if let Some(sess) = session {
                let mut req = req;
                req.extensions_mut().insert(sess.state().id);
                req.extensions_mut().insert(sess);
                inner.call(req).await
            } else {
                let id_raw = base_id_hdr.and_then(|v| v.to_str().ok()).unwrap_or("none");
                tracing::error!(base_id = %id_raw, "Middleware: Session not found or invalid");
                let resp = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())
                    .unwrap();
                Ok(resp)
            }
        })
    }
}

/// A local in-memory Bloom Filter replay guard.
///
/// ## Capacity Warning (SEC-07)
///
/// A Bloom filter has a fixed capacity. Once the number of accepted nonces
/// approaches `items`, the false-positive rate climbs, causing legitimate
/// nonces to be rejected as replays. This is a `DoS` vector: an adversary can
/// exhaust the filter by submitting `items` unique nonces.
///
/// **Mitigations required in production:**
/// - Set `items` to at least `2 × peak_requests_per_TTL`.
/// - Call [`LocalReplayGuard::rotate`] periodically (e.g. every `ttl / 2`).
///   `rotate` swaps in a fresh filter while retaining the previous one as an
///   overlap filter; nonces seen in *either* filter are still rejected (MED-01).
/// - For multi-node deployments, use `RedisReplayGuard` instead.
///
/// ## Rotation example
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use openhttpa_server::middleware::LocalReplayGuard;
///
/// let guard = Arc::new(LocalReplayGuard::new(100_000, 0.001));
/// // … wire into Rtt0ResumptionLayer …
///
/// // In a background task, rotate every half-TTL:
/// // guard.rotate();
/// ```
pub struct LocalReplayGuard {
    /// The current (active) Bloom filter — all new nonces are written here.
    bloom: Mutex<Bloom<Vec<u8>>>,
    /// MED-01: the previous filter retained after a rotation.
    ///
    /// During the overlap window (one full TTL after rotation) legitimate
    /// nonces that were accepted just before the rotate call will still be
    /// detected as replays.  The overlap filter is *read-only* after rotation.
    prev_bloom: Mutex<Option<Bloom<Vec<u8>>>>,
    /// Number of items the filter was sized for. Used to detect exhaustion.
    capacity: usize,
    /// Approximate count of items inserted into the current filter.
    count: std::sync::atomic::AtomicUsize,
}

impl LocalReplayGuard {
    /// Create a new `LocalReplayGuard`.
    ///
    /// * `items` — expected number of unique nonces per rotation period.
    ///   Size to at least `2 × peak_requests_per_TTL`.
    /// * `fp_rate` — desired false-positive rate at `items` capacity (e.g. `0.001`).
    #[must_use]
    pub fn new(items: usize, fp_rate: f64) -> Self {
        Self {
            bloom: Mutex::new(Bloom::new_for_fp_rate(items, fp_rate)),
            prev_bloom: Mutex::new(None),
            capacity: items,
            count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Create a new `LocalReplayGuard` that automatically rotates its internal
    /// Bloom filter on the given `interval`.
    ///
    /// A background `tokio` task is spawned that calls [`Self::rotate`] every
    /// `interval`.  The task stops automatically when the last `Arc` clone of
    /// the returned guard is dropped.
    ///
    /// * `items`   — expected unique nonces per rotation period (size to at
    ///   least `2 × peak_requests_per_TTL`).
    /// * `fp_rate`  — desired false-positive rate at `items` capacity.
    /// * `interval` — how often to rotate the filter (typically `ttl / 2`).
    ///
    /// # Panics
    /// Panics if called outside a Tokio runtime.
    #[must_use]
    pub fn with_auto_rotate(
        items: usize,
        fp_rate: f64,
        interval: std::time::Duration,
    ) -> Arc<Self> {
        let guard = Arc::new(Self::new(items, fp_rate));
        let weak = Arc::downgrade(&guard);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match weak.upgrade() {
                    Some(g) => g.rotate(),
                    // All strong references have been dropped — stop the task.
                    None => break,
                }
            }
        });
        guard
    }
    #[must_use]
    pub fn is_near_capacity(&self) -> bool {
        self.count.load(std::sync::atomic::Ordering::Relaxed) >= (self.capacity * 4 / 5)
    }

    /// Replace the active filter with a fresh empty filter (MED-01 double-buffer).
    ///
    /// The previous filter is retained as an *overlap buffer*.  During
    /// `check_and_accept`, a nonce is rejected if it appears in **either** the
    /// active or the overlap filter, ensuring that nonces accepted just before
    /// a rotation are still detected as replays throughout the remainder of
    /// their TTL window.
    ///
    /// Call this from a periodic Tokio task once the session TTL has elapsed
    /// or when [`Self::is_near_capacity`] returns `true`.
    ///
    /// # Panics
    /// Panics if either internal `Mutex` is poisoned.
    pub fn rotate(&self) {
        let new_filter = Bloom::new_for_fp_rate(self.capacity, 1e-3);
        let mut bloom = self.bloom.lock().expect("bloom mutex poisoned");
        let old = std::mem::replace(&mut *bloom, new_filter);
        drop(bloom);

        *self.prev_bloom.lock().expect("prev_bloom mutex poisoned") = Some(old);
        self.count.store(0, std::sync::atomic::Ordering::Relaxed);

        tracing::info!(
            capacity = self.capacity,
            "LocalReplayGuard rotated — overlap filter retained"
        );
    }
}

impl DistributedReplayGuard for LocalReplayGuard {
    /// Atomically check and set in a single mutex lock.
    ///
    /// Holding the lock for both the check and the insert ensures no TOCTOU
    /// race between two concurrent callers with the same nonce.
    ///
    /// MED-01: also consults the overlap (previous) filter so that nonces
    /// accepted just before a rotation are still rejected as replays.
    fn check_and_accept(
        &self,
        _key: &str,
        nonce: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ReplayError>> + Send + '_>>
    {
        Box::pin(async move {
            let nonce_bytes = nonce.to_be_bytes().to_vec();

            // Check overlap filter first (read-only, no insertion).
            if let Some(ref prev) = *self.prev_bloom.lock().expect("prev_bloom mutex poisoned")
                && prev.check(&nonce_bytes)
            {
                return Err(ReplayError::Replay(nonce));
            }

            let mut bloom = self.bloom.lock().expect("bloom mutex poisoned");
            if bloom.check(&nonce_bytes) {
                return Err(ReplayError::Replay(nonce));
            }
            bloom.set(&nonce_bytes);
            drop(bloom);
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.is_near_capacity() {
                tracing::warn!(
                    capacity = self.capacity,
                    "LocalReplayGuard approaching capacity — \
                     false-positive rate rising; rotate the guard"
                );
            }
            Ok(())
        })
    }

    fn check(
        &self,
        _key: &str,
        nonce: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ReplayError>> + Send + '_>>
    {
        Box::pin(async move {
            let nonce_bytes = nonce.to_be_bytes().to_vec();
            if let Some(ref prev) = *self.prev_bloom.lock().expect("prev_bloom mutex poisoned")
                && prev.check(&nonce_bytes)
            {
                return Err(ReplayError::Replay(nonce));
            }
            if self
                .bloom
                .lock()
                .expect("bloom mutex poisoned")
                .check(&nonce_bytes)
            {
                Err(ReplayError::Replay(nonce))
            } else {
                Ok(())
            }
        })
    }

    fn accept(
        &self,
        _key: &str,
        nonce: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ReplayError>> + Send + '_>>
    {
        Box::pin(async move {
            self.bloom
                .lock()
                .expect("bloom mutex poisoned")
                .set(&nonce.to_be_bytes().to_vec());
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        })
    }
}

/// Layer that handles 0-RTT session resumption.
#[derive(Clone)]
pub struct Rtt0ResumptionLayer {
    registry: AtbRegistry,
    ticket_engine: std::sync::Arc<openhttpa_core::session::ticket::TicketEngine>,
    replay_guard: Arc<dyn DistributedReplayGuard>,
}

impl Rtt0ResumptionLayer {
    #[must_use]
    pub fn new(
        registry: AtbRegistry,
        ticket_engine: openhttpa_core::session::ticket::TicketEngine,
        replay_guard: Arc<dyn DistributedReplayGuard>,
    ) -> Self {
        Self {
            registry,
            ticket_engine: std::sync::Arc::new(ticket_engine),
            replay_guard,
        }
    }
}

impl<S> Layer<S> for Rtt0ResumptionLayer {
    type Service = Rtt0ResumptionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Rtt0ResumptionMiddleware {
            inner,
            registry: self.registry.clone(),
            ticket_engine: self.ticket_engine.clone(),
            replay_guard: self.replay_guard.clone(),
        }
    }
}

/// Middleware that intercepts 0-RTT tickets and restores sessions.
#[derive(Clone)]
pub struct Rtt0ResumptionMiddleware<S> {
    inner: S,
    registry: AtbRegistry,
    ticket_engine: std::sync::Arc<openhttpa_core::session::ticket::TicketEngine>,
    replay_guard: Arc<dyn DistributedReplayGuard>,
}

impl<S> Service<Request<Body>> for Rtt0ResumptionMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        use openhttpa_core::session::AttestSession;
        use openhttpa_headers::HDR_ATTEST_TICKET_RESUMPTION;

        let registry = self.registry.clone();
        let engine = self.ticket_engine.clone();
        let guard = self.replay_guard.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let ticket_hdr = req.headers().get(&*HDR_ATTEST_TICKET_RESUMPTION);

            if let Some(hdr_val) = ticket_hdr
                && let Ok(ticket_b64) = hdr_val.to_str()
                && let Ok(ticket_raw) = hex::decode(ticket_b64)
                && let Ok(mut durable_state) = engine.unseal_session(&ticket_raw)
            {
                // SEC-02: Check distributed replay guard using the ticket's internal nonce.
                // We use the AtbId as the key for the replay guard window.
                let nonce = durable_state.client_counter; // In 0-RTT, the nonce is bound to the state
                let atb_id_str = durable_state.id.to_string();

                // SEC-03: Use the atomic check_and_accept to avoid
                // the TOCTOU window between a separate check + accept.
                if guard.check_and_accept(&atb_id_str, nonce).await.is_err() {
                    tracing::warn!(base_id = %atb_id_str, nonce = nonce, "Blocked replayed 0-RTT ticket");
                } else {
                    // SA-05: Handle 0-RTT key derivation if salt is present
                    let rtt0_salt = openhttpa_headers::decode_attest_ticket(req.headers())
                        .ok()
                        .and_then(|d| d.salt);

                    if let Some(salt) = rtt0_salt
                        && let Ok(k) = openhttpa_core::handshake::SessionKeys::derive_0rtt(
                            &durable_state.resumption_secret,
                            &salt,
                        )
                    {
                        tracing::info!("Deriving fresh 0-RTT keys");
                        durable_state.keys = openhttpa_core::session::SealedSessionKeys::new(k);
                    }

                    // Nonce was already committed atomically above by check_and_accept.

                    let session = AttestSession::from_durable(durable_state);
                    if let Err(e) = registry.insert(session.clone()) {
                        tracing::error!(error = %e, "Failed to insert resumed session");
                    } else {
                        tracing::info!(base_id = %session.state().id, "0-RTT session resumed");
                    }
                }
            }

            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_core::replay_guard::ReplayError;

    // ── LocalReplayGuard::check_and_accept ────────────────────────────────

    #[tokio::test]
    async fn local_guard_accepts_fresh_nonce() {
        let guard = LocalReplayGuard::new(1000, 0.001);
        assert!(guard.check_and_accept("", 1).await.is_ok());
    }

    #[tokio::test]
    async fn local_guard_rejects_duplicate_nonce() {
        let guard = LocalReplayGuard::new(1000, 0.001);
        guard.check_and_accept("", 42).await.unwrap();
        let result = guard.check_and_accept("", 42).await;
        assert!(
            matches!(result, Err(ReplayError::Replay(42))),
            "expected Replay(42), got {result:?}"
        );
    }

    #[tokio::test]
    async fn local_guard_independent_nonces_all_accepted() {
        let guard = LocalReplayGuard::new(1000, 0.001);
        for n in 0u64..100 {
            assert!(
                guard.check_and_accept("", n).await.is_ok(),
                "nonce {n} rejected"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_guard_concurrent_replays_prevent_toctou() {
        use std::sync::Arc;
        let guard = Arc::new(LocalReplayGuard::new(1000, 0.001));

        let mut handles = vec![];
        for _ in 0..100 {
            let guard_clone = guard.clone();
            handles.push(tokio::spawn(async move {
                guard_clone.check_and_accept("k_concurrent", 1337).await
            }));
        }

        let mut success_count = 0;
        let mut replay_err_count = 0;

        for h in handles {
            match h.await.unwrap() {
                Ok(()) => success_count += 1,
                Err(ReplayError::Replay(1337)) => replay_err_count += 1,
                Err(e) => panic!("Unexpected error type: {e:?}"),
            }
        }

        assert_eq!(success_count, 1, "Exactly one thread should win the race");
        assert_eq!(
            replay_err_count, 99,
            "All other 99 threads must receive ReplayError"
        );
    }

    // ── LocalReplayGuard::rotate (MED-01 overlap) ─────────────────────────

    #[tokio::test]
    async fn rotate_rejects_pre_rotation_nonces() {
        let guard = LocalReplayGuard::new(1000, 0.001);
        // Accept nonce BEFORE rotation.
        guard.check_and_accept("", 99).await.unwrap();
        // Rotate — old filter moves to overlap buffer.
        guard.rotate();
        // The nonce should still be rejected (overlap filter consulted).
        let result = guard.check_and_accept("", 99).await;
        assert!(
            matches!(result, Err(ReplayError::Replay(99))),
            "pre-rotation nonce should be rejected post-rotate; got {result:?}"
        );
    }

    #[tokio::test]
    async fn rotate_resets_count_and_accepts_new_nonces() {
        let guard = LocalReplayGuard::new(1000, 0.001);
        guard.check_and_accept("", 1).await.unwrap();
        guard.rotate();
        // count should be reset; new nonces (including previously seen ones
        // after a second rotation that clears the overlap) can be accepted.
        // A brand-new nonce not in either filter must be accepted immediately.
        assert!(guard.check_and_accept("", 2).await.is_ok());
    }

    #[tokio::test]
    async fn double_rotate_clears_overlap() {
        let guard = LocalReplayGuard::new(1000, 0.001);
        guard.check_and_accept("", 7).await.unwrap();
        // First rotate: nonce 7 is in overlap buffer.
        guard.rotate();
        // Second rotate: overlap is replaced — nonce 7 no longer tracked.
        guard.rotate();
        // Now nonce 7 should be accepted again (guard has forgotten it).
        assert!(guard.check_and_accept("", 7).await.is_ok());
    }

    // ── is_near_capacity ─────────────────────────────────────────────────

    #[test]
    fn near_capacity_threshold_at_80_percent() {
        let guard = LocalReplayGuard::new(10, 0.001);
        // At 0 items, not near capacity.
        assert!(!guard.is_near_capacity());
        // Manually bump counter to exactly 80% (8/10).
        guard.count.store(8, std::sync::atomic::Ordering::Relaxed);
        assert!(guard.is_near_capacity());
        // Below threshold (7/10 = 70%).
        guard.count.store(7, std::sync::atomic::Ordering::Relaxed);
        assert!(!guard.is_near_capacity());
    }

    // ── TrRequestMiddleware ───────────────────────────────────────────────

    #[tokio::test]
    async fn tr_request_middleware_missing_header() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use http::{Request, StatusCode};
        use tower::ServiceExt;

        let registry = AtbRegistry::new();
        let app = Router::new()
            .route("/", get(|| async { "OK" }))
            .layer(TrRequestLayer::new(registry));

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn dummy_cx() -> std::task::Context<'static> {
        let waker = Box::leak(Box::new(std::task::Waker::noop()));
        std::task::Context::from_waker(waker)
    }

    #[tokio::test]
    async fn middleware_poll_ready_delegation() {
        use axum::body::Body;
        use http::Request;
        use tower::Service;

        let registry = AtbRegistry::new();
        let inner = tower::service_fn(|_req: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(Body::empty()))
        });

        let mut svc = TrRequestMiddleware { inner, registry };

        let mut cx = dummy_cx();
        assert!(svc.poll_ready(&mut cx).is_ready());
    }

    #[tokio::test]
    async fn rtt0_middleware_poll_ready_delegation() {
        use axum::body::Body;
        use http::Request;
        use tower::Service;

        let registry = AtbRegistry::new();
        let engine = openhttpa_core::session::ticket::TicketEngine::new(
            openhttpa_core::session::ticket::TicketKey::generate(),
        );
        let guard = Arc::new(LocalReplayGuard::new(1000, 0.001));

        let inner = tower::service_fn(|_req: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(Body::empty()))
        });

        let mut svc = Rtt0ResumptionMiddleware {
            inner,
            registry,
            ticket_engine: Arc::new(engine),
            replay_guard: guard,
        };

        let mut cx = dummy_cx();
        assert!(svc.poll_ready(&mut cx).is_ready());
    }
}
