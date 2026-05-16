// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Anti-replay guard for `OpenHTTPA` `TrR` nonces.
//!
//! Uses a sliding bit-window to efficiently track which 64-bit nonces have
//! been seen within the recent window, without unbounded memory growth.

use async_trait::async_trait;
use std::sync::Mutex;

use thiserror::Error;

/// Anti-replay errors.
// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("replay detected: nonce {0} already seen")]
    Replay(u64),
    #[error("nonce {0} is too old (more than window_size below highest seen)")]
    TooOld(u64),
    #[error("distributed storage error: {0}")]
    StorageError(String),
}

/// A trait for anti-replay guards that can be used in distributed environments.
#[async_trait]
pub trait DistributedReplayGuard: Send + Sync {
    /// Atomically check that `nonce` has not been seen before **and** record it
    /// as seen in a single operation.
    ///
    /// This is the only method callers should use. Implementations must ensure
    /// the check and the commit are a single atomic step — for example, a Redis
    /// `SET NX` — to eliminate the TOCTOU window that exists when `check` and
    /// `accept` are called as separate round-trips.
    ///
    /// # Errors
    /// Returns `ReplayError::Replay` if the nonce has already been accepted, or
    /// `ReplayError::StorageError` if the backing store is unavailable.
    async fn check_and_accept(&self, key: &str, nonce: u64) -> Result<(), ReplayError>;

    /// Check if a nonce is valid **without** recording it.
    ///
    /// # Deprecated
    /// Prefer [`Self::check_and_accept`]. Calling `check` followed by a
    /// separate `accept` introduces a TOCTOU race in distributed deployments.
    /// This method is retained only for use-cases that genuinely need a
    /// read-only probe (e.g. metrics/diagnostics).
    async fn check(&self, key: &str, nonce: u64) -> Result<(), ReplayError>;

    /// Record `nonce` as seen **without** checking first.
    ///
    /// # Deprecated
    /// Prefer [`Self::check_and_accept`]. See [`Self::check`] for rationale.
    async fn accept(&self, key: &str, nonce: u64) -> Result<(), ReplayError>;
}

/// A bitmask anti-replay window.
///
/// Tracks the `WINDOW` most-recently seen nonces. Nonces older than
/// `highest - WINDOW` are rejected as too old.
pub struct ReplayGuard<const WINDOW: usize = 64> {
    inner: Mutex<ReplayGuardInner<WINDOW>>,
}

struct ReplayGuardInner<const W: usize> {
    highest: u64,
    window: [u64; W], // bit-packed; index = nonce % W
}

impl<const W: usize> ReplayGuardInner<W> {
    const fn new() -> Self {
        Self {
            highest: 0,
            window: [0u64; W],
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: `diff as usize` — `diff` is the distance from `highest`; the
    // guard above (`diff as usize >= W * 64`) guarantees `diff < W * 64`
    // which on any supported target (16-/32-/64-bit) fits in `usize`.
    // `nonce as usize` / `nonce / W as u64` — nonces are 64-bit sequence
    // numbers.  The bit-slot index `(nonce as usize) % W` is bounded by W
    // (always ≤ 64), and the bit index `(nonce / W as u64) % 64` is bounded
    // by 64 — both fit in `usize` and `u32` respectively.
    // R-01: NOT `const fn` — called only via `Mutex::lock()`, so the `const`
    // qualifier is semantically misleading and prevents future non-const logic.
    #[allow(clippy::missing_const_for_fn)] // R-01: intentionally non-const; see above
    fn check(&self, nonce: u64) -> Result<(), ReplayError> {
        if nonce == 0 {
            return Err(ReplayError::TooOld(nonce));
        }
        if nonce > self.highest {
            // Future nonces are always "checkable" unless they are absurdly large,
            // but we don't want to restrict them here.
            return Ok(());
        }
        let diff = self.highest - nonce;
        if diff as usize >= W * 64 {
            return Err(ReplayError::TooOld(nonce));
        }

        // Check bit for this nonce.
        let slot = (nonce as usize) % W;
        let bit = (nonce / W as u64) % 64;
        let mask = 1u64 << bit;
        if self.window[slot] & mask != 0 {
            return Err(ReplayError::Replay(nonce));
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: Same cast rationale as `check` above — `advance as usize` is
    // bounded by the `W * 64` guard on entry; all index casts are within
    // window-size bounds.  See `check` for the full argument.
    fn accept(&mut self, nonce: u64) {
        if nonce > self.highest {
            let advance = nonce - self.highest;
            if advance as usize >= W * 64 {
                self.window = [0u64; W];
            } else {
                for step in 1..=(advance as usize) {
                    let reclaimed_nonce = self.highest + step as u64;
                    let slot = (reclaimed_nonce as usize) % W;
                    let bit = (reclaimed_nonce / W as u64) % 64;
                    self.window[slot] &= !(1u64 << bit);
                }
            }
            self.highest = nonce;
        }

        let slot = (nonce as usize) % W;
        let bit = (nonce / W as u64) % 64;
        let mask = 1u64 << bit;
        self.window[slot] |= mask;
    }
}

impl<const W: usize> ReplayGuard<W> {
    /// Create a new, empty replay guard with a bit-window of `W * 64` nonces.
    ///
    /// The generic const `W` defaults to `64`, giving a window of 4096 nonces.
    /// Choose `W` according to the maximum expected burst of in-flight requests.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(ReplayGuardInner::new()),
        }
    }

    /// Verify that `nonce` is not a replay and is within the valid window.
    /// Does NOT mutate the guard state.
    ///
    /// # Errors
    /// * [`ReplayError::Replay`] — the nonce has already been accepted.
    /// * [`ReplayError::TooOld`] — the nonce is too old.
    pub fn check(&self, nonce: u64) -> Result<(), ReplayError> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .check(nonce)
    }

    /// Commit `nonce` to the guard state. Must be called after successful
    /// authentication of the message bearing the nonce.
    pub fn accept(&self, nonce: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accept(nonce);
    }

    /// Legacy combined method. **Prefer `check()` then `accept()`** for better
    /// security against unauthenticated `DoS`.
    ///
    /// # Errors
    /// Returns [`Err`] if the nonce is invalid or replayed.
    pub fn check_and_accept(&self, nonce: u64) -> Result<(), ReplayError> {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.check(nonce)?;
        g.accept(nonce);
        drop(g);
        Ok(())
    }

    /// Export current state for persistence.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned and the lock cannot be acquired.
    #[must_use]
    pub fn export_state(&self) -> (u64, [u64; W]) {
        let g = self.inner.lock().unwrap();
        (g.highest, g.window)
    }

    /// Import state from persistence.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned and the lock cannot be acquired.
    pub fn import_state(&self, highest: u64, window: [u64; W]) {
        let mut g = self.inner.lock().unwrap();
        g.highest = highest;
        g.window = window;
    }
}

impl<const W: usize> Default for ReplayGuard<W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonces_accepted() {
        let g = ReplayGuard::<64>::new();
        g.check_and_accept(1).unwrap();
        g.check_and_accept(2).unwrap();
        g.check_and_accept(100).unwrap();
    }

    #[test]
    fn duplicate_rejected() {
        let g = ReplayGuard::<64>::new();
        g.check_and_accept(5).unwrap();
        assert!(matches!(g.check_and_accept(5), Err(ReplayError::Replay(5))));
    }

    #[test]
    fn sequential_full_window() {
        let g = ReplayGuard::<64>::new();
        for i in 1u64..=128 {
            g.check_and_accept(i).unwrap();
        }
    }

    /// Regression: a nonce accepted before a large gap must NOT be accepted
    /// again after the gap advances the window past it.
    #[test]
    fn replay_after_large_gap_rejected() {
        let g = ReplayGuard::<64>::new();
        // Accept nonce 5
        g.check_and_accept(5).unwrap();
        // Advance the window far enough that slot for 5 would have been
        // incorrectly cleared in the old implementation
        g.check_and_accept(1000).unwrap();
        // Nonce 5 is too old now (1000 - 5 = 995 >= 64*64=4096? No, 995 < 4096)
        // It's within window distance but must still be rejected as already seen.
        // For a W=64 window covering 64*64=4096 nonces: 1000-5=995 < 4096 so it's in range.
        assert!(
            g.check_and_accept(5).is_err(),
            "nonce 5 was already accepted and must be rejected after gap advance"
        );
    }

    /// Nonces exactly at window boundary: too-old nonce rejected, in-window accepted.
    #[test]
    fn window_boundary() {
        const W: usize = 4;
        let g = ReplayGuard::<W>::new();
        // Window covers W*64 = 256 nonces
        g.check_and_accept(300).unwrap();
        // Nonce 1 is 299 positions back; 299 >= 256, so too old
        assert!(matches!(g.check_and_accept(1), Err(ReplayError::TooOld(1))));
        // Nonce 50 is 250 positions back; 250 < 256, so in window → accepted
        g.check_and_accept(50).unwrap();
    }

    #[test]
    fn zero_nonce_rejected() {
        let g = ReplayGuard::<64>::new();
        assert!(matches!(g.check_and_accept(0), Err(ReplayError::TooOld(0))));
    }

    #[test]
    fn out_of_order_within_window() {
        let g = ReplayGuard::<64>::new();
        g.check_and_accept(10).unwrap();
        g.check_and_accept(5).unwrap(); // out of order but within window
        g.check_and_accept(8).unwrap();
        // Replay of 5 within window must fail
        assert!(g.check_and_accept(5).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_replay_guard_monotonic(nonces in proptest::collection::vec(1u64..10000u64, 1..100)) {
            let guard = ReplayGuard::<64>::new();
            let mut seen = std::collections::HashSet::new();
            let mut highest = 0;

            for nonce in nonces {
                let res = guard.check(nonce);
                if seen.contains(&nonce) {
                    assert!(res.is_err(), "Nonce {nonce} should be replayed");
                } else if highest > 0 && nonce + 4096 <= highest {
                    assert!(res.is_err(), "Nonce {nonce} should be too old");
                } else {
                    assert!(res.is_ok(), "Nonce {nonce} should be valid");
                    guard.accept(nonce);
                    seen.insert(nonce);
                    if nonce > highest {
                        highest = nonce;
                    }
                }
            }
        }

        #[test]
        fn test_replay_guard_window_sliding(
            initial in 1u64..1000u64,
            gap in 4096u64..8192u64
        ) {
            let guard = ReplayGuard::<64>::new();
            guard.accept(initial);

            // Advance window past 'initial'
            let advanced = initial + gap;
            guard.accept(advanced);

            // 'initial' must be too old now
            assert!(matches!(guard.check(initial), Err(ReplayError::TooOld(_))));
        }

        // T-04-A: Any sequence of *distinct* nonces in [1, window_size) must
        // never produce a false replay.
        #[test]
        fn no_false_replays_for_distinct_nonces(
            nonces in proptest::collection::hash_set(1u64..4096u64, 1..100)
        ) {
            let guard = ReplayGuard::<64>::new();
            for nonce in &nonces {
                // All nonces are within the window (max distance < 4096)
                // and distinct, so every accept must succeed.
                guard.check_and_accept(*nonce)
                    .expect("distinct in-window nonce must not produce a false replay");
            }
        }

        // T-04-B: Any nonce that was accepted must ALWAYS be detected as a
        // replay on the second submission, regardless of what happened in
        // between (no other nonces are submitted so the window never evicts).
        #[test]
        fn accepted_nonce_always_replayed(nonce in 1u64..4096u64) {
            let guard = ReplayGuard::<64>::new();
            guard.check_and_accept(nonce).expect("first submission must succeed");
            assert!(
                matches!(guard.check_and_accept(nonce), Err(ReplayError::Replay(_))),
                "second submission of nonce {nonce} must be rejected as replay"
            );
        }

        // T-04-C: Nonces that straddle the window boundary — some just inside,
        // some just outside — must be classified correctly.
        #[test]
        fn window_boundary_classification(
            // Use W=4 so window covers 4*64 = 256 nonces — easier to straddle.
            high in 300u64..600u64,
            below_in  in 1u64..256u64, // distance = high - below_in; in-window iff < 256
            below_out in 256u64..600u64, // distance = high - below_out; out-window iff >= 256
        ) {
            prop_assume!(high > below_out);  // ensure subtraction is non-negative
            let guard = ReplayGuard::<4>::new();
            guard.check_and_accept(high).expect("high nonce must be accepted");

            let old_nonce = high - below_out; // distance >= 257, must be too-old
            assert!(
                matches!(guard.check(old_nonce), Err(ReplayError::TooOld(_))),
                "nonce {old_nonce} is {below_out} behind {high} (>= window) — must be TooOld"
            );

            // 'high - below_in' is in-window and not yet accepted — must be OK
            if below_in < below_out && high > below_in {
                let in_nonce = high - below_in; // distance < 256, within window
                assert!(
                    guard.check(in_nonce).is_ok(),
                    "nonce {in_nonce} is {below_in} behind {high} (< window) — must be valid"
                );
            }
        }
    }
}
