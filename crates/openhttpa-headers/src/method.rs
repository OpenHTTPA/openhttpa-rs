// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! The custom "ATTEST" HTTP method used by `OpenHTTPA`.

use http::Method;
use std::sync::OnceLock;

static ATTEST_INNER: OnceLock<Method> = OnceLock::new();

/// Return a reference to the `ATTEST` [`Method`].
///
/// # Panics
/// Never panics; `"ATTEST"` is a valid HTTP method token.
pub fn attest_method() -> &'static Method {
    ATTEST_INNER
        .get_or_init(|| Method::from_bytes(b"ATTEST").expect("ATTEST is a valid HTTP method token"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attest_method_is_attest() {
        assert_eq!(attest_method().as_str(), "ATTEST");
    }
}
