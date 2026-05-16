// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

#ifndef OPENHTTPA_H
#define OPENHTTPA_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Return the OpenHTTPA library version string (e.g. `"0.1.0"`).
 *
 * The returned string is heap-allocated; caller must free with
 * `openhttpa_free_string`.
 */
char *openhttpa_version(void);

/**
 * Parse and validate an `AtbId` UUID string.
 *
 * Returns the normalised hyphenated form (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
 * on success, or NULL if the input is not a valid UUID.
 * Caller must free the returned string with `openhttpa_free_string`.
 *
 * # Safety
 * `atb_id` must be a valid NUL-terminated C string, or NULL.
 */
char *openhttpa_parse_atb_id(const char *atb_id);

/**
 * Perform the OpenHTTPA attestation handshake.
 *
 * Returns a NUL-terminated AtB ID string on success, or NULL on failure.
 * Caller must free with `openhttpa_free_string`.
 *
 * # Safety
 * `server_uri` must be a valid NUL-terminated C string.
 */
char *openhttpa_attest_handshake(const char *server_uri);

/**
 * Perform a confidential LLM chat completion.
 *
 * `messages_json` must be a JSON array of `[role, content]` pairs, e.g.:
 * ```json
 * [["user","Hello!"],["assistant","Hi there!"]]
 * ```
 * Returns a NUL-terminated string with the assistant reply, or NULL.
 * Caller must free with `openhttpa_free_string`.
 *
 * # Safety
 * All pointer arguments must be valid NUL-terminated C strings or NULL.
 */
char *openhttpa_confidential_chat(const char *server_uri,
                               const char *model,
                               const char *messages_json);

char *openhttpa_server_handshake(const char *request_json);

char *openhttpa_server_decrypt(const char *atb_id_str, uint64_t nonce_val, const char *ciphertext_hex);

char *openhttpa_server_encrypt(const char *atb_id_str, const char *plaintext_hex);

/**
 * Free a string returned by an `openhttpa_*` function.
 *
 * Calling with `NULL` is a no-op.
 *
 * # Safety
 * `ptr` must have been returned by an `openhttpa_*` function and not yet freed.
 */
void openhttpa_free_string(char *ptr);

#endif  /* OPENHTTPA_H */
