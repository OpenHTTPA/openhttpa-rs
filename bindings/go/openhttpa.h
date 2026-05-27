#ifndef OPENHTTPA_H
#define OPENHTTPA_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct OpenHttpaCtx OpenHttpaCtx;

struct OpenHttpaCtx *openhttpa_ctx_new(void);

/**
 * Free an `OpenHttpaCtx`.
 *
 * # Safety
 *
 * The `ctx` must have been returned by `openhttpa_ctx_new` and not yet freed.
 */
void openhttpa_ctx_free(struct OpenHttpaCtx *ctx);

char *openhttpa_version(void);

/**
 * Parse a string into a canonical ATB-ID.
 *
 * # Safety
 *
 * The `atb_id` pointer must be a valid, null-terminated C string.
 */
char *openhttpa_parse_atb_id(const char *atb_id);

/**
 * Perform a full `OpenHTTPA` attestation handshake.
 *
 * # Safety
 *
 * The `server_uri` pointer must be a valid, null-terminated C string.
 */
char *openhttpa_attest_handshake(struct OpenHttpaCtx *ctx, const char *server_uri);

/**
 * Send a confidential chat message to an LLM via `OpenHTTPA`.
 *
 * # Safety
 *
 * All input pointers must be valid, null-terminated C strings.
 */
char *openhttpa_confidential_chat(struct OpenHttpaCtx *ctx,
                                  const char *server_uri,
                                  const char *model,
                                  const char *messages_json);

/**
 * Handle a server-side `OpenHTTPA` handshake request.
 *
 * # Safety
 *
 * The `request_json` pointer must be a valid, null-terminated C string.
 */
char *openhttpa_server_handshake(struct OpenHttpaCtx *ctx, const char *request_json);

/**
 * Decrypt a server-side `OpenHTTPA` request payload.
 *
 * # Safety
 *
 * Both `atb_id_str` and `ciphertext_hex` must be valid, null-terminated C strings.
 */
char *openhttpa_server_decrypt(struct OpenHttpaCtx *ctx,
                               const char *atb_id_str,
                               uint64_t nonce_val,
                               const char *ciphertext_hex);

/**
 * Encrypt a server-side `OpenHTTPA` response payload.
 *
 * # Safety
 *
 * Both `atb_id_str` and `plaintext_hex` must be valid, null-terminated C strings.
 */
char *openhttpa_server_encrypt(struct OpenHttpaCtx *ctx,
                               const char *atb_id_str,
                               const char *plaintext_hex);

/**
 * Free a string returned by any of the `openhttpa_*` functions.
 *
 * # Safety
 *
 * The `ptr` must have been returned by an `openhttpa_*` function and not yet freed.
 */
void openhttpa_free_string(char *ptr);

#endif  /* OPENHTTPA_H */
