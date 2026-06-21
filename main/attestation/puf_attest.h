#ifndef PUF_ATTEST_H
#define PUF_ATTEST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * PUF_ATTEST.H
 * COSE_Mac0 attestation token builder.
 *
 * Token structure (hand-encoded CBOR):
 *   COSE_Mac0 = [
 *     protected:   bstr .cbor { 1: 5 }   (alg: HMAC-SHA256)
 *     unprotected: {}
 *     payload:     bstr .cbor {           (CWT claims)
 *                    1:  "esp32s3-puf-v1"  (iss)
 *                    6:  <uint32 iat>       (issued-at, ms tick)
 *                    -1: <bstr nonce>       (32-byte nonce)
 *                  }
 *     tag:         bstr  (32-byte HMAC-SHA256 over AAD||payload)
 *   ]
 *
 * K_auth from Layer 2 is the MAC key.
 * Nonce supplied by remote verifier — guarantees freshness.
 */

#define PUF_ATTEST_NONCE_BYTES   32
#define PUF_ATTEST_TAG_BYTES     32
#define PUF_ATTEST_TOKEN_MAX     256

/**
 * @brief Build a COSE_Mac0 CWT attestation token.
 *
 * @param K_auth      32-byte MAC key from Layer 2 HKDF
 * @param nonce       32-byte nonce from verifier
 * @param token_out   Output buffer for the token
 * @param token_len   On input: size of token_out.
 *                    On output: actual token length.
 * @return true on success
 */
bool puf_attest_build(const uint8_t *K_auth,
                      const uint8_t *nonce,
                      uint8_t *token_out,
                      size_t *token_len);

#endif /* PUF_ATTEST_H */