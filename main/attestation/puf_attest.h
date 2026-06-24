#ifndef PUF_ATTEST_H
#define PUF_ATTEST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PUF_ATTEST_NONCE_BYTES   32
#define PUF_ATTEST_TAG_BYTES     32
#define PUF_ATTEST_TOKEN_MAX     256

bool puf_attest_build(const uint8_t *K_auth,
                      const uint8_t *nonce,
                      uint8_t *token_out,
                      size_t *token_len);

#endif /* PUF_ATTEST_H */
