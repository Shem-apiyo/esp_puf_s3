#ifndef PUF_WENC_H
#define PUF_WENC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PUF_WENC_IV_BYTES    12
#define PUF_WENC_TAG_BYTES   16
#define PUF_WENC_OVERHEAD    (PUF_WENC_IV_BYTES + PUF_WENC_TAG_BYTES)

bool puf_wenc_encrypt(const uint8_t *W_plain, size_t plain_len,
                      uint8_t *out, size_t out_len);

bool puf_wenc_decrypt(const uint8_t *in, size_t in_len,
                      uint8_t *W_plain, size_t plain_len);

#endif /* PUF_WENC_H */