#ifndef PUF_KDF_H
#define PUF_KDF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Derives key_len bytes into key_out using HKDF-SHA256.
 * IKM = HMAC-SHA256(eFuse BLOCK_KEY4, "PUF_IKM_V1")
 * Info = label (domain separator)
 *
 * Callers:
 *   puf_wenc.c    -> label = "W_ENCRYPT_V1",  len = 12
 *   puf_integrity -> label = "INTEGRITY_V1",  len = 12
 */
bool puf_hkdf_derive(const char *label, size_t label_len,
                     uint8_t *key_out, size_t key_len);

#endif /* PUF_KDF_H */