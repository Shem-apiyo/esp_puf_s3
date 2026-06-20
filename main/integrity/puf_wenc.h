#ifndef PUF_WENC_H
#define PUF_WENC_H

/*
 * PUF_WENC.H
 * AES-256-GCM encryption of helper data W using eFuse-derived key.
 *
 * Encryption key = HMAC(eFuse_key, "W_ENCRYPT_V1")
 * Never stored — derived fresh from hardware on every use.
 * W in NVS is ciphertext — useless without eFuse key.
 *
 * Ciphertext layout in NVS blob:
 *   [12 bytes IV] [N bytes ciphertext] [16 bytes GCM tag]
 *   Total = PUF_WENC_OVERHEAD + plaintext_len
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PUF_WENC_IV_BYTES    12
#define PUF_WENC_TAG_BYTES   16
#define PUF_WENC_OVERHEAD    (PUF_WENC_IV_BYTES + PUF_WENC_TAG_BYTES)

/**
 * @brief Encrypt W using AES-256-GCM with eFuse-derived key.
 *
 * @param W_plain    Plaintext helper data, PUF_HELPER_DATA_BYTES
 * @param plain_len  Length of W_plain
 * @param out        Output buffer, must be plain_len + PUF_WENC_OVERHEAD
 * @param out_len    Size of output buffer
 * @return true on success
 */
bool puf_wenc_encrypt(const uint8_t *W_plain, size_t plain_len,
                      uint8_t *out, size_t out_len);

/**
 * @brief Decrypt W using AES-256-GCM with eFuse-derived key.
 *        Fails if tag verification fails — detects tampering.
 *
 * @param in         Encrypted blob from NVS
 * @param in_len     Length of encrypted blob
 * @param W_plain    Output plaintext buffer, must be in_len - PUF_WENC_OVERHEAD
 * @param plain_len  Size of W_plain buffer
 * @return true on success, false if decryption or tag verification fails
 */
bool puf_wenc_decrypt(const uint8_t *in, size_t in_len,
                      uint8_t *W_plain, size_t plain_len);

#endif /* PUF_WENC_H */
