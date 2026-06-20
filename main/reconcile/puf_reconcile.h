#ifndef PUF_RECONCILE_H
#define PUF_RECONCILE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define PUF_KEY_BYTES        32
#define PUF_HELPER_DATA_BYTES 272

/**
 * @brief Enrollment — generate helper data W from stable PUF response R.
 *        W = XOR of BCH codewords with R blocks.
 *        W is public — store in NVS after calling puf_integrity_enroll(W).
 *
 * @param R      Stable PUF response, 256 bytes from RTC memory
 * @param W_out  Output helper data, 256 bytes
 * @return true on success
 */
bool puf_reconcile_enroll(const uint8_t *R, uint8_t *W_out);

/**
 * @brief Reconstruction — recover K_enc and K_auth from noisy R and W.
 *        BCH-corrects R_noisy, then derives two keys via HKDF-Expand.
 *
 * @param R_noisy   Noisy PUF response from current boot, 256 bytes
 * @param W         Helper data from NVS, 256 bytes
 * @param K_enc_out Output encryption key, 32 bytes
 * @param K_auth_out Output authentication key, 32 bytes
 * @return true on success, false if BCH cannot correct errors
 */
bool puf_reconcile_reconstruct(const uint8_t *R_noisy,
                               const uint8_t *W,
                               uint8_t *K_enc_out,
                               uint8_t *K_auth_out);

#endif // PUF_RECONCILE_H



