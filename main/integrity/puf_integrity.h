#ifndef PUF_INTEGRITY_H
#define PUF_INTEGRITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * PUF_INTEGRITY.H
 *
 * Hardware-rooted helper data authentication via ESP32-S3 HMAC peripheral.
 * eFuse key: BLOCK_KEY4 (HMAC_KEY4), purpose HMAC_DOWN_ALL.
 *
 * Enrollment:  compute HMAC-SHA256(eFuse_key, W) -> write tag to NVS
 * Verification: read tag from NVS -> recompute HMAC -> constant-time compare
 *
 * Nothing secret ever touches NVS.
 * Failure on any error — no bypass, no fallback.
 */

/* W = R XOR BCH_codeword(C), 256 bytes */
#define PUF_HELPER_DATA_BYTES   272
/* HMAC-SHA256 output */
#define PUF_HMAC_TAG_BYTES       32

/**
 * @brief Enrollment — compute HMAC over W and write tag to NVS.
 *        Call once at factory provisioning only.
 *
 * @param W      Helper data buffer, PUF_HELPER_DATA_BYTES
 * @return true on success, false on any failure
 */
bool puf_integrity_enroll(const uint8_t *W);

/**
 * @brief Verification — read tag from NVS, recompute HMAC, compare.
 *        Call every boot before reconciliation.
 *
 * @param W      Helper data buffer, PUF_HELPER_DATA_BYTES
 * @return true if tag matches, false on any failure or mismatch
 */
bool puf_integrity_verify(const uint8_t *W);

#endif // PUF_INTEGRITY_H




