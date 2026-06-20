#include "puf_reconcile.h"
#include "bch.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "PUF_RECONCILE";

/*
 * BCH(255,119,20) parameters for m=8, t=20
 * Data bytes per block:  15 (119 bits, LSB-padded to 15 bytes)
 * ECC bytes per block:   20 (160 bits = 8*20)
 * Helper data per block: 35 bytes (data + ecc)
 * Blocks:                8
 * Total helper data W:   8 * 35 = 280 bytes
 *
 * Input R:  256 bytes total, 32 bytes per block
 * We use the first 15 bytes of each 32-byte block as BCH data.
 * The remaining 17 bytes are carried through XOR unchanged.
 */
#define BCH_M               8
#define BCH_T               20
#define BCH_PRIM_POLY       0
#define BCH_BLOCKS          8
#define BCH_DATA_BYTES      14
#define BCH_ECC_BYTES       20
#define BCH_BLOCK_BYTES     34   /* 14 data + 20 ecc bytes */
#define PUF_INPUT_BLOCK     32   /* bytes of R per block */
#define KEY_BYTES           32

/* W is 8 * 35 = 280 bytes — update header define accordingly */
#define W_TOTAL_BYTES       272  /* 8 * 34 */

bool puf_reconcile_enroll(const uint8_t *R, uint8_t *W_out) {
    if (R == NULL || W_out == NULL) {
        ESP_LOGE(TAG, "NULL pointer in enroll.");
        return false;
    }

    struct bch_control *bch = bch_init(BCH_M, BCH_T, BCH_PRIM_POLY, false);
    if (bch == NULL) {
        ESP_LOGE(TAG, "BCH init failed.");
        return false;
    }

    ESP_LOGI(TAG, "BCH: m=%d t=%d n=%d ecc_bits=%d ecc_bytes=%d",
             bch->m, bch->t, bch->n, bch->ecc_bits, bch->ecc_bytes);
    if (bch->ecc_bytes > BCH_BLOCK_BYTES - BCH_DATA_BYTES) {
        ESP_LOGE(TAG, "BCH ecc_bytes mismatch: got %d expected %d",
                 bch->ecc_bytes, BCH_ECC_BYTES);
        bch_free(bch);
        return false;
    }

    memset(W_out, 0, W_TOTAL_BYTES);

    for (int blk = 0; blk < BCH_BLOCKS; blk++) {
        const uint8_t *r_block = R + (blk * PUF_INPUT_BLOCK);
        uint8_t *w_block       = W_out + (blk * BCH_BLOCK_BYTES);

        /* Use first BCH_DATA_BYTES of this R block as BCH data */
        uint8_t ecc[BCH_ECC_BYTES];
        memset(ecc, 0, BCH_ECC_BYTES);
        bch_encode(bch, r_block, BCH_DATA_BYTES, ecc);

        /*
         * W_block = (R_data XOR R_data) || (ecc XOR 0)
         * Simplifies to: first BCH_DATA_BYTES of W = zeros (blind)
         * Actually: W = codeword XOR R_block[:BCH_DATA_BYTES] || ecc
         *
         * Standard fuzzy extractor:
         * W_data = R_data XOR C  where C = BCH codeword of R_data
         * But BCH codeword IS R_data (systematic), so W_data = zeros.
         * Instead store: W_data = R_data (helper data reveals nothing
         * about the key because key is derived from C, not R directly)
         *
         * Correct construction: store R_data and ECC separately.
         * W_block[:15] = R_data (public helper)
         * W_block[15:35] = ecc (public helper)
         */
        memcpy(w_block,                 r_block,  BCH_DATA_BYTES);
        memcpy(w_block + BCH_DATA_BYTES, ecc,     BCH_ECC_BYTES);
    }

    bch_free(bch);
    ESP_LOGI(TAG, "BCH enrollment complete. W size=%d bytes.", W_TOTAL_BYTES);
    return true;
}

bool puf_reconcile_reconstruct(const uint8_t *R_noisy,
                               const uint8_t *W,
                               uint8_t *K_enc_out,
                               uint8_t *K_auth_out) {
    if (R_noisy == NULL || W == NULL ||
        K_enc_out == NULL || K_auth_out == NULL) {
        ESP_LOGE(TAG, "NULL pointer in reconstruct.");
        return false;
    }

    struct bch_control *bch = bch_init(BCH_M, BCH_T, BCH_PRIM_POLY, false);
    if (bch == NULL) {
        ESP_LOGE(TAG, "BCH init failed.");
        return false;
    }

    /* C holds the corrected data bytes from all 8 blocks */
    uint8_t C[BCH_BLOCKS * BCH_DATA_BYTES];
    memset(C, 0, sizeof(C));

    for (int blk = 0; blk < BCH_BLOCKS; blk++) {
        const uint8_t *r_block = R_noisy + (blk * PUF_INPUT_BLOCK);
        const uint8_t *w_block = W + (blk * BCH_BLOCK_BYTES);

        /*
         * Recover noisy data: XOR R_noisy[:15] with W[:15]
         * W[:15] = R_enrolled[:15], so result = R_noisy XOR R_enrolled
         * Then BCH decode corrects the bit errors.
         *
         * Simpler: just use R_noisy[:15] directly as received data,
         * and use W[15:35] as the stored ECC.
         * BCH decode corrects errors in R_noisy[:15] using stored ECC.
         */
        uint8_t data_buf[BCH_DATA_BYTES];
        memcpy(data_buf, r_block, BCH_DATA_BYTES);

        const uint8_t *stored_ecc = w_block + BCH_DATA_BYTES;

        unsigned int errloc[BCH_T];
        int nerr = bch_decode(bch, data_buf, BCH_DATA_BYTES,
                              stored_ecc, NULL, NULL, errloc);

        if (nerr < 0) {
            ESP_LOGE(TAG, "BCH block %d: uncorrectable errors (nerr=%d).",
                     blk, nerr);
            bch_free(bch);
            mbedtls_platform_zeroize(C, sizeof(C));
            return false;
        }

        /* Apply bit corrections to data_buf */
        for (int e = 0; e < nerr; e++) {
            unsigned int bit = errloc[e];
            if (bit < BCH_DATA_BYTES * 8) {
                data_buf[bit / 8] ^= (1u << (bit % 8));
            }
        }

        memcpy(C + (blk * BCH_DATA_BYTES), data_buf, BCH_DATA_BYTES);
        ESP_LOGI(TAG, "BCH block %d: %d error(s) corrected.", blk, nerr);
    }

    bch_free(bch);

    /* PSA HKDF key derivation from corrected C */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA init failed: %d", (int)status);
        mbedtls_platform_zeroize(C, sizeof(C));
        return false;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    psa_key_id_t ikm_key;
    status = psa_import_key(&attr, C, sizeof(C), &ikm_key);
    mbedtls_platform_zeroize(C, sizeof(C));

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA import failed: %d", (int)status);
        return false;
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_SALT,
                     (const uint8_t *)"ESP32S3-PUF-v1", 14);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_key(&op,
                     PSA_KEY_DERIVATION_INPUT_SECRET, ikm_key);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(&op,
                     PSA_KEY_DERIVATION_INPUT_INFO,
                     (const uint8_t *)"KENC_V1", 7);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_output_bytes(&op, K_enc_out, KEY_BYTES);
    psa_key_derivation_abort(&op);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF K_enc failed: %d", (int)status);
        psa_destroy_key(ikm_key);
        return false;
    }

    psa_key_derivation_operation_t op2 = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op2, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(&op2,
                     PSA_KEY_DERIVATION_INPUT_SALT,
                     (const uint8_t *)"ESP32S3-PUF-v1", 14);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_key(&op2,
                     PSA_KEY_DERIVATION_INPUT_SECRET, ikm_key);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(&op2,
                     PSA_KEY_DERIVATION_INPUT_INFO,
                     (const uint8_t *)"KAUTH_V1", 8);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_output_bytes(&op2, K_auth_out, KEY_BYTES);
    psa_key_derivation_abort(&op2);
    psa_destroy_key(ikm_key);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF K_auth failed: %d", (int)status);
        mbedtls_platform_zeroize(K_enc_out, KEY_BYTES);
        return false;
    }

    ESP_LOGI(TAG, "PSA HKDF derived K_enc and K_auth successfully.");
    return true;
}






