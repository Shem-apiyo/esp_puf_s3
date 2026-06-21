#include "puf_kdf.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include <string.h>

static const char *TAG = "PUF_KDF";

#define HMAC_KEY_ID     HMAC_KEY4
#define IKM_LABEL       "PUF_IKM_V1"
#define IKM_LABEL_LEN   10

/*
 * Extract IKM from eFuse peripheral.
 * HMAC-SHA256(eFuse_KEY4, "PUF_IKM_V1") -> 32 bytes
 * This is the single root secret for all derived keys.
 */
static bool puf_derive_ikm(uint8_t ikm[32]) {
    esp_err_t err = esp_hmac_calculate(HMAC_KEY_ID,
                                       (const uint8_t *)IKM_LABEL,
                                       IKM_LABEL_LEN,
                                       ikm);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "IKM extraction failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

/*
 * HKDF-Expand: derives key_len bytes from IKM + domain label.
 * Each unique label produces a cryptographically independent key.
 */
bool puf_hkdf_derive(const char *label, size_t label_len,
                     uint8_t *key_out, size_t key_len) {
    uint8_t ikm[32] = {0};

    if (!puf_derive_ikm(ikm)) {
        return false;
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t s;

    s = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF setup failed: %d", (int)s);
        goto fail;
    }

    s = psa_key_derivation_input_bytes(&op,
            PSA_KEY_DERIVATION_INPUT_SECRET, ikm, 32);
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF secret input failed: %d", (int)s);
        goto fail;
    }

    s = psa_key_derivation_input_bytes(&op,
            PSA_KEY_DERIVATION_INPUT_INFO,
            (const uint8_t *)label, label_len);
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF info input failed: %d", (int)s);
        goto fail;
    }

    s = psa_key_derivation_output_bytes(&op, key_out, key_len);
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF output failed: %d", (int)s);
    }

fail:
    psa_key_derivation_abort(&op);
    memset(ikm, 0, sizeof(ikm));
    return s == PSA_SUCCESS;
}