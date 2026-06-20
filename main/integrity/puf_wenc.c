#include "puf_wenc.h"
#include "puf_integrity.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "mbedtls/platform_util.h"
#include <string.h>

static const char *TAG = "PUF_WENC";

#define HMAC_KEY_ID         HMAC_KEY4
#define WENC_LABEL          "W_ENCRYPT_V1"
#define WENC_LABEL_LEN      12
#define AES_KEY_BYTES       32

/*
 * Derive a 32-byte AES key from the eFuse HMAC peripheral.
 * Uses domain-separated label so this key is distinct from
 * the integrity tag key used in puf_integrity.c.
 */
static bool derive_wenc_key(uint8_t *key_out) {
    esp_err_t err = esp_hmac_calculate(HMAC_KEY_ID,
                                       (const uint8_t *)WENC_LABEL,
                                       WENC_LABEL_LEN,
                                       key_out);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "eFuse HMAC key derivation failed: %s",
                 esp_err_to_name(err));
        return false;
    }
    return true;
}

bool puf_wenc_encrypt(const uint8_t *W_plain, size_t plain_len,
                      uint8_t *out, size_t out_len) {
    if (W_plain == NULL || out == NULL) {
        ESP_LOGE(TAG, "NULL pointer.");
        return false;
    }
    if (out_len < plain_len + PUF_WENC_OVERHEAD) {
        ESP_LOGE(TAG, "Output buffer too small.");
        return false;
    }

    /* Derive AES key from eFuse */
    uint8_t aes_key[AES_KEY_BYTES];
    if (!derive_wenc_key(aes_key)) return false;

    /* Generate random IV */
    uint8_t *iv  = out;
    uint8_t *ct  = out + PUF_WENC_IV_BYTES;
    uint8_t *tag = out + PUF_WENC_IV_BYTES + plain_len;

    psa_status_t status = psa_generate_random(iv, PUF_WENC_IV_BYTES);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "IV generation failed: %d", (int)status);
        mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
        return false;
    }

    /* Import AES key into PSA */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, PUF_WENC_TAG_BYTES));

    psa_key_id_t key_id;
    status = psa_import_key(&attr, aes_key, AES_KEY_BYTES, &key_id);
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA key import failed: %d", (int)status);
        return false;
    }

    /* Encrypt */
    size_t ct_len = 0;
    uint8_t ct_and_tag[plain_len + PUF_WENC_TAG_BYTES];

    status = psa_aead_encrypt(key_id,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, PUF_WENC_TAG_BYTES),
        iv, PUF_WENC_IV_BYTES,
        NULL, 0,
        W_plain, plain_len,
        ct_and_tag, sizeof(ct_and_tag), &ct_len);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "AES-GCM encrypt failed: %d", (int)status);
        mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));
        return false;
    }

    /* PSA appends tag to ciphertext — split them */
    memcpy(ct,  ct_and_tag,             plain_len);
    memcpy(tag, ct_and_tag + plain_len, PUF_WENC_TAG_BYTES);
    mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));

    ESP_LOGI(TAG, "W encrypted successfully (%d bytes plaintext).",
             (int)plain_len);
    return true;
}

bool puf_wenc_decrypt(const uint8_t *in, size_t in_len,
                      uint8_t *W_plain, size_t plain_len) {
    if (in == NULL || W_plain == NULL) {
        ESP_LOGE(TAG, "NULL pointer.");
        return false;
    }
    if (in_len < PUF_WENC_OVERHEAD) {
        ESP_LOGE(TAG, "Input too short.");
        return false;
    }

    size_t ct_len = in_len - PUF_WENC_OVERHEAD;
    if (plain_len < ct_len) {
        ESP_LOGE(TAG, "Output buffer too small.");
        return false;
    }

    const uint8_t *iv  = in;
    const uint8_t *ct  = in + PUF_WENC_IV_BYTES;
    const uint8_t *tag = in + PUF_WENC_IV_BYTES + ct_len;

    /* Reassemble ciphertext+tag for PSA */
    uint8_t ct_and_tag[ct_len + PUF_WENC_TAG_BYTES];
    memcpy(ct_and_tag,           ct,  ct_len);
    memcpy(ct_and_tag + ct_len,  tag, PUF_WENC_TAG_BYTES);

    /* Derive AES key from eFuse */
    uint8_t aes_key[AES_KEY_BYTES];
    if (!derive_wenc_key(aes_key)) {
        mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));
        return false;
    }

    /* Import AES key */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, PUF_WENC_TAG_BYTES));

    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attr, aes_key, AES_KEY_BYTES,
                                         &key_id);
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA key import failed: %d", (int)status);
        mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));
        return false;
    }

    /* Decrypt + verify tag */
    size_t out_len = 0;
    status = psa_aead_decrypt(key_id,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, PUF_WENC_TAG_BYTES),
        iv, PUF_WENC_IV_BYTES,
        NULL, 0,
        ct_and_tag, sizeof(ct_and_tag),
        W_plain, plain_len, &out_len);

    psa_destroy_key(key_id);
    mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "AES-GCM decrypt/verify failed: %d — W tampered or wrong key.", (int)status);
        mbedtls_platform_zeroize(W_plain, plain_len);
        return false;
    }

    ESP_LOGI(TAG, "W decrypted and authenticated successfully.");
    return true;
}
