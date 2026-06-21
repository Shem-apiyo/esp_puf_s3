#include "puf_wenc.h"
#include "puf_integrity.h"
#include "../kdf/puf_kdf.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "mbedtls/platform_util.h"
#include <string.h>

static const char *TAG = "PUF_WENC";

#define WENC_LABEL      "W_ENCRYPT_V1"
#define WENC_LABEL_LEN  12
#define AES_KEY_BYTES   32

bool puf_wenc_encrypt(const uint8_t *W_plain, size_t plain_len,
                      uint8_t *out, size_t out_len) {
    if (W_plain == NULL || out == NULL) return false;
    if (out_len < plain_len + PUF_WENC_OVERHEAD) {
        ESP_LOGE(TAG, "Output buffer too small.");
        return false;
    }

    uint8_t aes_key[AES_KEY_BYTES] = {0};
    if (!puf_hkdf_derive(WENC_LABEL, WENC_LABEL_LEN, aes_key, AES_KEY_BYTES)) {
        ESP_LOGE(TAG, "Key derivation failed.");
        return false;
    }

    uint8_t *iv  = out;
    uint8_t *ct  = out + PUF_WENC_IV_BYTES;
    uint8_t *tag = out + PUF_WENC_IV_BYTES + plain_len;

    psa_status_t status = psa_generate_random(iv, PUF_WENC_IV_BYTES);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "IV generation failed: %d", (int)status);
        mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
        return false;
    }

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

    uint8_t ct_and_tag[plain_len + PUF_WENC_TAG_BYTES];
    size_t ct_len = 0;
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

    memcpy(ct,  ct_and_tag,             plain_len);
    memcpy(tag, ct_and_tag + plain_len, PUF_WENC_TAG_BYTES);
    mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));

    ESP_LOGI(TAG, "W encrypted successfully (%d bytes).", (int)plain_len);
    return true;
}

bool puf_wenc_decrypt(const uint8_t *in, size_t in_len,
                      uint8_t *W_plain, size_t plain_len) {
    if (in == NULL || W_plain == NULL) return false;
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

    uint8_t ct_and_tag[ct_len + PUF_WENC_TAG_BYTES];
    memcpy(ct_and_tag,          ct,  ct_len);
    memcpy(ct_and_tag + ct_len, tag, PUF_WENC_TAG_BYTES);

    uint8_t aes_key[AES_KEY_BYTES] = {0};
    if (!puf_hkdf_derive(WENC_LABEL, WENC_LABEL_LEN, aes_key, AES_KEY_BYTES)) {
        mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));
        return false;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, PUF_WENC_TAG_BYTES));

    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attr, aes_key, AES_KEY_BYTES, &key_id);
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(ct_and_tag, sizeof(ct_and_tag));
        return false;
    }

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
        ESP_LOGE(TAG, "AES-GCM decrypt failed: %d — tampered or wrong key.", (int)status);
        mbedtls_platform_zeroize(W_plain, plain_len);
        return false;
    }

    ESP_LOGI(TAG, "W decrypted and authenticated successfully.");
    return true;
}