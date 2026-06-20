#include "puf_integrity.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>

static const char *TAG         = "PUF_INTEGRITY";
#define NVS_NAMESPACE           "puf_v2"
#define NVS_KEY_HMAC_TAG        "hmac_tag"

/*
 * BLOCK_KEY4 burned with purpose HMAC_DOWN_ALL.
 * HMAC_KEY4 maps to physical BLOCK8 in ESP-IDF v6.0.
 * Software cannot read this key — peripheral access only.
 */
#define PUF_HMAC_KEY_ID         HMAC_KEY4

/* ---------- internal helpers ---------- */

static bool hmac_compute(const uint8_t *W, uint8_t *tag_out) {
    esp_err_t err = esp_hmac_calculate(PUF_HMAC_KEY_ID,
                                       W,
                                       PUF_HELPER_DATA_BYTES,
                                       tag_out);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HMAC peripheral error: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

static bool nvs_write_tag(const uint8_t *tag) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS open failed: %s", esp_err_to_name(err));
        return false;
    }
    err = nvs_set_blob(h, NVS_KEY_HMAC_TAG, tag, PUF_HMAC_TAG_BYTES);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS write failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

static bool nvs_read_tag(uint8_t *tag_out) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS open failed: %s", esp_err_to_name(err));
        return false;
    }
    size_t len = PUF_HMAC_TAG_BYTES;
    err = nvs_get_blob(h, NVS_KEY_HMAC_TAG, tag_out, &len);
    nvs_close(h);
    if (err != ESP_OK || len != PUF_HMAC_TAG_BYTES) {
        ESP_LOGE(TAG, "NVS read failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

/*
 * Constant-time comparison — prevents timing side-channel on tag verify.
 * Returns 0 if equal, nonzero if different.
 * No early exit on mismatch.
 */
static uint8_t ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

/* ---------- public API ---------- */

bool puf_integrity_enroll(const uint8_t *W) {
    if (W == NULL) {
        ESP_LOGE(TAG, "NULL helper data.");
        return false;
    }

    uint8_t tag[PUF_HMAC_TAG_BYTES] = {0};

    if (!hmac_compute(W, tag)) {
        return false;
    }

    if (!nvs_write_tag(tag)) {
        memset(tag, 0, sizeof(tag));
        return false;
    }

    memset(tag, 0, sizeof(tag));
    ESP_LOGI(TAG, "Enrollment complete. HMAC tag written to NVS.");
    return true;
}

bool puf_integrity_verify(const uint8_t *W) {
    if (W == NULL) {
        ESP_LOGE(TAG, "NULL helper data.");
        return false;
    }

    uint8_t computed[PUF_HMAC_TAG_BYTES] = {0};
    uint8_t stored[PUF_HMAC_TAG_BYTES]   = {0};

    if (!hmac_compute(W, computed)) {
        memset(computed, 0, sizeof(computed));
        return false;
    }

    if (!nvs_read_tag(stored)) {
        memset(computed, 0, sizeof(computed));
        memset(stored,   0, sizeof(stored));
        return false;
    }

    uint8_t diff = ct_memcmp(computed, stored, PUF_HMAC_TAG_BYTES);

    memset(computed, 0, sizeof(computed));
    memset(stored,   0, sizeof(stored));

    if (diff != 0) {
        ESP_LOGE(TAG, "HMAC tag mismatch. Helper data invalid or tampered.");
        return false;
    }

    ESP_LOGI(TAG, "Integrity verified.");
    return true;
}

