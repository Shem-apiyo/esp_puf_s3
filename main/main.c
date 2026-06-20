#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "capture/puf_capture.h"
#include "integrity/puf_integrity.h"
#include "reconcile/puf_reconcile.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "ORCHESTRATOR";

#define NVS_NAMESPACE       "puf_v2"
#define NVS_KEY_W           "helper_w"
#define NVS_KEY_ENROLLED    "enrolled"

static bool is_enrolled(void) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    ESP_LOGI(TAG, "is_enrolled: nvs_open err=0x%x", err);
    if (err != ESP_OK) return false;
    uint8_t flag = 0;
    err = nvs_get_u8(h, NVS_KEY_ENROLLED, &flag);
    ESP_LOGI(TAG, "is_enrolled: nvs_get_u8 err=0x%x flag=%d", err, flag);
    nvs_close(h);
    return (err == ESP_OK && flag == 1);
}

static bool nvs_write_W(const uint8_t *W) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return false;
    err = nvs_set_blob(h, NVS_KEY_W, W, PUF_HELPER_DATA_BYTES);
    if (err == ESP_OK) err = nvs_set_u8(h, NVS_KEY_ENROLLED, 1);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return (err == ESP_OK);
}

static bool nvs_read_W(uint8_t *W_out) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return false;
    size_t len = PUF_HELPER_DATA_BYTES;
    err = nvs_get_blob(h, NVS_KEY_W, W_out, &len);
    nvs_close(h);
    return (err == ESP_OK && len == PUF_HELPER_DATA_BYTES);
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    uint8_t R[PUF_RESPONSE_BYTES];
    uint8_t W[PUF_HELPER_DATA_BYTES];
    uint8_t K_enc[PUF_KEY_BYTES];
    uint8_t K_auth[PUF_KEY_BYTES];

    memset(R,      0, sizeof(R));
    memset(W,      0, sizeof(W));
    memset(K_enc,  0, sizeof(K_enc));
    memset(K_auth, 0, sizeof(K_auth));

    if (!puf_capture_sram(R, PUF_RESPONSE_BYTES)) {
        ESP_LOGE(TAG, "PUF capture failed. Halting.");
        goto cleanup;
    }


    if (!is_enrolled()) {
        ESP_LOGI(TAG, "Device not enrolled. Starting enrollment...");

        if (!puf_reconcile_enroll(R, W)) {
            ESP_LOGE(TAG, "BCH enrollment failed.");
            goto cleanup;
        }
        if (!nvs_write_W(W)) {
            ESP_LOGE(TAG, "NVS write failed.");
            goto cleanup;
        }
        if (!puf_integrity_enroll(W)) {
            ESP_LOGE(TAG, "HMAC enrollment failed.");
            goto cleanup;
        }
        ESP_LOGI(TAG, "Enrollment complete. Reboot to reconstruct.");

    } else {
        ESP_LOGI(TAG, "Device enrolled. Starting reconstruction...");

    if (!nvs_read_W(W)) {
            ESP_LOGE(TAG, "NVS read failed.");
            goto cleanup;
        }
        if (!puf_integrity_verify(W)) {
            ESP_LOGE(TAG, "Integrity check failed. System locked.");
            goto cleanup;
        }
        if (!puf_reconcile_reconstruct(R, W, K_enc, K_auth)) {
            ESP_LOGE(TAG, "Reconciliation failed.");
            goto cleanup;
        }
        ESP_LOGI(TAG, "Identity reconstructed. K_enc and K_auth ready.");
    }

cleanup:
    mbedtls_platform_zeroize(R,      sizeof(R));
    mbedtls_platform_zeroize(W,      sizeof(W));
    mbedtls_platform_zeroize(K_enc,  sizeof(K_enc));
    mbedtls_platform_zeroize(K_auth, sizeof(K_auth));
}









