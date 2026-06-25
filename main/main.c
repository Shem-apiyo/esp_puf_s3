#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "capture/puf_capture.h"
#include "capture/puf_mfrc522.h"
#include "integrity/puf_integrity.h"
#include "reconcile/puf_reconcile.h"
#include "integrity/puf_wenc.h"
#include "attestation/puf_attest.h"
#include "mbedtls/platform_util.h"
#include "network/puf_wifi.h"
#include "network/puf_mqtt.h"

static const char *TAG = "ORCHESTRATOR";

#define NVS_NAMESPACE    "puf_v2"
#define NVS_KEY_W        "helper_w"
#define NVS_KEY_ENROLLED "enrolled"

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
    uint8_t enc_buf[PUF_HELPER_DATA_BYTES + PUF_WENC_OVERHEAD];
    if (!puf_wenc_encrypt(W, PUF_HELPER_DATA_BYTES,
                          enc_buf, sizeof(enc_buf))) {
        ESP_LOGE(TAG, "W encryption failed.");
        return false;
    }
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return false;
    err = nvs_set_blob(h, NVS_KEY_W, enc_buf, sizeof(enc_buf));
    if (err == ESP_OK) err = nvs_set_u8(h, NVS_KEY_ENROLLED, 1);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    mbedtls_platform_zeroize(enc_buf, sizeof(enc_buf));
    return (err == ESP_OK);
}

static bool nvs_read_W(uint8_t *W_out) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return false;
    uint8_t enc_buf[PUF_HELPER_DATA_BYTES + PUF_WENC_OVERHEAD];
    size_t len = sizeof(enc_buf);
    err = nvs_get_blob(h, NVS_KEY_W, enc_buf, &len);
    nvs_close(h);
    if (err != ESP_OK || len != sizeof(enc_buf)) return false;
    bool ok = puf_wenc_decrypt(enc_buf, len, W_out, PUF_HELPER_DATA_BYTES);
    mbedtls_platform_zeroize(enc_buf, sizeof(enc_buf));
    return ok;
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "FATAL: NVS init failed (0x%x). System locked.", ret);
        while (1) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    /* Initialise MFRC522 early — halt if not detected */
    if (!puf_mfrc522_init()) {
        ESP_LOGE(TAG, "MFRC522 not detected. Check wiring. Halting.");
        while (1) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    uint8_t R[PUF_RESPONSE_BYTES];
    uint8_t W[PUF_HELPER_DATA_BYTES];
    uint8_t K_enc[PUF_KEY_BYTES];
    uint8_t K_auth[PUF_KEY_BYTES];
    uint8_t card_uid[MFRC522_UID_BYTES];

    memset(R,        0, sizeof(R));
    memset(W,        0, sizeof(W));
    memset(K_enc,    0, sizeof(K_enc));
    memset(K_auth,   0, sizeof(K_auth));
    memset(card_uid, 0, sizeof(card_uid));

    if (!puf_capture_sram(R, PUF_RESPONSE_BYTES)) {
        ESP_LOGE(TAG, "PUF capture failed. Halting.");
        goto cleanup;
    }

    if (!is_enrolled()) {
        ESP_LOGI("INTER_DEVICE", "R[0..15]: %02x %02x %02x %02x %02x %02x %02x %02x "
                 "%02x %02x %02x %02x %02x %02x %02x %02x",
                 R[0],R[1],R[2],R[3],R[4],R[5],R[6],R[7],
                 R[8],R[9],R[10],R[11],R[12],R[13],R[14],R[15]);
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

        /* --- Layer 5: RFID card tap --- */
        ESP_LOGI(TAG, "Present card to authenticate...");
        puf_mfrc522_wait_for_card(card_uid);
        ESP_LOGI(TAG, "Card accepted: %02x:%02x:%02x:%02x",
                 card_uid[0], card_uid[1], card_uid[2], card_uid[3]);

        /* --- Layer 4: WiFi + MQTT transport --- */
        uint8_t nonce[PUF_ATTEST_NONCE_BYTES] = {0};
        uint8_t token[PUF_ATTEST_TOKEN_MAX];
        size_t  token_len = sizeof(token);
        char    device_id[7];

        if (!puf_wifi_connect()) {
            ESP_LOGE(TAG, "WiFi connection failed.");
            goto cleanup;
        }
        puf_wifi_get_device_id(device_id);
        ESP_LOGI(TAG, "Device ID: %s", device_id);

        if (!puf_mqtt_connect(device_id)) {
            ESP_LOGE(TAG, "MQTT connection failed.");
            goto cleanup;
        }

        if (!puf_mqtt_wait_for_nonce(nonce)) {
            ESP_LOGE(TAG, "Nonce timeout.");
            puf_mqtt_disconnect();
            goto cleanup;
        }

        if (!puf_attest_build(K_auth, nonce, token, &token_len)) {
            ESP_LOGE(TAG, "Attestation failed.");
            puf_mqtt_disconnect();
            goto cleanup;
        }

        puf_mqtt_publish_token(token, token_len);
        vTaskDelay(pdMS_TO_TICKS(2000));
        puf_mqtt_disconnect();

        mbedtls_platform_zeroize(token, sizeof(token));
        mbedtls_platform_zeroize(nonce, sizeof(nonce));
    }

cleanup:
    mbedtls_platform_zeroize(R,      sizeof(R));
    mbedtls_platform_zeroize(W,      sizeof(W));
    mbedtls_platform_zeroize(K_enc,  sizeof(K_enc));
    mbedtls_platform_zeroize(K_auth, sizeof(K_auth));
}
