#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "capture/puf_capture.h"
#include "integrity/puf_integrity.h"
#include "reconcile/puf_reconcile.h"
#include "integrity/puf_wenc.h"
#include "attestation/puf_attest.h"
#include "mbedtls/platform_util.h"

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
    /* Fail-closed NVS: Lock down on corruption instead of auto-erasing */
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "FATAL: NVS initialization failed (err: 0x%x). Possible tampering. System locked.", ret);
        while (1) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }

    uint8_t R[PUF_RESPONSE_BYTES];
    uint8_t W[PUF_HELPER_DATA_BYTES];
    uint8_t K_enc[PUF_KEY_BYTES];
    uint8_t K_auth[PUF_KEY_BYTES];

    memset(R,     0, sizeof(R));
    memset(W,     0, sizeof(W));
    memset(K_enc, 0, sizeof(K_enc));
    memset(K_auth,0, sizeof(K_auth));

   
    if (!puf_capture_sram(R, PUF_RESPONSE_BYTES)) {
        ESP_LOGE(TAG, "PUF capture failed. Halting.");
        goto cleanup;
    }

    if (!is_enrolled()) {
         ESP_LOGI("INTER_DEVICE", "R[0..15]: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
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
        
                /* --- Layer 3: COSE_Mac0 attestation --- */
        uint8_t nonce[PUF_ATTEST_NONCE_BYTES] = {0};
        uint8_t token[PUF_ATTEST_TOKEN_MAX];
        size_t  token_len = sizeof(token);

        /* Install USB Serial JTAG driver securely */
        if (!usb_serial_jtag_is_driver_installed()) {
            usb_serial_jtag_driver_config_t usb_cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
            usb_serial_jtag_driver_install(&usb_cfg);
        }

        /* Beacon loop: wait for trigger byte 'S' from verifier */
        {
            uint8_t trigger = 0;
            int wait_cycles = 0;
            while (trigger != 'S') {
                if (wait_cycles % 10 == 0) {
                    ESP_LOGI(TAG, "WAITING_FOR_VERIFIER");
                }
                int got = usb_serial_jtag_read_bytes(&trigger, 1, pdMS_TO_TICKS(100));
                if (got <= 0) trigger = 0;
                wait_cycles++;
            }
        }
        ESP_LOGI(TAG, "ATTEST_READY");

        /* Read 64 hex ASCII chars for nonce */
        char hex_nonce[65] = {0};
        int hi = 0;
        while (hi < 64) {
            uint8_t b = 0;
            int got = usb_serial_jtag_read_bytes(&b, 1, pdMS_TO_TICKS(100));
            if (got <= 0) continue;
            if ((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') ||
                (b >= 'A' && b <= 'F')) {
                hex_nonce[hi++] = (char)b;
            }
        }
        for (int i = 0; i < 32; i++) {
            char byte_str[3] = {hex_nonce[i*2], hex_nonce[i*2+1], 0};
            nonce[i] = (uint8_t)strtol(byte_str, NULL, 16);
        }
        ESP_LOGI(TAG, "Nonce received (32 bytes).");

        if (!puf_attest_build(K_auth, nonce, token, &token_len)) {
            ESP_LOGE(TAG, "Attestation failed.");
            goto cleanup;
        }

        /* Hex-encode and transmit token */
        ESP_LOGI(TAG, "TOKEN_BEGIN");
        for (size_t i = 0; i < token_len; i++) {
            printf("%02x", token[i]);
        }
        printf("\n");
        fflush(stdout);
        ESP_LOGI(TAG, "TOKEN_END");

        mbedtls_platform_zeroize(token, sizeof(token));
        mbedtls_platform_zeroize(nonce, sizeof(nonce));
    }

cleanup:
    mbedtls_platform_zeroize(R,     sizeof(R));
    mbedtls_platform_zeroize(W,     sizeof(W));
    mbedtls_platform_zeroize(K_enc, sizeof(K_enc));
    mbedtls_platform_zeroize(K_auth,sizeof(K_auth));
}
