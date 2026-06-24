#include "puf_attest.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "psa/crypto.h"
#include "mbedtls/platform_util.h"
#include "qcbor/qcbor_encode.h"
#include <string.h>

static const char *TAG = "PUF_ATTEST";

static bool build_protected(uint8_t *buf, size_t buf_sz, UsefulBufC *out) {
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, (UsefulBuf){buf, buf_sz});
    QCBOREncode_OpenMap(&ctx);
    QCBOREncode_AddInt64ToMapN(&ctx, 1, 5);
    QCBOREncode_CloseMap(&ctx);
    return QCBOREncode_Finish(&ctx, out) == QCBOR_SUCCESS;
}

static bool build_payload(uint8_t *buf, size_t buf_sz,
                          const uint8_t *nonce, UsefulBufC *out) {
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, (UsefulBuf){buf, buf_sz});
    QCBOREncode_OpenMap(&ctx);
    QCBOREncode_AddTextToMapN(&ctx, 1,
        UsefulBuf_FROM_SZ_LITERAL("esp32s3-puf-v1"));
    QCBOREncode_AddUInt64ToMapN(&ctx, 6,
        (uint64_t)(esp_timer_get_time() / 1000));
    QCBOREncode_AddBytesToMapN(&ctx, -1,
        (UsefulBufC){nonce, PUF_ATTEST_NONCE_BYTES});
    QCBOREncode_CloseMap(&ctx);
    return QCBOREncode_Finish(&ctx, out) == QCBOR_SUCCESS;
}

static bool build_mac_structure(uint8_t *buf, size_t buf_sz,
                                UsefulBufC prot, UsefulBufC payload,
                                UsefulBufC *out) {
    static const uint8_t empty[1] = {0};
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, (UsefulBuf){buf, buf_sz});
    QCBOREncode_OpenArray(&ctx);
    QCBOREncode_AddText(&ctx, UsefulBuf_FROM_SZ_LITERAL("MAC0"));
    QCBOREncode_AddBytes(&ctx, prot);
    QCBOREncode_AddBytes(&ctx, (UsefulBufC){empty, 0});
    QCBOREncode_AddBytes(&ctx, payload);
    QCBOREncode_CloseArray(&ctx);
    return QCBOREncode_Finish(&ctx, out) == QCBOR_SUCCESS;
}

bool puf_attest_build(const uint8_t *K_auth,
                      const uint8_t *nonce,
                      uint8_t *token_out,
                      size_t *token_len) {
    if (!K_auth || !nonce || !token_out || !token_len) return false;

    uint8_t prot_buf[16], payload_buf[96], mac_struct_buf[160];
    uint8_t mac[PUF_ATTEST_TAG_BYTES];
    UsefulBufC prot, payload, mac_structure;

    if (!build_protected(prot_buf, sizeof(prot_buf), &prot)) {
        ESP_LOGE(TAG, "Protected header encoding failed."); return false;
    }
    if (!build_payload(payload_buf, sizeof(payload_buf), nonce, &payload)) {
        ESP_LOGE(TAG, "Payload encoding failed."); return false;
    }
    if (!build_mac_structure(mac_struct_buf, sizeof(mac_struct_buf),
                             prot, payload, &mac_structure)) {
        ESP_LOGE(TAG, "MAC_structure encoding failed."); return false;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_key_id_t key_id;
    psa_status_t s = psa_import_key(&attr, K_auth, 32, &key_id);
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Key import failed: %d", (int)s); return false;
    }

    size_t mac_len = 0;
    s = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        mac_structure.ptr, mac_structure.len,
                        mac, sizeof(mac), &mac_len);
    psa_destroy_key(key_id);
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "MAC compute failed: %d", (int)s);
        mbedtls_platform_zeroize(mac, sizeof(mac)); return false;
    }

    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, (UsefulBuf){token_out, *token_len});
    QCBOREncode_OpenArray(&ctx);
    QCBOREncode_AddBytes(&ctx, prot);
    QCBOREncode_OpenMap(&ctx);
    QCBOREncode_CloseMap(&ctx);
    QCBOREncode_AddBytes(&ctx, payload);
    QCBOREncode_AddBytes(&ctx, (UsefulBufC){mac, mac_len});
    QCBOREncode_CloseArray(&ctx);

    UsefulBufC encoded;
    QCBORError qerr = QCBOREncode_Finish(&ctx, &encoded);
    mbedtls_platform_zeroize(mac, sizeof(mac));
    if (qerr != QCBOR_SUCCESS) {
        ESP_LOGE(TAG, "COSE_Mac0 assembly failed: %d", (int)qerr); return false;
    }

    *token_len = encoded.len;
    ESP_LOGI(TAG, "CWT token built (%d bytes).", (int)*token_len);
    return true;
}
