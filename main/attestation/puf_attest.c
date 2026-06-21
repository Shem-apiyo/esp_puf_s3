#include "puf_attest.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "psa/crypto.h"
#include "mbedtls/platform_util.h"
#include <string.h>

static const char *TAG = "PUF_ATTEST";

/* ---------- minimal CBOR helpers ---------- */

static uint8_t *cbor_uint8(uint8_t *p, uint8_t v) {
    *p++ = 0x00 | 24; *p++ = v; return p;
}
static uint8_t *cbor_uint32(uint8_t *p, uint32_t v) {
    *p++ = 0x1a;
    *p++ = (v >> 24) & 0xff; *p++ = (v >> 16) & 0xff;
    *p++ = (v >>  8) & 0xff; *p++ =  v        & 0xff;
    return p;
}
static uint8_t *cbor_negint(uint8_t *p, uint8_t n) {
    /* negative integer: -1 = 0x20, -2 = 0x21 ... */
    *p++ = 0x20 | n; return p;
}
static uint8_t *cbor_tstr(uint8_t *p, const char *s) {
    size_t len = strlen(s);
    *p++ = 0x60 | (uint8_t)len;
    memcpy(p, s, len); return p + len;
}
static uint8_t *cbor_bstr_hdr(uint8_t *p, size_t len) {
    if (len <= 23) { *p++ = 0x40 | (uint8_t)len; }
    else           { *p++ = 0x58; *p++ = (uint8_t)len; }
    return p;
}
static uint8_t *cbor_map_hdr(uint8_t *p, uint8_t n) {
    *p++ = 0xa0 | n; return p;
}
static uint8_t *cbor_array_hdr(uint8_t *p, uint8_t n) {
    *p++ = 0x80 | n; return p;
}

/* ---------- token builder ---------- */

bool puf_attest_build(const uint8_t *K_auth,
                      const uint8_t *nonce,
                      uint8_t *token_out,
                      size_t *token_len) {
    if (!K_auth || !nonce || !token_out || !token_len) return false;

    /* --- Build protected header: {1: 5} (alg: HMAC-SHA256) --- */
    uint8_t prot[4];
    uint8_t *pp = prot;
    pp = cbor_map_hdr(pp, 1);
    *pp++ = 0x01;          /* key 1 (alg) */
    *pp++ = 0x05;          /* value 5 (HMAC-SHA256) */
    size_t prot_len = pp - prot;

    /* --- Build payload: CWT claims map --- */
    uint8_t payload[96];
    uint8_t *pl = payload;
    pl = cbor_map_hdr(pl, 3);          /* 3 claims */
    *pl++ = 0x01;                       /* key 1 (iss) */
    pl = cbor_tstr(pl, "esp32s3-puf-v1");
    *pl++ = 0x06;                       /* key 6 (iat) */
    pl = cbor_uint32(pl, (uint32_t)(esp_timer_get_time() / 1000));
    pl = cbor_negint(pl, 0);            /* key -1 (nonce) */
    pl = cbor_bstr_hdr(pl, PUF_ATTEST_NONCE_BYTES);
    memcpy(pl, nonce, PUF_ATTEST_NONCE_BYTES);
    pl += PUF_ATTEST_NONCE_BYTES;
    size_t payload_len = pl - payload;

    /* --- Compute MAC over Enc_structure (COSE AAD) --- */
    /*
     * MAC_structure = ["MAC0", protected_bstr, external_aad, payload]
     * external_aad = h'' (empty)
     * We MAC over: protected_bstr || payload
     * Simplified Enc_structure for COSE_Mac0.
     */
    uint8_t aad[8 + sizeof(prot) + sizeof(payload)];
    uint8_t *ap = aad;
    ap = cbor_array_hdr(ap, 4);
    /* "MAC0" text string */
    *ap++ = 0x64; memcpy(ap, "MAC0", 4); ap += 4;
    /* protected header as bstr */
    ap = cbor_bstr_hdr(ap, prot_len);
    memcpy(ap, prot, prot_len); ap += prot_len;
    /* external_aad: empty bstr */
    *ap++ = 0x40;
    /* payload */
    ap = cbor_bstr_hdr(ap, payload_len);
    memcpy(ap, payload, payload_len); ap += payload_len;
    size_t aad_len = ap - aad;

    /* --- PSA HMAC-SHA256 --- */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_key_id_t key_id;
    psa_status_t s = psa_import_key(&attr, K_auth, 32, &key_id);
    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Key import failed: %d", (int)s);
        return false;
    }

    uint8_t mac[PUF_ATTEST_TAG_BYTES];
    size_t mac_len = 0;
    s = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        aad, aad_len, mac, sizeof(mac), &mac_len);
    psa_destroy_key(key_id);

    if (s != PSA_SUCCESS) {
        ESP_LOGE(TAG, "MAC compute failed: %d", (int)s);
        return false;
    }

    /* --- Assemble COSE_Mac0 array --- */
    uint8_t *tp = token_out;
    tp = cbor_array_hdr(tp, 4);
    /* protected */
    tp = cbor_bstr_hdr(tp, prot_len);
    memcpy(tp, prot, prot_len); tp += prot_len;
    /* unprotected: empty map */
    *tp++ = 0xa0;
    /* payload */
    tp = cbor_bstr_hdr(tp, payload_len);
    memcpy(tp, payload, payload_len); tp += payload_len;
    /* tag */
    tp = cbor_bstr_hdr(tp, mac_len);
    memcpy(tp, mac, mac_len); tp += mac_len;

    *token_len = tp - token_out;

    mbedtls_platform_zeroize(mac, sizeof(mac));
    ESP_LOGI(TAG, "CWT token built (%d bytes).", (int)*token_len);
    return true;
}