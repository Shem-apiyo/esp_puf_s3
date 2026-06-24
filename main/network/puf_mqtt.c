#include "puf_mqtt.h"
#include "credentials.h"
#include "puf_attest.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "PUF_MQTT";
#define MQTT_CONNECTED_BIT BIT0
#define NONCE_RECEIVED_BIT BIT1

static EventGroupHandle_t       s_mqtt_events;
static esp_mqtt_client_handle_t s_client;
static char s_topic_ready[48];
static char s_topic_challenge[48];
static char s_topic_token[48];
static char s_topic_result[48];
static uint8_t s_nonce[32];

static void mqtt_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "Connected to broker");
            esp_mqtt_client_subscribe(s_client, s_topic_challenge, 1);
            esp_mqtt_client_subscribe(s_client, s_topic_result, 1);
            xEventGroupSetBits(s_mqtt_events, MQTT_CONNECTED_BIT);
            break;
        case MQTT_EVENT_DATA:
            if (event->topic_len > 0 &&
                strncmp(event->topic, s_topic_challenge,
                        (size_t)event->topic_len) == 0) {
                if (event->data_len == 64) {
                    for (int i = 0; i < 32; i++) {
                        char b[3] = {event->data[i*2], event->data[i*2+1], 0};
                        s_nonce[i] = (uint8_t)strtol(b, NULL, 16);
                    }
                    ESP_LOGI(TAG, "Nonce received.");
                    xEventGroupSetBits(s_mqtt_events, NONCE_RECEIVED_BIT);
                }
            }
            if (event->topic_len > 0 &&
                strncmp(event->topic, s_topic_result,
                        (size_t)event->topic_len) == 0) {
                ESP_LOGI(TAG, "Verifier: %.*s", event->data_len, event->data);
            }
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "Disconnected.");
            break;
        default: break;
    }
}

bool puf_mqtt_connect(const char *device_id) {
    s_mqtt_events = xEventGroupCreate();
    snprintf(s_topic_ready,     sizeof(s_topic_ready),     "puf/%s/ready",     device_id);
    snprintf(s_topic_challenge, sizeof(s_topic_challenge), "puf/%s/challenge", device_id);
    snprintf(s_topic_token,     sizeof(s_topic_token),     "puf/%s/token",     device_id);
    snprintf(s_topic_result,    sizeof(s_topic_result),    "puf/%s/result",    device_id);
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker = {
            .address = {
                .hostname  = PUF_MQTT_BROKER_IP,
                .port      = PUF_MQTT_BROKER_PORT,
                .transport = MQTT_TRANSPORT_OVER_TCP,
            },
        },
        .credentials = {
            .client_id = "esp32s3_puf",
        },
    };
    s_client = esp_mqtt_client_init(&mqtt_cfg);
    if (!s_client) return false;
    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID,
                                   mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_client);
    EventBits_t bits = xEventGroupWaitBits(s_mqtt_events, MQTT_CONNECTED_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(10000));
    return (bits & MQTT_CONNECTED_BIT) != 0;
}

bool puf_mqtt_wait_for_nonce(uint8_t *nonce_out) {
    esp_mqtt_client_publish(s_client, s_topic_ready, "1", 1, 1, 0);
    ESP_LOGI(TAG, "Ready published. Waiting for nonce...");
    EventBits_t bits = xEventGroupWaitBits(s_mqtt_events, NONCE_RECEIVED_BIT,
        pdTRUE, pdFALSE, pdMS_TO_TICKS(60000));
    if (bits & NONCE_RECEIVED_BIT) { memcpy(nonce_out, s_nonce, 32); return true; }
    return false;
}

bool puf_mqtt_publish_token(const uint8_t *token, size_t token_len) {
    char hex_buf[PUF_ATTEST_TOKEN_MAX * 2 + 1];
    for (size_t i = 0; i < token_len; i++) {
        snprintf(&hex_buf[i*2], 3, "%02x", token[i]);
    }
    hex_buf[token_len * 2] = '\0';
    int id = esp_mqtt_client_publish(s_client, s_topic_token,
                                     hex_buf, (int)(token_len * 2), 1, 0);
    ESP_LOGI(TAG, "Token published (msg_id=%d).", id);
    return (id >= 0);
}

void puf_mqtt_disconnect(void) {
    esp_mqtt_client_stop(s_client);
    esp_mqtt_client_destroy(s_client);
    s_client = NULL;
}
