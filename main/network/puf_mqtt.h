#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
bool puf_mqtt_connect(const char *device_id);
bool puf_mqtt_wait_for_nonce(uint8_t *nonce_out);
bool puf_mqtt_publish_token(const uint8_t *token, size_t token_len);
void puf_mqtt_disconnect(void);
