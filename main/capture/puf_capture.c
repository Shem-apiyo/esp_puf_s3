#include "puf_capture.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "PUF_CAPTURE";

#define RTC_SLOW_MEM_BASE   ((const uint8_t *)0x50000000)
#define RTC_PUF_OFFSET      0x200
#define PUF_CAPTURE_BYTES   256

bool puf_capture_sram(uint8_t *buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        ESP_LOGE(TAG, "Invalid buffer.");
        return false;
    }

    if (size > PUF_CAPTURE_BYTES) {
        ESP_LOGE(TAG, "Requested %d bytes exceeds capture size %d.",
                 (int)size, PUF_CAPTURE_BYTES);
        return false;
    }

    const uint8_t *rtc_src = RTC_SLOW_MEM_BASE + RTC_PUF_OFFSET;
    memcpy(buffer, rtc_src, size);

    ESP_LOGI(TAG, "PUF entropy read from RTC memory (%d bytes).", (int)size);
    return true;
}

