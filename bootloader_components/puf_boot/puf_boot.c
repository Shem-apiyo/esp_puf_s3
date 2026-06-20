#include <string.h>
#include <stdint.h>
#include "esp_rom_sys.h"

/*
 * PUF_BOOT.C
 * Reads RTC slow memory entropy from offset 0x400.
 * RTC slow memory is NOT initialized by the ROM bootloader.
 * Its power-on state is device-specific and temperature-stable.
 * Stores captured data at offset 0x200 for app-stage retrieval.
 */
#define PUF_CAPTURE_BYTES   256
#define RTC_SLOW_MEM_BASE   ((uint8_t *)0x50000000)
#define RTC_PUF_SRC_OFFSET  0x400
#define RTC_PUF_DST_OFFSET  0x200

void bootloader_before_init(void) {
    const uint8_t *rtc_src = RTC_SLOW_MEM_BASE + RTC_PUF_SRC_OFFSET;
    uint8_t *rtc_dst       = RTC_SLOW_MEM_BASE + RTC_PUF_DST_OFFSET;

    for (size_t i = 0; i < PUF_CAPTURE_BYTES; i++) {
        rtc_dst[i] = rtc_src[i];
    }

    __asm__ volatile ("memw" ::: "memory");
}
