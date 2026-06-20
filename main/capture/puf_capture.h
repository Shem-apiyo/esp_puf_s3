#ifndef PUF_CAPTURE_H
#define PUF_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PUF_RESPONSE_BYTES  256

/**
 * @brief Reads PUF entropy from RTC slow memory.
 *        Data was captured from Region B (0x3FC98000) by the
 *        bootloader hook before SRAM initialization.
 *
 * @param buffer  Destination buffer, must be >= PUF_RESPONSE_BYTES
 * @param size    Bytes to read, must be <= PUF_RESPONSE_BYTES
 * @return true on success, false on invalid arguments
 */
bool puf_capture_sram(uint8_t *buffer, size_t size);

#endif // PUF_CAPTURE_H
