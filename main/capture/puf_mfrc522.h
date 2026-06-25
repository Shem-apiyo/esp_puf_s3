#pragma once
#include <stdint.h>
#include <stdbool.h>

#define MFRC522_UID_BYTES 4

/**
 * Initialise MFRC522 on SPI2.
 * RST=GPIO9, CS=GPIO10, MOSI=GPIO11, SCK=GPIO12, MISO=GPIO13
 * Returns true if chip detected (version reg != 0x00/0xFF).
 */
bool puf_mfrc522_init(void);

/**
 * Block until a card is presented, copy 4-byte UID into uid_out.
 */
void puf_mfrc522_wait_for_card(uint8_t uid_out[MFRC522_UID_BYTES]);
