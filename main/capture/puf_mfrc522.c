#include "puf_mfrc522.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "MFRC522";

#define PIN_RST   9
#define PIN_CS    10
#define PIN_MOSI  11
#define PIN_SCK   12
#define PIN_MISO  13

#define REG_CommandReg     0x01
#define REG_CommIEnReg     0x02
#define REG_CommIrqReg     0x04
#define REG_ErrorReg       0x06
#define REG_FIFODataReg    0x09
#define REG_FIFOLevelReg   0x0A
#define REG_BitFramingReg  0x0D
#define REG_ModeReg        0x11
#define REG_TxControlReg   0x14
#define REG_TxASKReg       0x15
#define REG_RFCfgReg       0x26
#define REG_TModeReg       0x2A
#define REG_TPrescalerReg  0x2B
#define REG_TReloadRegH    0x2C
#define REG_TReloadRegL    0x2D
#define REG_VersionReg     0x37

#define CMD_IDLE           0x00
#define CMD_TRANSCEIVE     0x0C
#define CMD_SOFTRESET      0x0F

#define PICC_REQIDL        0x26
#define PICC_ANTICOLL1     0x93
#define PICC_ANTICOLL_NVB  0x20

static spi_device_handle_t s_spi = NULL;

static void reg_write(uint8_t addr, uint8_t val) {
    uint8_t tx[2] = {(addr << 1) & 0x7E, val};
    spi_transaction_t t = {.length = 16, .tx_buffer = tx};
    spi_device_transmit(s_spi, &t);
}

static uint8_t reg_read(uint8_t addr) {
    uint8_t tx[2] = {((addr << 1) & 0x7E) | 0x80, 0x00};
    uint8_t rx[2] = {0, 0};
    spi_transaction_t t = {.length = 16, .tx_buffer = tx, .rx_buffer = rx};
    spi_device_transmit(s_spi, &t);
    return rx[1];
}

static void reg_set_bits(uint8_t addr, uint8_t mask) {
    reg_write(addr, reg_read(addr) | mask);
}

static void reg_clear_bits(uint8_t addr, uint8_t mask) {
    reg_write(addr, reg_read(addr) & ~mask);
}

static void mfrc522_reset(void) {
    gpio_set_level(PIN_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(50));
    reg_write(REG_CommandReg, CMD_SOFTRESET);
    vTaskDelay(pdMS_TO_TICKS(50));
}

static void mfrc522_antenna_on(void) {
    uint8_t val = reg_read(REG_TxControlReg);
    if ((val & 0x03) != 0x03)
        reg_write(REG_TxControlReg, val | 0x03);
}

/* Send data via TRANSCEIVE and wait for response */
static bool mfrc522_transceive(uint8_t *tx_data, uint8_t tx_len,
                                uint8_t tx_last_bits,
                                uint8_t *rx_data, uint8_t *rx_len) {
    /* Stop any running command */
    reg_write(REG_CommandReg, CMD_IDLE);

    /* Clear all interrupt flags (Set1=0 ? write 0 to clear) */
    reg_write(REG_CommIrqReg, 0x7F);

    /* Flush FIFO */
    reg_set_bits(REG_FIFOLevelReg, 0x80);

    /* Enable interrupts: RxIRq, IdleIRq, ErrIRq, TimerIRq */
    reg_write(REG_CommIEnReg, 0xF7);

    /* Write TX data to FIFO */
    for (uint8_t i = 0; i < tx_len; i++)
        reg_write(REG_FIFODataReg, tx_data[i]);

    /* Set bit framing */
    reg_write(REG_BitFramingReg, tx_last_bits);

    /* Start TRANSCEIVE and immediately set StartSend */
    reg_write(REG_CommandReg, CMD_TRANSCEIVE);
    reg_set_bits(REG_BitFramingReg, 0x80);

    /* Wait for completion */
    uint8_t irq = 0;
    for (int i = 0; i < 40; i++) {
        irq = reg_read(REG_CommIrqReg);
        if (irq & 0x31) break;   /* RxIRq | IdleIRq | TimerIRq */
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    reg_clear_bits(REG_BitFramingReg, 0x80);

    if (irq & 0x01) return false;  /* TimerIRq = timeout */
    uint8_t err = reg_read(REG_ErrorReg);
    if (err & 0x13) return false;

    uint8_t fifo_len = reg_read(REG_FIFOLevelReg);
    if (rx_len) *rx_len = fifo_len;
    if (rx_data) {
        for (uint8_t i = 0; i < fifo_len && i < 16; i++)
            rx_data[i] = reg_read(REG_FIFODataReg);
    }
    return (fifo_len > 0);
}

static bool picc_request(void) {
    uint8_t cmd = PICC_REQIDL;
    uint8_t rx[4] = {0};
    uint8_t rx_len = 0;
    /* REQA is a 7-bit short frame */
    return mfrc522_transceive(&cmd, 1, 0x07, rx, &rx_len);
}

static bool picc_anticoll(uint8_t uid[4]) {
    uint8_t tx[2] = {PICC_ANTICOLL1, PICC_ANTICOLL_NVB};
    uint8_t rx[8] = {0};
    uint8_t rx_len = 0;
    if (!mfrc522_transceive(tx, 2, 0x00, rx, &rx_len)) return false;
    if (rx_len < 4) return false;
    memcpy(uid, rx, 4);
    return true;
}

bool puf_mfrc522_init(void) {
    gpio_config_t rst_cfg = {
        .pin_bit_mask = (1ULL << PIN_RST),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&rst_cfg);
    gpio_set_level(PIN_RST, 1);

    spi_bus_config_t bus = {
        .mosi_io_num = PIN_MOSI, .miso_io_num = PIN_MISO,
        .sclk_io_num = PIN_SCK, .quadwp_io_num = -1, .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t dev = {
        .mode = 0, .clock_speed_hz = 5 * 1000 * 1000,
        .spics_io_num = PIN_CS, .queue_size = 4,
    };
    ESP_ERROR_CHECK(spi_bus_add_device(SPI2_HOST, &dev, &s_spi));

    mfrc522_reset();

    /* Timer: auto-start, ~25kHz tick */
    reg_write(REG_TModeReg,      0x8D);
    reg_write(REG_TPrescalerReg, 0x3E);
    reg_write(REG_TReloadRegH,   0);
    reg_write(REG_TReloadRegL,   30);

    /* 100% ASK, CRC preset 0x6363 */
    reg_write(REG_TxASKReg, 0x40);
    reg_write(REG_ModeReg,  0x3D);

    /* Maximum antenna gain (48dB) */
    reg_write(REG_RFCfgReg, 0x60);

    mfrc522_antenna_on();

    uint8_t ver = reg_read(REG_VersionReg);
    ESP_LOGI(TAG, "Version register: 0x%02x", ver);

    if (ver == 0x00 || ver == 0xFF) {
        ESP_LOGE(TAG, "Not detected � check wiring.");
        return false;
    }
    ESP_LOGI(TAG, "MFRC522 initialised (gain=48dB).");
    return true;
}

void puf_mfrc522_wait_for_card(uint8_t uid_out[MFRC522_UID_BYTES]) {
    ESP_LOGI(TAG, "Waiting for card...");
    while (true) {
        if (picc_request()) {
            uint8_t uid[4] = {0};
            if (picc_anticoll(uid)) {
                memcpy(uid_out, uid, 4);
                ESP_LOGI(TAG, "Card UID: %02x:%02x:%02x:%02x",
                         uid[0], uid[1], uid[2], uid[3]);
                return;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

