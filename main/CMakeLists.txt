idf_component_register(SRCS "main.c"
                            "capture/puf_capture.c"
                            "integrity/puf_integrity.c"
                            "integrity/puf_wenc.c"
                            "kdf/puf_kdf.c"
                            "attestation/puf_attest.c"
                            "reconcile/puf_reconcile.c"
                            "reconcile/bch.c"
                            "network/puf_wifi.c"
                            "network/puf_mqtt.c"
                       INCLUDE_DIRS "."
                                    "capture"
                                    "integrity"
                                    "kdf"
                                    "attestation"
                                    "reconcile"
                                    "network"
                       REQUIRES efuse
                                esp_hw_support
                                esp_security
                                esp_timer
                                nvs_flash
                                mbedtls
                                qcbor
                                esp_wifi
                                esp_netif
                                esp_event
                                esp-mqtt
                                esp_driver_gpio)
