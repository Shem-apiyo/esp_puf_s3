idf_component_register(SRCS "main.c"
                            "capture/puf_capture.c"
                            "integrity/puf_integrity.c"
                            "reconcile/puf_reconcile.c"
                            "reconcile/bch.c"
                       INCLUDE_DIRS "."
                                    "capture"
                                    "integrity"
                                    "reconcile"
                       REQUIRES efuse
                                esp_hw_support
                                esp_security
                                nvs_flash
                                mbedtls)
