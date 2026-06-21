idf_component_register(SRCS "main.c"
                            "capture/puf_capture.c"
                            "integrity/puf_integrity.c"
                            "integrity/puf_wenc.c"
                            "kdf/puf_kdf.c"
                            "reconcile/puf_reconcile.c"
                            "reconcile/bch.c"
                       INCLUDE_DIRS "."
                                    "capture"
                                    "integrity"
                                    "kdf"
                                    "reconcile"
                       REQUIRES efuse
                                esp_hw_support
                                esp_security
                                nvs_flash
                                mbedtls)
