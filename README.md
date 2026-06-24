# esp_puf_s3

**Hardware-rooted cryptographic device identity on the ESP32-S3 using Physical Unclonable Functions.**

No static keys. No factory provisioning secrets stored in flash. Device identity is derived at runtime from silicon-level entropy that is unique per chip and cannot be cloned or extracted.

---

## What this is

A three-layer PUF-based identity system implemented on the ESP32-S3 microcontroller using ESP-IDF v6.0. The system reconstructs a stable cryptographic key from hardware entropy, encrypts enrollment data, and produces a standards-based attestation token — entirely from a hardware root of trust, with no plaintext key material at rest.

Targeted at resource-constrained IoT devices where conventional key injection (burned secrets, certificate provisioning) is either operationally fragile or a security liability.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  LAYER 3 — Attestation                                   │
│  COSE_Mac0 CWT token · HMAC-SHA256 · nonce replay guard  │
│  Python verifier · USB Serial JTAG beacon transport      │
├─────────────────────────────────────────────────────────┤
│  LAYER 2 — Key Derivation & Helper Data Security         │
│  PSA HKDF · AES-256-GCM · eFuse HMAC peripheral         │
│  NVS-encrypted helper data W                             │
├─────────────────────────────────────────────────────────┤
│  LAYER 1 — PUF Entropy & Reconstruction                  │
│  RTC slow memory entropy source (0x50000400)             │
│  BCH(255,119,20) × 8 blocks · fuzzy extraction          │
└─────────────────────────────────────────────────────────┘
         Hardware: ESP32-S3 · eFuse key block
```

### Layer 1 — PUF Entropy and Reconstruction

RTC slow memory at `0x50000400` is the entropy source. This region is not initialized by ROM before user code executes, making it a stable SRAM PUF candidate. Eight blocks of BCH(255,119,20) error correction provide fuzzy extraction: the device reconstructs the same key across power cycles and temperature variation without storing the key itself.

| Parameter | Value |
|-----------|-------|
| Entropy source | RTC slow memory `0x50000400` |
| BCH configuration | BCH(255,119,20) × 8 blocks |
| Raw entropy | H_raw = 1,487 bits/device |
| Security entropy | H_sec = 464 bits (post-BCH leakage, 1.5× thermal model) |
| Reconstruction rate | 100% across warm reset and cold boot cycles |

> **Why not SRAM Region B?** ROM writes a `0xA5` fill pattern to `0x3FC98000` before bootloader execution. Any entropy read from that region after ROM runs is contaminated. See the engineering dossier for the full discovery record.

### Layer 2 — Key Derivation and Helper Data Encryption

The reconstructed PUF key feeds into PSA Crypto HKDF (HMAC-SHA256) with purpose-encoded info labels for domain separation. Two keys are derived:

```
K_w    = HKDF(IKM=K_puf, salt=device_id, info="puf_w_encrypt_v1")
K_auth = HKDF(IKM=K_puf, salt=device_id, info="puf_k_auth_v1")
```

BCH helper data `W` is encrypted with `K_w` using AES-256-GCM and stored in NVS. The GCM tag is verified before any reconstruction attempt. The eFuse HMAC peripheral (purpose: `HMAC_UP`) is used to derive `K_puf` without exposing raw eFuse bytes to application code.

> **mbedTLS 4.x note:** `mbedtls_hkdf()` was removed in mbedTLS 4.x. This project uses the PSA Crypto key derivation API (`psa_key_derivation_*`). Any ESP-IDF v6.0+ port must use PSA, not the standalone mbedTLS HKDF functions.

### Layer 3 — Attestation

The device produces a COSE_Mac0 CWT token containing:

- `iss` — issuer claim derived from PUF key hash
- `iat` — RTC timestamp (Unix epoch)
- `nonce` — 16 bytes of TRNG output per token

The MAC is HMAC-SHA256 over the COSE Sig_Structure, keyed with `K_auth`. The device transmits on a 2-second beacon loop over USB Serial JTAG. A Python verifier (`tools/verifier.py`) connects, reads the next frame, verifies MAC, and checks nonce against a replay set.

**Verified result:**
```
[PASS] Token authentic. Nonce verified. No replay.
```

---

## Repository Structure

```
esp_puf_s3/
├── main/
│   ├── puf_entropy.c        # RTC memory read, bootloader_before_init hook
│   ├── puf_bch.c            # BCH(255,119,20) encode/decode, compat shim
│   ├── puf_kdf.c            # PSA HKDF key derivation, domain separation
│   ├── puf_nvs.c            # AES-256-GCM NVS encrypt/decrypt for helper data
│   └── puf_attest.c         # COSE_Mac0 CWT construction, beacon loop
├── tools/
│   └── verifier.py          # Python COSE_Mac0 verifier, nonce replay guard
├── components/
│   └── bch/                 # Linux kernel BCH library port + ESP-IDF shim
├── CMakeLists.txt
└── partitions.csv
```

---

## Build and Flash

**Requirements:** ESP-IDF v6.0, ESP32-S3 board, Python 3.9+

```bash
git clone https://github.com/Shem-apiyo/esp_puf_s3
cd esp_puf_s3
idf.py set-target esp32s3
idf.py build
idf.py -p <PORT> flash monitor
```

**eFuse key burn (required before Layer 2 operates):**

```bash
# Burn HMAC key to eFuse block 3 — HMAC_UP purpose only
# WARNING: this operation is irreversible
espefuse.py --port <PORT> burn_key BLOCK_KEY3 key.bin HMAC_UP
```

> Read the [ESP32-S3 Technical Reference Manual §12](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf) before burning. `HMAC_UP` is required for key derivation. `HMAC_DOWN_ALL` is a different purpose and will permanently misconfigure the device for this use case.

**NVS erase (if re-provisioning):**

```bash
# Get NVS partition offset from partition table first
idf.py partition-table
# Then erase using the correct offset
esptool.py --port <PORT> erase_region <NVS_OFFSET> <NVS_SIZE>
```

**Run verifier:**

```bash
cd tools
pip install pyserial cbor2
python verifier.py --port <PORT>
```

---

## CMakeLists.txt — Critical Ordering Note

`BOOTLOADER_EXTRA_COMPONENT_DIRS` must be declared **before** `project()`. If declared after, CMake does not include the BCH component in the bootloader build stage, and `bootloader_before_init` is silently stripped by the linker. The entropy read then occurs after ROM initialization — defeating the PUF entirely.

```cmake
# CORRECT — before project()
set(BOOTLOADER_EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/components/bch")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp_puf_s3)
```

---

## Implementation Status

| Layer | Component | Status |
|-------|-----------|--------|
| 1 | RTC entropy + BCH(255,119,20) fuzzy extraction | ✅ Complete |
| 2 | PSA HKDF + AES-256-GCM helper data encryption | ✅ Complete |
| 3 | COSE_Mac0 CWT attestation + Python verifier | ✅ Complete |
| 4 | Secure Boot V2 (RSA-3072) | ✅ Complete |
| — | Flash Encryption | 🔲 Planned |

**Secure Boot V2** is enabled and permanent. The bootloader and every app image are signed with an RSA-3072 key. The public key digest is burned into eFuse BLOCK_KEY0. On every boot the ROM verifies the bootloader signature before execution and the bootloader verifies the app signature before loading it. Any unsigned or incorrectly signed image is rejected at boot. JTAG is hardware-disabled as part of the Secure Boot burn sequence.

**Flash Encryption** is not yet enabled. Flash contents are not encrypted at rest. This is the remaining open item before the hardware root of trust is complete.

---

## Known Limitations

**Hand-encoded CBOR.** The COSE_Mac0 structure in `puf_attest.c` is built from raw byte construction, not a validated COSE library. It passes the project verifier. A third-party RFC 8152-compliant verifier may reject tokens with encoding deviations. Replacing this with a validated COSE library is a Phase 2 item.

**Single-device entropy characterisation.** H_raw and H_sec figures are from one device. They are sufficient for BCH parameter selection but are not population statistics. A rigorous characterisation requires multiple devices across voltage and temperature variation.

**Provisioning channel.** K_auth is exported in plaintext over USB Serial JTAG at first boot. This is acceptable on a development bench. It is not acceptable for field deployment, which requires a mutually authenticated encrypted provisioning channel.

---

## Author

**Sammy Shem Apiyo**

[github.com/Shem-apiyo](https://github.com/Shem-apiyo) · shem.apiyo@gmail.com

---

## License

MIT — see `LICENSE`.
