#!/usr/bin/env python3
"""
PUF Attestation Verifier
COSE_Mac0 CWT token verifier for ESP32-S3 PUF identity system.

Usage:
    python tools/verifier.py --port COM12 --key <hex-encoded K_auth>

K_auth is obtained once during enrollment and stored securely.
"""

import argparse
import serial
import os
import hmac
import hashlib
import struct
import time

# ── minimal CBOR decoder (only what we need) ──────────────────────

def cbor_decode(data: bytes, pos: int):
    b = data[pos]
    major = b >> 5
    info  = b & 0x1f
    pos  += 1

    if info <= 23:
        val = info
    elif info == 24:
        val = data[pos]; pos += 1
    elif info == 25:
        val = struct.unpack_from('>H', data, pos)[0]; pos += 2
    elif info == 26:
        val = struct.unpack_from('>I', data, pos)[0]; pos += 4
    else:
        val = None

    if major == 0:   # unsigned int
        return val, pos
    elif major == 1: # negative int
        return -1 - val, pos
    elif major == 2: # bstr
        return data[pos:pos+val], pos+val
    elif major == 3: # tstr
        return data[pos:pos+val].decode(), pos+val
    elif major == 4: # array
        items = []
        for _ in range(val):
            item, pos = cbor_decode(data, pos)
            items.append(item)
        return items, pos
    elif major == 5: # map
        m = {}
        for _ in range(val):
            k, pos = cbor_decode(data, pos)
            v, pos = cbor_decode(data, pos)
            m[k] = v
        return m, pos
    else:
        raise ValueError(f"Unsupported CBOR major type {major}")

# ── COSE_Mac0 verifier ─────────────────────────────────────────────

def verify_cose_mac0(token_bytes: bytes, k_auth: bytes, nonce_sent: bytes) -> bool:
    token, _ = cbor_decode(token_bytes, 0)

    if not isinstance(token, list) or len(token) != 4:
        print("[FAIL] Not a valid COSE_Mac0 array")
        return False

    prot_bstr, unprot, payload_bstr, tag_bstr = token

    # Rebuild MAC_structure (same as device)
    # MAC_structure = ["MAC0", protected_bstr, external_aad, payload]
    def cbor_bstr(b):
        if len(b) <= 23:
            return bytes([0x40 | len(b)]) + b
        else:
            return bytes([0x58, len(b)]) + b

    def cbor_tstr(s):
        b = s.encode()
        return bytes([0x60 | len(b)]) + b

    mac_structure = (
        bytes([0x84])          +   # array(4)
        cbor_tstr("MAC0")      +
        cbor_bstr(prot_bstr)   +
        bytes([0x40])          +   # empty bstr (external_aad)
        cbor_bstr(payload_bstr)
    )

    expected_tag = hmac.new(k_auth, mac_structure, hashlib.sha256).digest()

    if not hmac.compare_digest(expected_tag, bytes(tag_bstr)):
        print("[FAIL] MAC verification failed — token tampered or wrong key")
        return False

    # Decode payload claims
    claims, _ = cbor_decode(payload_bstr, 0)
    print(f"  issuer (iss):  {claims.get(1)}")
    print(f"  issued-at(iat): {claims.get(6)} ms")

    nonce_in_token = claims.get(-1)
    if isinstance(nonce_in_token, (bytes, bytearray)):
        if not hmac.compare_digest(bytes(nonce_in_token), nonce_sent):
            print("[FAIL] Nonce mismatch — possible replay attack")
            return False
    else:
        print("[FAIL] Nonce claim missing or wrong type")
        return False

    print("[PASS] Token authentic. Nonce verified. No replay.")
    return True

# ── main ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', required=True)
    parser.add_argument('--key',  required=True)
    args = parser.parse_args()

    k_auth = bytes.fromhex(args.key)
    if len(k_auth) != 32:
        print("ERROR: K_auth must be 32 bytes (64 hex chars)")
        return

    nonce = os.urandom(32)
    print(f"[*] Nonce (hex): {nonce.hex()}")

    # Connect — board is already booted and waiting
    print(f"[*] Connecting to {args.port}...")
    for attempt in range(30):
        try:
            ser = serial.Serial(args.port, 115200, timeout=30)
            print(f"[*] Connected.")
            break
        except Exception as e:
            print(f"    [{e}]")
            time.sleep(1)
    else:
        print("[FAIL] Could not connect.")
        return

    # Drain any pending output
    time.sleep(0.5)
    ser.reset_input_buffer()

    # Send trigger
    ser.write(b'S')
    ser.flush()
    print("[*] Trigger sent. Waiting for ATTEST_READY...")

    # Wait for ATTEST_READY
    while True:
        line = ser.readline().decode(errors='replace').strip()
        if line:
            print(f"    device: {line}")
        if 'ATTEST_READY' in line:
            break

    # Send hex nonce
    ser.write((nonce.hex() + '\n').encode('ascii'))
    ser.flush()
    print(f"[*] Nonce sent.")

    # Wait for token
    token_hex = None
    in_token  = False
    print("[*] Waiting for token...")
    while True:
        line = ser.readline().decode(errors='replace').strip()
        if line:
            print(f"    device: {line}")
        if 'TOKEN_BEGIN' in line:
            in_token = True
            continue
        if in_token and line and not line.startswith('I ('):
            token_hex = line
            continue
        if 'TOKEN_END' in line:
            break

    ser.close()

    if not token_hex:
        print("[FAIL] No token received")
        return

    print(f"[*] Token (hex): {token_hex}")
    token_bytes = bytes.fromhex(token_hex)
    print(f"[*] Token length: {len(token_bytes)} bytes")
    print("[*] Verifying...")
    verify_cose_mac0(token_bytes, k_auth, nonce)

if __name__ == '__main__':
    main()