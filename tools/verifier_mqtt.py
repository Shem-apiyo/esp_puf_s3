#!/usr/bin/env python3
import argparse, os, hmac, hashlib, struct, time, json
from datetime import datetime
import paho.mqtt.client as mqtt

TRANSACTION_LOG = "transactions.jsonl"

def cbor_decode(data, pos):
    b = data[pos]; major = b >> 5; info = b & 0x1f; pos += 1
    if info <= 23: val = info
    elif info == 24: val = data[pos]; pos += 1
    elif info == 25: val = struct.unpack_from(">H", data, pos)[0]; pos += 2
    elif info == 26: val = struct.unpack_from(">I", data, pos)[0]; pos += 4
    else: val = None
    if major == 0: return val, pos
    elif major == 1: return -1 - val, pos
    elif major == 2: return data[pos:pos+val], pos+val
    elif major == 3: return data[pos:pos+val].decode(), pos+val
    elif major == 4:
        items = []
        for _ in range(val): item, pos = cbor_decode(data, pos); items.append(item)
        return items, pos
    elif major == 5:
        m = {}
        for _ in range(val):
            k, pos = cbor_decode(data, pos); v, pos = cbor_decode(data, pos); m[k] = v
        return m, pos
    raise ValueError(f"Unsupported major {major}")

def verify_cose_mac0(token_bytes, k_auth, nonce_sent):
    token, _ = cbor_decode(token_bytes, 0)
    if not isinstance(token, list) or len(token) != 4:
        print("[FAIL] Not a valid COSE_Mac0"); return None
    prot_bstr, _, payload_bstr, tag_bstr = token
    def cbor_bstr(b):
        return (bytes([0x40 | len(b)]) + b) if len(b) <= 23 else (bytes([0x58, len(b)]) + b)
    mac_structure = (bytes([0x84]) + bytes([0x64]) + b"MAC0" +
                     cbor_bstr(prot_bstr) + bytes([0x40]) + cbor_bstr(payload_bstr))
    expected = hmac.new(k_auth, mac_structure, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, bytes(tag_bstr)):
        print("[FAIL] MAC verification failed"); return None
    claims, _ = cbor_decode(payload_bstr, 0)
    print(f"  issuer:    {claims.get(1)}")
    print(f"  iat (ms):  {claims.get(6)}")
    nonce_tok = claims.get(-1)
    if not isinstance(nonce_tok, (bytes, bytearray)):
        print("[FAIL] Nonce missing"); return None
    if not hmac.compare_digest(bytes(nonce_tok), nonce_sent):
        print("[FAIL] Nonce mismatch"); return None
    print("[PASS] Token authentic. Nonce verified. No replay.")
    return {"issuer": claims.get(1), "iat_ms": claims.get(6)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--key",    required=True)
    args = parser.parse_args()
    k_auth = bytes.fromhex(args.key)
    nonce  = os.urandom(32)
    state  = {"done": False}
    topic_ready     = f"puf/{args.device}/ready"
    topic_challenge = f"puf/{args.device}/challenge"
    topic_token     = f"puf/{args.device}/token"
    topic_result    = f"puf/{args.device}/result"
    print(f"[*] Broker: {args.broker}  Device: {args.device}")
    print(f"[*] Nonce:  {nonce.hex()}")
    print(f"[*] Waiting for device on {topic_ready} ...")

    def on_connect(client, userdata, flags, rc, properties=None):
        print(f"[*] Connected (rc={rc})")
        client.subscribe(topic_ready); client.subscribe(topic_token)

    def on_message(client, userdata, msg):
        if msg.topic == topic_ready:
            print(f"[*] Device ready. Sending nonce...")
            client.publish(topic_challenge, nonce.hex(), qos=1)
        elif msg.topic == topic_token:
            payload = msg.payload.decode().strip()
            print(f"[*] Token received ({len(payload)//2} bytes). Verifying...")
            result = verify_cose_mac0(bytes.fromhex(payload), k_auth, nonce)
            verdict = "PASS" if result else "FAIL"
            client.publish(topic_result, verdict, qos=1)
            if result:
                entry = {"timestamp": datetime.utcnow().isoformat()+"Z",
                         "device": args.device, "issuer": result["issuer"], "pass": True}
                with open(TRANSACTION_LOG, "a") as f: f.write(json.dumps(entry)+"\n")
                print(f"[LOG] {TRANSACTION_LOG}")
            state["done"] = True

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    try: client.connect(args.broker, 1883, 60)
    except Exception as e: print(f"[FAIL] {e}"); return
    client.loop_start()
    timeout = 120
    while not state["done"] and timeout > 0: time.sleep(1); timeout -= 1
    if not state["done"]: print("[FAIL] Timeout.")
    client.loop_stop(); client.disconnect()

if __name__ == "__main__":
    main()
