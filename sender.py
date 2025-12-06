# sender.py
import sys
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# ---------- utility functions ----------

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

# ---------- main logic ----------

def load_rsa_public_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def sender_main(sender_name: str,
                receiver_name: str,
                message_file: str,
                output_file: str = "Transmitted_Data.json") -> None:
    # 1) Load receiver's public RSA key
    receiver_pub_path = f"{receiver_name}_public.pem"
    receiver_pub = load_rsa_public_key(receiver_pub_path)

    # 2) Read plaintext message from file
    with open(message_file, "r", encoding="utf-8") as f:
        plaintext = f.read().encode("utf-8")

    # 3) Generate AES key (256-bit) and IV
    aes_key = get_random_bytes(32)   # 32 bytes = 256 bits
    iv = get_random_bytes(16)        # AES block size

    # 4) AES-CBC encrypt plaintext
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad_pkcs7(plaintext, 16))

    # 5) RSA encrypt the AES key with receiver's public key (OAEP)
    cipher_rsa = PKCS1_OAEP.new(receiver_pub)
    enc_key = cipher_rsa.encrypt(aes_key)

    # 6) Compute HMAC-SHA256 over (iv || ciphertext || enc_key) using aes_key
    h = HMAC.new(aes_key, digestmod=SHA256)
    h.update(iv + ciphertext + enc_key)
    mac_tag = h.digest()

    # 7) Pack everything into a JSON file (Base64 for binary data)
    packet = {
        "sender": sender_name,
        "receiver": receiver_name,
        "rsa_scheme": "RSA-2048-OAEP",
        "aes_mode": "AES-256-CBC",
        "mac_algo": "HMAC-SHA256",
        "enc_key": b64e(enc_key),
        "iv": b64e(iv),
        "ciphertext": b64e(ciphertext),
        "mac": b64e(mac_tag),
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(packet, f, indent=2)

    print(f"[Sender] Wrote encrypted data to {output_file}")

if __name__ == "__main__":
    # CLI usage:
    #   python sender.py <sender_name> <receiver_name> <message_file> [output_file]
    if len(sys.argv) < 4:
        print("Usage: python sender.py <sender_name> <receiver_name> <message_file> [output_file]")
        sys.exit(1)

    sender_name = sys.argv[1]
    receiver_name = sys.argv[2]
    message_file = sys.argv[3]
    out_file = sys.argv[4] if len(sys.argv) >= 5 else "Transmitted_Data.json"

    sender_main(sender_name, receiver_name, message_file, out_file)
