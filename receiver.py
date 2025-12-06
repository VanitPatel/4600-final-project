import sys
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import HMAC, SHA256

# ---------- utility functions ----------

def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("Empty data, cannot unpad")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding")

    # Basic sanity check: all padding bytes equal pad_len
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-pad_len]

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def load_rsa_private_key(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


# ---------- main logic ----------

def receiver_main(input_file: str = "Transmitted_Data.json",
                  output_file: str = "decrypted_message.txt") -> None:
    # 1) Load receiver's private RSA key
    receiver_priv_path = "receiver_private.pem"
    receiver_priv = load_rsa_private_key(receiver_priv_path)

    # 2) Read the transmitted packet
    with open(input_file, "r", encoding="utf-8") as f:
        packet = json.load(f)

    enc_key = b64d(packet["enc_key"])
    iv = b64d(packet["iv"])
    ciphertext = b64d(packet["ciphertext"])
    mac_tag = b64d(packet["mac"])

    # 3) RSA decrypt the AES key
    cipher_rsa = PKCS1_OAEP.new(receiver_priv)
    aes_key = cipher_rsa.decrypt(enc_key)

    # 4) Verify HMAC-SHA256 over (iv || ciphertext || enc_key)
    h = HMAC.new(aes_key, digestmod=SHA256)
    h.update(iv + ciphertext + enc_key)

    try:
        h.verify(mac_tag)
    except ValueError:
        print("[Receiver] MAC verification FAILED! Data has been tampered with or wrong key used.")
        sys.exit(1)

    print("[Receiver] MAC verification succeeded. Data integrity/authenticity confirmed.")

    # 5) AES-CBC decrypt the ciphertext
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plain = cipher_aes.decrypt(ciphertext)
    plaintext = unpad_pkcs7(padded_plain, 16)

    # 6) Write the recovered message to a file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(plaintext.decode("utf-8"))

    print(f"[Receiver] Decrypted message written to {output_file}")

if __name__ == "__main__":
    
    
    #   python receiver.py [input_file] [output_file]
    in_file = sys.argv[1] if len(sys.argv) >= 2 else "Transmitted_Data.json"
    out_file = sys.argv[2] if len(sys.argv) >= 3 else "decrypted_message.txt"

    receiver_main(in_file, out_file)