# keygen.py
from Crypto.PublicKey import RSA

def generate_rsa_keypair(private_path, public_path, bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_path, "wb") as f:
        f.write(private_key)

    with open(public_path, "wb") as f:
        f.write(public_key)

    print(f"Generated:\n  {private_path}\n  {public_path}")

def main():
    # Sender keys
    generate_rsa_keypair("sender_private.pem", "sender_public.pem")

    # Receiver keys
    generate_rsa_keypair("receiver_private.pem", "receiver_public.pem")

if __name__ == "__main__":
    main()
