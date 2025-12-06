# generate_keys.py
from Crypto.PublicKey import RSA


def generate_party_keys(name: str, bits: int = 2048) -> None:
    """
    Generate an RSA key pair for a party and save to disk as:
        {name}_private.pem
        {name}_public.pem
    """
    key = RSA.generate(bits)

    private_pem = key.export_key()
    public_pem = key.publickey().export_key()

    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_pem)

    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_pem)

    print(f"Generated RSA-{bits} key pair for {name}.")


if __name__ == "__main__":
    # Generate generic sender/receiver key pairs
    generate_party_keys("sender")
    generate_party_keys("receiver")
    print("Done.")