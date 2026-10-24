from pathlib import Path

from common.mlkem import generate_keypair

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"


def main():
    generate_keypair(
        KEYS / "edge_mlkem_private.key",
        KEYS / "edge_mlkem_public.key",
        )
    generate_keypair(
        KEYS / "cloud_mlkem_private.key",
        KEYS / "cloud_mlkem_public.key",
        )

    print(f"ML-KEM-768 key pairs generated in {KEYS}")


if __name__ == "__main__":
    main()