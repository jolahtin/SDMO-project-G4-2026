import argparse
import base64
import hashlib
import json
import logging
import socket
import time
import uuid
from pathlib import Path

from common.crypto import encrypt, fernet_key_from_shared_secret
from common.mlkem import encapsulate, load_public_key
from common.protocol import receive_message, send_message

ROOT = Path(__file__).resolve().parent.parent
EDGE_PUBLIC_KEY = ROOT / "keys" / "edge_mlkem_public.key"

HOST = "127.0.0.1"
PORT = 5000
CHUNK_SIZE = 4096
SEND_DELAY = 0.05
PROTOCOL = "edge-cloud-demo-v1"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENSOR] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def send_json(sock, message):
    send_message(sock, json.dumps(message).encode("utf-8"))


def receive_json(sock):
    raw = receive_message(sock)
    if not raw:
        raise ConnectionError("Unexpected empty response")
    return json.loads(raw.decode("utf-8"))


def establish_session(sock):
    public_key = load_public_key(EDGE_PUBLIC_KEY)
    shared_secret, kem_ciphertext = encapsulate(public_key)

    send_json(sock, {
        "type": "KEM",
        "protocol": PROTOCOL,
        "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("ascii"),
    })

    response = receive_json(sock)
    if response.get("type") != "READY":
        raise ValueError("Edge did not confirm session establishment")

    logger.info("ML-KEM-768 session established with edge")
    return fernet_key_from_shared_secret(shared_secret)


def run_sensor(audio_path: Path):
    if not audio_path.is_file():
        raise FileNotFoundError(f"Audio file not found: {audio_path}")

    if audio_path.suffix.lower() != ".wav":
        raise ValueError("Input must be a .wav file")

    data = audio_path.read_bytes()
    if not data:
        raise ValueError("Audio file is empty")

    session_id = str(uuid.uuid4())
    sha256 = hashlib.sha256(data).hexdigest()
    chunks = [
        data[i:i + CHUNK_SIZE]
        for i in range(0, len(data), CHUNK_SIZE)
    ]

    logger.info("File: %s (%d bytes)", audio_path, len(data))
    logger.info("Session: %s; chunks: %d", session_id, len(chunks))

    with socket.create_connection((HOST, PORT), timeout=30) as sock:
        sock.settimeout(30)
        session_key = establish_session(sock)

        send_json(sock, {
            "type": "START",
            "protocol": PROTOCOL,
            "session_id": session_id,
            "filename": audio_path.name,
            "total_chunks": len(chunks),
            "original_size": len(data),
            "original_sha256": sha256,
        })

        for index, chunk in enumerate(chunks):
            encrypted = encrypt(chunk, session_key)

            send_json(sock, {
                "type": "DATA",
                "protocol": PROTOCOL,
                "session_id": session_id,
                "chunk_index": index,
                "payload": base64.b64encode(encrypted).decode("ascii"),
            })

            logger.info("Sent chunk %d/%d", index + 1, len(chunks))
            time.sleep(SEND_DELAY)

        send_json(sock, {
            "type": "END",
            "protocol": PROTOCOL,
            "session_id": session_id,
            "original_sha256": sha256,
        })

        response = receive_json(sock)
        if response.get("status") != "ok":
            raise RuntimeError(f"Edge/cloud reported failure: {response}")

        logger.info("Transfer completed: %s", response)


def main():
    parser = argparse.ArgumentParser(description="Simulated audio sensor")
    parser.add_argument("audio_file", type=Path)
    args = parser.parse_args()

    try:
        run_sensor(args.audio_file)
    except Exception:
        logger.exception("Sensor failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()