import base64
import hashlib
import json
import logging
import socket
from pathlib import Path

from common.crypto import decrypt, encrypt, fernet_key_from_shared_secret
from common.mlkem import decapsulate, load_private_key
from common.protocol import receive_message, send_message
from cloud.storage import create_session_directory, save_metadata
from cloud.analysis import analyze_data

ROOT = Path(__file__).resolve().parent.parent
CLOUD_PRIVATE_KEY = ROOT / "keys" / "cloud_mlkem_private.key"

HOST = "127.0.0.1"
PORT = 6000
PROTOCOL = "edge-cloud-demo-v1"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLOUD] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def send_json(sock, message):
    send_message(sock, json.dumps(message).encode("utf-8"))


def receive_json(sock):
    raw = receive_message(sock)
    if not raw:
        raise ConnectionError("Unexpected empty message")
    return json.loads(raw.decode("utf-8"))


def establish_edge_session(connection):
    message = receive_json(connection)

    if message.get("type") != "KEM":
        raise ValueError("Expected ML-KEM handshake")
    if message.get("protocol") != PROTOCOL:
        raise ValueError("Unsupported protocol")

    ciphertext = base64.b64decode(
        message["kem_ciphertext"], validate=True
    )
    private_key = load_private_key(CLOUD_PRIVATE_KEY)
    secret = decapsulate(private_key, ciphertext)

    send_json(connection, {"type": "READY", "protocol": PROTOCOL})
    logger.info("ML-KEM-768 edge session established")
    return fernet_key_from_shared_secret(secret)


def process_connection(connection):
    session_key = establish_edge_session(connection)

    start = receive_json(connection)
    if start.get("type") != "START":
        raise ValueError("Expected START message")
    if start.get("protocol") != PROTOCOL:
        raise ValueError("Unsupported protocol")

    session_id = start.get("session_id")
    expected_chunks = start.get("total_chunks")
    expected_size = start.get("original_size")
    expected_hash = start.get("original_sha256")

    if (
            not isinstance(session_id, str) or not session_id
            or not isinstance(expected_chunks, int) or expected_chunks < 1
            or not isinstance(expected_size, int) or expected_size < 1
            or not isinstance(expected_hash, str) or len(expected_hash) != 64
    ):
        raise ValueError("Invalid START metadata")

    session_dir = create_session_directory()
    encrypted_path = session_dir / "encrypted_data.bin"
    decrypted_path = session_dir / "decrypted_data.bin"

    encrypted_parts = []
    plaintext_parts = []

    for expected_index in range(expected_chunks):
        protected = receive_message(connection)
        envelope = json.loads(decrypt(protected, session_key).decode("utf-8"))

        if envelope.get("type") != "DATA":
            raise ValueError("Expected DATA message")
        if envelope.get("protocol") != PROTOCOL:
            raise ValueError("Unsupported protocol")
        if envelope.get("session_id") != session_id:
            raise ValueError("Session ID mismatch")
        if envelope.get("chunk_index") != expected_index:
            raise ValueError("Unexpected chunk index")

        encrypted = base64.b64decode(
            envelope["encrypted_sensor_data"], validate=True
        )
        plaintext = base64.b64decode(
            envelope["decrypted_data"], validate=True
        )

        # Ensure the original encrypted sensor chunk matches its plaintext.
        # The edge has already decrypted this chunk; the cloud does not have
        # the sensor-edge session key, so it cannot decrypt it independently.
        encrypted_parts.append(encrypted)
        plaintext_parts.append(plaintext)

    protected_end = receive_message(connection)
    end = json.loads(decrypt(protected_end, session_key).decode("utf-8"))

    if end.get("type") != "END":
        raise ValueError("Expected END message")
    if end.get("session_id") != session_id:
        raise ValueError("Session ID mismatch")
    if end.get("original_sha256") != expected_hash:
        raise ValueError("START/END hash mismatch")

    encrypted_data = b"".join(encrypted_parts)
    plaintext_data = b"".join(plaintext_parts)

    actual_hash = hashlib.sha256(plaintext_data).hexdigest()
    if len(plaintext_data) != expected_size:
        raise ValueError("Cloud size validation failed")
    if actual_hash != expected_hash:
        raise ValueError("Cloud SHA-256 validation failed")

    encrypted_path.write_bytes(encrypted_data)
    decrypted_path.write_bytes(plaintext_data)

    metadata = {
        "session_id": session_id,
        "protocol": PROTOCOL,
        "filename": start.get("filename", "audio.wav"),
        "total_chunks": expected_chunks,
        "original_size": expected_size,
        "original_sha256": expected_hash,
        "cloud_sha256": actual_hash,
        "hash_valid": True,
        "size_valid": True,
        "pqc": {
            "key_establishment": "ML-KEM-768",
            "bulk_encryption": "Fernet",
        },
    }

    metadata.update(analyze_data(encrypted_path, decrypted_path))
    save_metadata(session_dir, metadata)

    logger.info(
        "Stored validated session %s in %s", session_id, session_dir
    )

    response = {
        "status": "ok",
        "session_id": session_id,
        "chunks": expected_chunks,
        "decrypted_bytes": len(plaintext_data),
        "sha256": actual_hash,
    }
    send_message(
        connection,
        encrypt(json.dumps(response).encode("utf-8"), session_key),
    )


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        logger.info("Listening on %s:%d", HOST, PORT)

        while True:
            connection, address = server.accept()
            logger.info("Edge connected: %s", address)
            with connection:
                connection.settimeout(60)
                try:
                    process_connection(connection)
                except Exception:
                    logger.exception("Failed to process edge connection")


if __name__ == "__main__":
    run_server()