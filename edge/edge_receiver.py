import base64
import hashlib
import json
import logging
import socket
from pathlib import Path

from common.crypto import decrypt, encrypt, fernet_key_from_shared_secret
from common.mlkem import decapsulate, encapsulate, load_private_key, load_public_key
from common.protocol import receive_message, send_message

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"

EDGE_PRIVATE_KEY = KEYS / "edge_mlkem_private.key"
CLOUD_PUBLIC_KEY = KEYS / "cloud_mlkem_public.key"

EDGE_HOST = "127.0.0.1"
EDGE_PORT = 5000
CLOUD_HOST = "127.0.0.1"
CLOUD_PORT = 6000
PROTOCOL = "edge-cloud-demo-v1"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EDGE] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def send_json(sock, message):
    send_message(sock, json.dumps(message).encode("utf-8"))


def receive_json(sock):
    raw = receive_message(sock)
    if not raw:
        raise ConnectionError("Unexpected empty message")
    return json.loads(raw.decode("utf-8"))


def establish_sensor_session(sensor_socket):
    message = receive_json(sensor_socket)

    if message.get("type") != "KEM":
        raise ValueError("Expected ML-KEM handshake")
    if message.get("protocol") != PROTOCOL:
        raise ValueError("Unsupported protocol")

    ciphertext = base64.b64decode(
        message["kem_ciphertext"], validate=True
    )
    private_key = load_private_key(EDGE_PRIVATE_KEY)
    secret = decapsulate(private_key, ciphertext)

    send_json(sensor_socket, {"type": "READY", "protocol": PROTOCOL})
    return fernet_key_from_shared_secret(secret)


def establish_cloud_session(cloud_socket):
    public_key = load_public_key(CLOUD_PUBLIC_KEY)
    secret, ciphertext = encapsulate(public_key)

    send_json(cloud_socket, {
        "type": "KEM",
        "protocol": PROTOCOL,
        "kem_ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })

    response = receive_json(cloud_socket)
    if response.get("type") != "READY":
        raise ValueError("Cloud did not confirm session establishment")

    return fernet_key_from_shared_secret(secret)


def handle_sensor(sensor_socket):
    session_key = establish_sensor_session(sensor_socket)

    start = receive_json(sensor_socket)
    if start.get("type") != "START":
        raise ValueError("Expected START message")
    if start.get("protocol") != PROTOCOL:
        raise ValueError("Unsupported protocol")

    session_id = start.get("session_id")
    expected_chunks = start.get("total_chunks")
    expected_hash = start.get("original_sha256")
    expected_size = start.get("original_size")

    if (
            not isinstance(session_id, str) or not session_id
            or not isinstance(expected_chunks, int) or expected_chunks < 1
            or not isinstance(expected_size, int) or expected_size < 1
            or not isinstance(expected_hash, str) or len(expected_hash) != 64
    ):
        raise ValueError("Invalid START metadata")

    logger.info("Receiving session %s", session_id)

    encrypted_chunks = []
    decrypted_chunks = []

    for expected_index in range(expected_chunks):
        message = receive_json(sensor_socket)

        if message.get("type") != "DATA":
            raise ValueError("Expected DATA message")
        if message.get("protocol") != PROTOCOL:
            raise ValueError("Unsupported protocol")
        if message.get("session_id") != session_id:
            raise ValueError("Session ID mismatch")
        if message.get("chunk_index") != expected_index:
            raise ValueError("Unexpected chunk index")

        encrypted = base64.b64decode(message["payload"], validate=True)
        plaintext = decrypt(encrypted, session_key)

        encrypted_chunks.append(encrypted)
        decrypted_chunks.append(plaintext)

    end = receive_json(sensor_socket)
    if end.get("type") != "END":
        raise ValueError("Expected END message")
    if end.get("session_id") != session_id:
        raise ValueError("Session ID mismatch")
    if end.get("original_sha256") != expected_hash:
        raise ValueError("START/END hash mismatch")

    plaintext = b"".join(decrypted_chunks)
    actual_hash = hashlib.sha256(plaintext).hexdigest()

    if len(plaintext) != expected_size:
        raise ValueError("Original size validation failed")
    if actual_hash != expected_hash:
        raise ValueError("Original SHA-256 validation failed")

    logger.info("Sensor data decrypted and hash verified")

    with socket.create_connection((CLOUD_HOST, CLOUD_PORT), timeout=30) as cloud:
        cloud.settimeout(30)
        cloud_key = establish_cloud_session(cloud)

        send_json(cloud, {
            "type": "START",
            "protocol": PROTOCOL,
            "session_id": session_id,
            "filename": start.get("filename", "audio.wav"),
            "total_chunks": expected_chunks,
            "original_size": expected_size,
            "original_sha256": expected_hash,
        })

        for index, (encrypted, plain) in enumerate(
                zip(encrypted_chunks, decrypted_chunks)
        ):
            envelope = {
                "type": "DATA",
                "protocol": PROTOCOL,
                "session_id": session_id,
                "chunk_index": index,
                "encrypted_sensor_data": base64.b64encode(
                    encrypted
                ).decode("ascii"),
                "decrypted_data": base64.b64encode(
                    plain
                ).decode("ascii"),
            }

            protected = encrypt(
                json.dumps(envelope).encode("utf-8"),
                cloud_key,
            )
            send_message(cloud, protected)

        end_envelope = {
            "type": "END",
            "protocol": PROTOCOL,
            "session_id": session_id,
            "original_sha256": expected_hash,
        }
        send_message(
            cloud,
            encrypt(json.dumps(end_envelope).encode("utf-8"), cloud_key),
        )

        response = decrypt(receive_message(cloud), cloud_key)
        result = json.loads(response.decode("utf-8"))

    if result.get("status") != "ok":
        raise RuntimeError(f"Cloud reported failure: {result}")

    send_json(sensor_socket, result)
    logger.info("Session %s forwarded and acknowledged", session_id)


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((EDGE_HOST, EDGE_PORT))
        server.listen()
        logger.info("Listening on %s:%d", EDGE_HOST, EDGE_PORT)

        while True:
            connection, address = server.accept()
            logger.info("Sensor connected: %s", address)
            with connection:
                connection.settimeout(60)
                try:
                    handle_sensor(connection)
                except Exception:
                    logger.exception("Failed to process sensor connection")


if __name__ == "__main__":
    run_server()