import base64
import json
import logging
import socket
import hashlib

from common.crypto import load_key, decrypt
from common.protocol import (
    receive_message,
    send_message,
)


EDGE_HOST = "127.0.0.1"
EDGE_PORT = 5000

CLOUD_HOST = "127.0.0.1"
CLOUD_PORT = 6000


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [EDGE] %(levelname)s: %(message)s",
)

logger = logging.getLogger(__name__)

def send_start_to_cloud(
        cloud_socket: socket.socket,
        session_id: str,
) -> None:
    """
    Send START message to the cloud.
    """

    payload = {
        "type": "start",
        "session_id": session_id,
    }

    send_message(
        cloud_socket,
        json.dumps(
            payload
        ).encode("utf-8")
)

def send_to_cloud(
        cloud_socket: socket.socket,
        session_id: str,
        encrypted_data: bytes,
        decrypted_data: bytes,
) -> None:
    """
    Send encrypted and decrypted data to the cloud.

    Binary data is encoded using Base64 so that it can
    safely be included in the JSON message.
    """

    payload = {
        "type": "data",
        "session_id": session_id,

        "encrypted_data": base64.b64encode(
            encrypted_data
        ).decode("ascii"),

        "decrypted_data": base64.b64encode(
            decrypted_data
        ).decode("ascii"),
    }

    message = json.dumps(
        payload
    ).encode("utf-8")

    send_message(
        cloud_socket,
        message,
    )

def send_end_to_cloud(
        cloud_socket: socket.socket,
        session_id: str,
        original_sha256: str,
        edge_sha256: str,
) -> None:
    """
    Send END message and SHA-256 to the cloud.
    """

    payload = {
        "type": "end",
        "session_id": session_id,
        "original_sha256": original_sha256,
        "edge_sha256": edge_sha256,
    }

    send_message(
        cloud_socket,
        json.dumps(
            payload
        ).encode("utf-8")
    )

def handle_sensor_connection(
        sensor_socket: socket.socket,
        sensor_address: tuple[str, int],
        key: bytes,
) -> None:
    """Receive sensor data and forward it to cloud."""

    logger.info(
        "Sensor connected: %s:%d",
        sensor_address[0],
        sensor_address[1],
    )

    try:
        logger.info(
            "Connecting to cloud at %s:%d",
            CLOUD_HOST,
            CLOUD_PORT,
        )

        with socket.create_connection(
                (CLOUD_HOST, CLOUD_PORT)
        ) as cloud_socket:

            logger.info(
                "Connected to cloud"
            )

            chunk_number = 0
            session_id = None
            # original_sha256 = None
            edge_hash_object = hashlib.sha256()

            while True:
                message = receive_message(
                    sensor_socket
                )

                if message is None:
                    logger.error(
                        "Sensor connection closed"
                        " without END message"
                    )
                    break

                try:
                    payload = json.loads(
                        message.decode("utf-8")
                    )

                except json.JSONDecodeError:
                    logger.error(
                        "Received invalid JSON from sensor"
                    )
                    break

                message_type = payload.get(
                    "type"
                )

                if message_type == "start":
                    session_id = payload.get(
                        "session_id"
                    )

                    if not session_id:
                        logger.error(
                            "START message does not contain " 
                            "a session ID"
                        )
                        break

                    logger.info(
                        "Sensor session started: %s",
                        session_id,
                    )

                    send_start_to_cloud(
                        cloud_socket,
                        session_id,
                    )
                    continue

                if message_type == "data":
                    message_session_id = payload.get(
                        "session_id"
                    )

                    if message_session_id != session_id:
                        logger.error(
                            "Session ID mismatch in DATA message"
                        )
                        break

                    try: encrypted_data = (
                        base64.b64decode(
                            payload[
                                "encrypted_data"
                            ]
                        )
                    )

                    except (
                            KeyError,
                            ValueError,
                            base64.binascii.Error,
                    ):
                        logger.error(
                            "Invalid encrypted data " 
                            "in DATA message"
                        )
                        break

                    try: decrypted_data = decrypt(
                        encrypted_data,
                        key,
                    )
                    except ValueError:
                        logger.error(
                            "Failed to decrypt " 
                            "sensor chunk"
                        )
                        break

                    edge_hash_object.update(
                        decrypted_data
                    )

                    chunk_number += 1

                    logger.info(
                        "Received sensor chunk %d: " 
                        "%d encrypted bytes -> " 
                        "%d decrypted bytes",
                        chunk_number,
                        len(encrypted_data),
                        len(decrypted_data),
                    )

                    send_to_cloud(
                        cloud_socket,
                        session_id,
                        encrypted_data,
                        decrypted_data,
                    )

                    logger.info(
                        "Forwarded chunk %d to cloud",
                        chunk_number,
                    )
                    continue

                if message_type == "end":
                    message_session_id = payload.get(
                        "session_id"
                    )

                    if message_session_id != session_id:
                        logger.error(
                            "Session ID mismatch in END message"
                        )
                        break

                    original_sha256 = payload.get(
                        "original_sha256"
                    )

                    if not original_sha256:
                        logger.error(
                            "END message does not contain " 
                            "original SHA-256"
                        )
                        break

                    edge_sha256 = (
                        edge_hash_object.hexdigest()
                    )

                    logger.info(
                        "Sensor SHA-256: %s",
                        original_sha256,
                    )
                    logger.info(
                        "Edge SHA-256: %s",
                        edge_sha256,
                    )

                    if original_sha256 == edge_sha256:
                        logger.info(
                            "Sensor and Edge SHA-256 match"
                        )

                    else: logger.error(
                        "Sensor and Edge SHA-256 mismatch"
                    )

                    send_end_to_cloud(
                        cloud_socket,
                        session_id,
                        original_sha256,
                        edge_sha256,
                    )

                    logger.info(
                        "Sensor finished transmission"
                    )
                    break

                logger.error(
                    "Unknown message type: %s",
                    message_type,
                )
                break

            # Receive cloud confirmation.
            response_data = receive_message(
                cloud_socket
            )

            if response_data:
                try:
                    response = json.loads(
                        response_data.decode("utf-8")
                    )

                    logger.info(
                        "Cloud response: %s",
                        response,
                    )

                except json.JSONDecodeError:
                    logger.error(
                        "Received invalid response from cloud"
                    )


    except ConnectionRefusedError:
        logger.error(
            "Could not connect to cloud. "
            "Make sure the cloud server is running."
        )

    except Exception:
        logger.exception(
            "Error while processing sensor connection"
        )

    finally:
        logger.info(
            "Sensor connection finished"
        )


def run_server() -> None:
    """Start the edge receiver."""

    key = load_key()

    logger.info(
        "Starting legacy edge receiver"
    )

    logger.info(
        "Listening on %s:%d",
        EDGE_HOST,
        EDGE_PORT,
    )

    with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
    ) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server.bind(
            (EDGE_HOST, EDGE_PORT)
        )

        server.listen(5)

        logger.info(
            "Waiting for sensor connection..."
        )

        while True:
            connection, address = (
                server.accept()
            )

            with connection:
                handle_sensor_connection(
                    connection,
                    address,
                    key,
                )


def main() -> None:
    try:
        run_server()

    except KeyboardInterrupt:
        logger.info(
            "Edge receiver stopped"
        )

    except Exception:
        logger.exception(
            "Edge receiver failed"
        )


if __name__ == "__main__":
    main()

# there might me missing the data sending part