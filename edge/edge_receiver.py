import base64
import json
import logging
import socket

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


def send_to_cloud(
        cloud_socket: socket.socket,
        encrypted_data: bytes,
        decrypted_data: bytes,
) -> None:
    """
    Send encrypted and decrypted data to the cloud.

    Binary data is encoded using Base64 so that it can
    safely be included in the JSON message.
    """

    payload = {
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

            while True:
                encrypted_data = receive_message(
                    sensor_socket
                )

                if encrypted_data is None:
                    logger.info(
                        "Sensor finished transmission"
                    )

                    # Tell cloud that transmission is finished.
                    send_message(
                        cloud_socket,
                        b"",
                    )

                    break

                try:
                    decrypted_data = decrypt(
                        encrypted_data,
                        key,
                    )

                except ValueError:
                    logger.error(
                        "Failed to decrypt sensor chunk"
                    )
                    continue

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
                    encrypted_data,
                    decrypted_data,
                )

                logger.info(
                    "Forwarded chunk %d to cloud",
                    chunk_number,
                )

            # Receive cloud confirmation.
            response_data = receive_message(
                cloud_socket
            )

            if response_data:
                response = json.loads(
                    response_data.decode("utf-8")
                )

                logger.info(
                    "Cloud response: %s",
                    response,
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