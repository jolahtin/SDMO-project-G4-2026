import base64
import json
import logging
import socket

from cloud.analysis import analyze_data
from cloud.storage import (
    create_session_directory,
    create_storage_files,
    save_metadata,
)
from common.protocol import (
    receive_message,
    send_message,
)


HOST = "127.0.0.1"
PORT = 6000


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLOUD] %(levelname)s: %(message)s",
)

logger = logging.getLogger(__name__)


def process_edge_connection(
        connection: socket.socket,
        address: tuple[str, int],
) -> None:
    """Receive one complete sensor transmission from the edge."""

    logger.info(
        "Edge connected: %s:%d",
        address[0],
        address[1],
    )

    session_id = None
    expected_sha256 = None
    edge_sha256 = None

    session_dir = None
    encrypted_file = None
    decrypted_file = None

    chunk_count = 0
    encrypted_bytes = 0
    decrypted_bytes = 0

    try:
        first_message = receive_message(
            connection
        )

        if first_message is None:
            raise ValueError(
                "Connection closed before START message"
            )

        try:
            first_payload = json.loads(
                first_message.decode("utf-8")
            )

        except json.JSONDecodeError as exc:
            raise ValueError(
                "Invalid START message"
            ) from exc

        if first_payload.get("type") != "start":
            raise ValueError(
                "First message must be START"
            )

        session_id = first_payload.get("session_id")

        if not session_id:
            raise ValueError(
                "START message does not contain session ID"
            )

        logger.info(
            "Started cloud session: %s",
            session_id,
        )

        session_dir = (
            create_session_directory()
        )

        encrypted_file, decrypted_file = (
            create_storage_files(
                session_dir
            )
        )

        while True:
            message = receive_message(
                connection
            )

            if message is None:
                raise  ValueError(
                    "Connection closed before END message"
                )

            try:
                payload = json.loads(
                    message.decode("utf-8")
                )

            except json.JSONDecodeError as exc:
                raise ValueError(
                    "Received invalid JSON from edge"
                ) from exc

            message_type = payload.get(
                "type"
            )

            if message_type == "data":
                message_session_id = (
                    payload.get(
                        "session_id"
                    )
                )

                if message_session_id != session_id:
                    raise ValueError(
                        "Session ID mismatch"
                    )

                try:
                    encrypted_data = (
                        base64.b64decode(
                            payload[
                                "encrypted_data"
                            ]
                        )
                    )

                    decrypted_data = (
                        base64.b64decode(
                            payload[
                                "decrypted_data"
                            ]
                        )
                    )

                except (
                    KeyError,
                    ValueError,
                    base64.binascii.Error,
                ) as exc:
                    raise ValueError(
                        "Invalid DATA payload"
                    ) from exc

                encrypted_file.write(
                    encrypted_data
                )

                decrypted_file.write(
                    decrypted_data
                )

                chunk_count += 1

                encrypted_bytes += len(encrypted_data)
                decrypted_bytes += len(decrypted_data)

                logger.info(
                    "Stored chunk %d: "
                    "%d encrypted bytes, "
                    "" "%d decrypted bytes",
                    chunk_count,
                    len(encrypted_data),
                    len(decrypted_data),
                )
                continue

            if message_type == "end":
                message_session_id = (
                    payload.get(
                        "session_id"
                    )
                )

                if message_session_id != session_id:
                    raise ValueError(
                        "Session ID mismatch in END message"
                    )

                expected_sha256 = (
                    payload.get(
                        "original_sha256"
                    )
                )

                edge_sha256 = (
                    payload.get(
                        "edge_sha256"
                    )
                )

                if not expected_sha256:
                    raise ValueError(
                        "END message does not contain Sensor SHA-256"
                    )

                logger.info(
                    "Received Sensor SHA-256: %s",
                    expected_sha256,
                )

                if edge_sha256:
                    logger.info(
                        "Received Edge SHA-256: %s",
                        edge_sha256,
                    )

                logger.info(
                    "Received END message"
                )

                break

            raise ValueError(
                f"Unknown message type: {message_type}"
            )

        encrypted_file.close()
        encrypted_file = None

        decrypted_file.close()
        decrypted_file = None

        encrypted_path = (
            session_dir
            / "encrypted_data.bin"
        )

        decrypted_path = (
                session_dir
                / "decrypted_data.bin"
        )

        analysis_results = analyze_data(
            encrypted_path,
            decrypted_path,
            expected_sha256,
        )

        metadata = {
            "session_id": session_id,
            "chunks": chunk_count,
            "encrypted_bytes": encrypted_bytes,
            "decrypted_bytes": decrypted_bytes,
            "sensor_sha256": expected_sha256,
            "edge_sha256": edge_sha256,
            "analysis": analysis_results,
        }

        save_metadata(
            session_dir,
            metadata,
        )

        response = {
            "type": "ack",
            "status": "success",
            "session_id": session_id,
            "chunks": chunk_count,
            "decrypted_bytes": decrypted_bytes,
            "sha256_match": analysis_results[
                "sha256_match"
            ],
        }

        send_message(
            connection,
            json.dumps(response).encode("utf-8"),
        )

        logger.info(
            "Cloud processing completed: %s",
            session_dir,
        )

    except Exception:
        logger.exception(
            "Failed to process edge data"
        )

        try:
            if encrypted_file is not None:
                encrypted_file.close()

            if decrypted_file is not None:
                decrypted_file.close()

        except Exception:
            logger.exception(
                "Could not close storage file"
            )

        error_response = {
            "type": "error",
            "status": "error",
            "message": "Cloud processing failed",
        }

        try:
            send_message(
                connection,
                json.dumps(
                    error_response
                ).encode("utf-8")
            )

        except Exception:
            logger.exception(
                "Could not send error response"
            )

    finally:
        logger.info(
            "Edge connection closed"
        )

def run_server() -> None:
    """Start the cloud server."""

    logger.info(
        "Starting legacy cloud server"
    )

    logger.info(
        "Listening on %s:%d",
        HOST,
        PORT,
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
            (HOST, PORT)
        )

        server.listen(5)

        logger.info(
            "Waiting for edge connection..."
        )

        while True:
            connection, address = (
                server.accept()
            )

            with connection:
                process_edge_connection(
                    connection,
                    address,
                )


def main() -> None:
    try:
        run_server()

    except KeyboardInterrupt:
        logger.info(
            "Cloud server stopped"
        )

    except Exception:
        logger.exception(
            "Cloud server failed"
        )


if __name__ == "__main__":
    main()
