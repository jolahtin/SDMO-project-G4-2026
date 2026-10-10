import argparse
import json
import logging
import socket
import time
import wave
from pathlib import Path
import uuid
import hashlib
import base64

from common.crypto import load_key, encrypt
from common.protocol import send_message


HOST = "127.0.0.1"
PORT = 5000

CHUNK_SIZE = 4096
SEND_DELAY = 0.05



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENSOR] %(levelname)s: %(message)s",
)

logger = logging.getLogger(__name__)


def run_sensor(audio_file: Path) -> None:
    """Read audio data and send encrypted chunks."""

    key = load_key()
    hash_object = hashlib.sha256()
    session_id = str(uuid.uuid4())

    logger.info(
        "Using audio file: %s",
        audio_file,
    )

    logger.info(
        "Session ID: %s",
        session_id,
    )

    with wave.open(
            str(audio_file),
            "rb",
    ) as audio:

        logger.info(
            "Audio: %d Hz, %d channel(s), "
            "%d byte sample width",
            audio.getframerate(),
            audio.getnchannels(),
            audio.getsampwidth(),
        )

        logger.info(
            "Total audio frames: %d",
            audio.getnframes(),
        )

        with socket.create_connection(
                (HOST, PORT)
        ) as sock:

            logger.info(
                "Connected to edge at %s:%d",
                HOST,
                PORT,
            )

            start_payload = {
                "type": "start",
                "session_id": session_id,
            }

            send_message(
                sock,
                json.dumps(
                    start_payload
                ).encode("utf-8")
            )

            logger.info(
                "Sent START message"
            )

            chunk_number = 0

            while True:
                raw_data = audio.readframes(
                    CHUNK_SIZE
                )

                if not raw_data:
                    break

                hash_object.update(raw_data)

                encrypted_data = encrypt(
                    raw_data,
                    key,
                )

                data_payload = {
                    "type": "data",
                    "session_id": session_id,
                    "encrypted_data": base64.b64encode(
                        encrypted_data
                    ).decode("ascii"),
                }

                message = json.dumps(
                    data_payload
                ).encode("utf-8")

                send_message(
                    sock,
                    message,
                )

                chunk_number += 1

                logger.info(
                    "Sent chunk %d: "
                    "%d bytes -> "
                    "%d encrypted bytes",
                    chunk_number,
                    len(raw_data),
                    len(encrypted_data),
                )

                time.sleep(
                    SEND_DELAY
                )

            original_sha256 = (
                hash_object.hexdigest()
            )

            logger.info(
                "Original data SHA-256: %s",
                original_sha256,
            )

            end_payload = {
                "type": "end",
                "session_id": session_id,
                "original_sha256": original_sha256,
            }

            send_message(
                sock,
                json.dumps(
                    end_payload
                ).encode("utf-8"),
            )

            logger.info(
                "Sent END message"
            )

            logger.info(
                "Finished sending %d chunks",
                chunk_number,
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulated audio sensor"
    )

    parser.add_argument(
        "audio_file",
        type=Path,
        help="Path to WAV audio file",
    )

    args = parser.parse_args()

    if not args.audio_file.exists():
        logger.error(
            "Audio file does not exist: %s",
            args.audio_file,
        )
        return

    if args.audio_file.suffix.lower() != ".wav":
        logger.error(
            "Only WAV files are supported"
        )
        return

    try:
        run_sensor(
            args.audio_file
        )

    except ConnectionRefusedError:
        logger.error(
            "Could not connect to edge. "
            "Make sure it is running."
        )

    except Exception:
        logger.exception(
            "Sensor failed"
        )


if __name__ == "__main__":
    main()
