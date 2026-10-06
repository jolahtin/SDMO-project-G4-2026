import argparse
import logging
import socket
import time
import wave
from pathlib import Path

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

    logger.info(
        "Using audio file: %s",
        audio_file,
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

            chunk_number = 0

            while True:
                raw_data = audio.readframes(
                    CHUNK_SIZE
                )

                if not raw_data:
                    break

                encrypted_data = encrypt(
                    raw_data,
                    key,
                )

                send_message(
                    sock,
                    encrypted_data,
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

            # Zero-length message means finished.
            send_message(
                sock,
                b"",
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
