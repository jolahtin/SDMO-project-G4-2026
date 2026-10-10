import json
import logging
from datetime import datetime
from pathlib import Path


CLOUD_DATA_DIR = (
        Path(__file__).resolve().parent.parent / "cloud_data"
)

logger = logging.getLogger(__name__)


def create_session_directory() -> Path:
    """Create a unique directory for one sensor transmission."""

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    session_dir = CLOUD_DATA_DIR / f"session_{timestamp}"

    session_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    logger.info(
        "Created cloud storage session: %s",
        session_dir,
    )

    return session_dir


def create_storage_files(
        session_dir: Path,
) -> tuple[object, object]:
    """
    Create files for encrypted and decrypted data.
    """

    encrypted_file = open(
        session_dir / "encrypted_data.bin",
        "wb",
        )

    decrypted_file = open(
        session_dir / "decrypted_data.bin",
        "wb",
        )

    return encrypted_file, decrypted_file


def save_metadata(
        session_dir: Path,
        metadata: dict,
) -> None:
    """Save session metadata as JSON."""

    metadata_file = session_dir / "metadata.json"

    with open(metadata_file, "w", encoding="utf-8") as file:
        json.dump(
            metadata,
            file,
            indent=4,
        )

    logger.info(
        "Saved metadata: %s",
        metadata_file,
    )
