import json
import logging
from datetime import datetime
from pathlib import Path

CLOUD_DATA_DIR = Path(__file__).resolve().parent.parent / "cloud_data"
logger = logging.getLogger(__name__)


def create_session_directory() -> Path:
    CLOUD_DATA_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    session_dir = CLOUD_DATA_DIR / f"session_{timestamp}"
    session_dir.mkdir()
    logger.info("Created storage directory: %s", session_dir)
    return session_dir


def save_metadata(session_dir: Path, metadata: dict) -> None:
    path = session_dir / "metadata.json"
    path.write_text(
        json.dumps(metadata, indent=4),
        encoding="utf-8",
    )
    logger.info("Saved metadata: %s", path)