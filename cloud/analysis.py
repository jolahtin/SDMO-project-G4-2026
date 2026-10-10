import hashlib
import logging
from pathlib import Path


logger = logging.getLogger(__name__)


def analyze_data(
        encrypted_file: Path,
        decrypted_file: Path,
        expected_sha256: str | None = None,
) -> dict:
    """
    Perform basic analysis of the received sensor data.
    """

    encrypted_data = encrypted_file.read_bytes()
    decrypted_data = decrypted_file.read_bytes()

    if not decrypted_data:
        raise ValueError(
            "No decrypted data available for analysis"
        )

    decrypted_hash = hashlib.sha256(
        decrypted_data
    ).hexdigest()

    encrypted_hash = hashlib.sha256(
        encrypted_data
    ).hexdigest()

    hash_matches = None

    if expected_sha256 is not None:
        hash_matches = (
            decrypted_hash == expected_sha256
        )

    byte_values = list(decrypted_data)

    minimum = min(byte_values)
    maximum = max(byte_values)
    average = sum(byte_values) / len(byte_values)

    encrypted_size = len(encrypted_data)
    decrypted_size = len(decrypted_data)

    expansion_ratio = (
        encrypted_size / decrypted_size
        if decrypted_size > 0
        else 0
    )

    results = {
        "decrypted_bytes": decrypted_size,
        "encrypted_bytes": encrypted_size,
        "encryption_expansion_ratio": round(
            expansion_ratio,
            3,
        ),
        "decrypted_sha256": decrypted_hash,
        "expected_sha256": expected_sha256,
        "sha256_match": hash_matches,
        "encrypted_sha256": encrypted_hash,
        "decrypted_byte_min": minimum,
        "decrypted_byte_max": maximum,
        "decrypted_byte_average": round(
            average,
            3,
        ),
    }

    logger.info(
        "Cloud analysis completed: %s",
        results,
    )

    if expected_sha256 is not None:
        if hash_matches:
            logger.info(
                "SHA-256 verification successful"
            )
        else:
            logger.error(
                "SHA-256 verification failed"
            )

    return results
