"""Hash-keyed detection lookup and historical intelligence helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from trojandetector.intelligence.database import _collection

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def normalize_sha256(sha256: str) -> str:
    """Validate and normalize a SHA-256 digest."""
    digest = sha256.strip().lower()
    if not _SHA256.fullmatch(digest):
        raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
    return digest


def lookup_hash(sha256: str) -> dict[str, Any] | None:
    """Return the current intelligence summary for a SHA-256 digest."""
    return _collection("files").find_one({"sha256": normalize_sha256(sha256)}, {"_id": 0})


def get_hash_history(sha256: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """Return recent detection reports associated with a hash."""
    digest = normalize_sha256(sha256)
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    return list(
        _collection("detections")
        .find({"sha256": digest}, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )


def upsert_hash(sha256: str, *, detection_id: str | None = None, **metadata: Any) -> None:
    """Update summary metadata for a SHA-256 indicator."""
    digest = normalize_sha256(sha256)
    collection = _collection("files")
    if metadata.get("classification") == "suspicious":
        current = collection.find_one({"sha256": digest}, {"classification": 1}) or {}
        if current.get("classification") == "malicious":
            metadata["classification"] = "malicious"
    update: dict[str, Any] = {
        "$set": {"sha256": digest, "updated_at": datetime.now(timezone.utc), **metadata},
        "$inc": {"report_count": 1},
        "$setOnInsert": {"first_seen": datetime.now(timezone.utc)},
    }
    if detection_id:
        update["$addToSet"] = {"detection_ids": detection_id}
    collection.update_one({"sha256": digest}, update, upsert=True)
