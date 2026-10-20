"""Domain-keyed detection intelligence helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from trojandetector.intelligence.database import _collection


def normalize_domain(domain: str) -> str:
    """Normalize a DNS name using IDNA and reject malformed labels."""
    value = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not value:
        raise ValueError("domain must be a valid DNS name")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("domain must be a valid DNS name")
    return value


def lookup_domain(domain: str) -> dict[str, Any] | None:
    """Return the intelligence summary for a DNS domain."""
    return _collection("domains").find_one({"domain": normalize_domain(domain)}, {"_id": 0})


def get_domain_history(domain: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """Return recent reports mentioning a domain."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    return list(
        _collection("detections")
        .find({"domains": normalize_domain(domain)}, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )


def upsert_domain(domain: str, *, detection_id: str | None = None, **metadata: Any) -> None:
    """Update metadata for a domain indicator."""
    name = normalize_domain(domain)
    collection = _collection("domains")
    if metadata.get("classification") == "suspicious":
        current = collection.find_one({"domain": name}, {"classification": 1}) or {}
        if current.get("classification") == "malicious":
            metadata["classification"] = "malicious"
    update: dict[str, Any] = {
        "$set": {"domain": name, "updated_at": datetime.now(timezone.utc), **metadata},
        "$inc": {"report_count": 1},
        "$setOnInsert": {"first_seen": datetime.now(timezone.utc)},
    }
    if detection_id:
        update["$addToSet"] = {"detection_ids": detection_id}
    collection.update_one({"domain": name}, update, upsert=True)
