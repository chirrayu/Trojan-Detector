"""IP-keyed detection intelligence helpers."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from trojandetector.intelligence.database import _collection


def normalize_ip(ip: str) -> str:
    """Validate and normalize an IPv4 or IPv6 address."""
    return str(ipaddress.ip_address(ip.strip()))


def lookup_ip(ip: str) -> dict[str, Any] | None:
    """Return the intelligence summary for an IP address."""
    return _collection("ips").find_one({"ip": normalize_ip(ip)}, {"_id": 0})


def get_ip_history(ip: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """Return recent reports mentioning an IP address."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    return list(
        _collection("detections")
        .find({"ips": normalize_ip(ip)}, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )


def upsert_ip(ip: str, *, detection_id: str | None = None, **metadata: Any) -> None:
    """Update metadata for an IP indicator."""
    address = normalize_ip(ip)
    collection = _collection("ips")
    if metadata.get("classification") == "suspicious":
        current = collection.find_one({"ip": address}, {"classification": 1}) or {}
        if current.get("classification") == "malicious":
            metadata["classification"] = "malicious"
    update: dict[str, Any] = {
        "$set": {"ip": address, "updated_at": datetime.now(timezone.utc), **metadata},
        "$inc": {"report_count": 1},
        "$setOnInsert": {"first_seen": datetime.now(timezone.utc)},
    }
    if detection_id:
        update["$addToSet"] = {"detection_ids": detection_id}
    collection.update_one({"ip": address}, update, upsert=True)
