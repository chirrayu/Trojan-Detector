"""Optional MongoDB persistence for local and community threat intelligence."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from trojandetector.config import settings
from trojandetector.logger import log


class IntelligenceUnavailableError(RuntimeError):
    """Raised when MongoDB intelligence is disabled or cannot be loaded."""


@lru_cache(maxsize=1)
def _mongo_client(uri: str):
    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise IntelligenceUnavailableError(
            "MongoDB support requires pymongo; install the database extra"
        ) from exc
    return MongoClient(uri, serverSelectionTimeoutMS=2500, connectTimeoutMS=2500)


def get_database(*, require_enabled: bool = True):
    """Return the configured database, or ``None`` when integration is disabled."""
    if require_enabled and not settings.mongodb_enabled:
        return None
    client = _mongo_client(settings.mongodb_uri)
    return client[settings.mongodb_database]


def check_connection() -> tuple[bool, str]:
    """Check MongoDB availability and return a safe, user-facing status."""
    if not settings.mongodb_enabled:
        return False, "MongoDB intelligence is disabled (set MONGODB_ENABLED=true)."
    try:
        db = get_database()
        db.command("ping")
        ensure_indexes(db)
    except Exception as exc:
        log.warning("MongoDB intelligence unavailable: %s", exc)
        return False, f"MongoDB is unavailable: {type(exc).__name__}"
    return True, f"Connected to MongoDB database '{settings.mongodb_database}'."


def ensure_indexes(db=None) -> None:
    """Create lookup indexes for indicator summaries and report history."""
    db = db or get_database()
    if db is None:
        raise IntelligenceUnavailableError("MongoDB intelligence is disabled")
    db["files"].create_index("sha256", unique=True)
    db["ips"].create_index("ip", unique=True)
    db["domains"].create_index("domain", unique=True)
    db["detections"].create_index([("timestamp", -1)])
    db["detections"].create_index("sha256")
    db["detections"].create_index("ips")
    db["detections"].create_index("domains")


def close_database() -> None:
    """Close and clear the cached MongoDB client."""
    if _mongo_client.cache_info().currsize:
        _mongo_client(settings.mongodb_uri).close()
        _mongo_client.cache_clear()


def _collection(name: str):
    db = get_database()
    if db is None:
        raise IntelligenceUnavailableError(
            "MongoDB intelligence is disabled (set MONGODB_ENABLED=true)."
        )
    return db[name]


def record_detection(record: dict[str, Any]) -> str:
    """Store an explicitly confirmed detection and index its indicators."""
    from datetime import datetime, timezone

    try:
        from pymongo.errors import PyMongoError
    except ImportError as exc:
        raise IntelligenceUnavailableError("MongoDB support requires pymongo") from exc

    from trojandetector.intelligence.domain_intelligence import upsert_domain
    from trojandetector.intelligence.hash_intelligence import upsert_hash
    from trojandetector.intelligence.ip_intelligence import upsert_ip
    from trojandetector.intelligence.domain_intelligence import normalize_domain
    from trojandetector.intelligence.hash_intelligence import normalize_sha256
    from trojandetector.intelligence.ip_intelligence import normalize_ip

    payload = dict(record)
    payload.setdefault("timestamp", datetime.now(timezone.utc))
    if not payload.get("confirmed"):
        raise ValueError("Only explicitly confirmed detections may be community reported")
    if payload.get("classification") not in {"suspicious", "malicious"}:
        raise ValueError("classification must be 'suspicious' or 'malicious'")
    if not any(payload.get(key) for key in ("sha256", "ips", "domains")):
        raise ValueError("A detection must include a SHA-256 hash, IP, or domain")
    if payload.get("sha256"):
        payload["sha256"] = normalize_sha256(payload["sha256"])
    payload["ips"] = sorted(set(payload.get("ips", [])))
    payload["ips"] = sorted({normalize_ip(ip) for ip in payload["ips"]})
    payload["domains"] = sorted({normalize_domain(d) for d in payload.get("domains", [])})
    score = payload.get("risk_score", 0)
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("risk_score must be an integer between 0 and 100")
    try:
        db = get_database()
        ensure_indexes(db)
        result = db["detections"].insert_one(payload)
        detection_id = str(result.inserted_id)
        summary = {
            "classification": payload["classification"],
            "risk_score": payload.get("risk_score"),
            "confirmed": True,
        }
        if payload.get("sha256"):
            upsert_hash(payload["sha256"], detection_id=detection_id, **summary)
        for ip in payload["ips"]:
            upsert_ip(ip, detection_id=detection_id, **summary)
        for domain in payload["domains"]:
            upsert_domain(domain, detection_id=detection_id, **summary)
        return detection_id
    except PyMongoError as exc:
        log.warning("Could not store detection: %s", exc)
        raise IntelligenceUnavailableError("Could not store detection in MongoDB") from exc


def get_detection_history(*, limit: int = 50) -> list[dict[str, Any]]:
    """Return newest reports, with a bounded result size."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    return list(_collection("detections").find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
