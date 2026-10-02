"""Pulp REST API shared utilities."""

from datetime import datetime, timezone


def utc_timestamp() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
