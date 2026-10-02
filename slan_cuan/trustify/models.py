"""Trustify REST API models."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TrustifyConfig:
    """Connection configuration for a Trustify instance."""

    api_url: str
    sso_token_url: str
    sso_client_id: str
    sso_client_secret: str
    verify_ssl: bool
    ca_cert: Path | None = None
    retries: int = 3


@dataclass(frozen=True)
class SBOMUploadResult:
    """Result of a single SBOM upload to Trustify."""

    file_path: str
    file_size: int
    sbom_urn: str
