"""Pulp Maven REST API client."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import httpx

MAVEN_DEPLOY_PATH = "/pulp/maven/"

AUTH_TYPE_TBR: str = "tbr"
AUTH_TYPE_CERT: str = "cert"
AUTH_TYPES: frozenset[str] = frozenset({AUTH_TYPE_TBR, AUTH_TYPE_CERT})


@dataclass(frozen=True)
class PulpConfig:
    """Connection configuration for a Pulp instance."""

    base_url: str
    verify_ssl: bool
    ca_cert: Path | None = None
    auth_type: str = AUTH_TYPE_TBR
    username: str | None = None
    password: str | None = None
    client_cert: Path | None = None
    client_key: Path | None = None


def _validate_auth(config: PulpConfig) -> None:
    """Validate auth fields are consistent with auth_type.

    Raises:
        PulpError: If required credentials are missing or inconsistent.

    """
    if config.auth_type not in AUTH_TYPES:
        raise PulpError(
            f"Invalid auth type '{config.auth_type}', "
            f"must be one of: {', '.join(sorted(AUTH_TYPES))}",
            status_code=0,
            response_body="",
        )
    if config.auth_type == AUTH_TYPE_TBR:
        if not config.username or not config.password:
            raise PulpError(
                "TBR auth requires --pulp-username and --pulp-password",
                status_code=0,
                response_body="",
            )
    elif config.auth_type == AUTH_TYPE_CERT:
        if config.client_cert is None or config.client_key is None:
            raise PulpError(
                "Certificate auth requires "
                "--pulp-client-cert and --pulp-client-key",
                status_code=0,
                response_body="",
            )


@dataclass(frozen=True)
class UploadResult:
    """Result of a single artifact upload to Pulp."""

    relative_path: str
    status_code: int
    pulp_href: str


class PulpError(Exception):
    """Exception raised when a Pulp API call fails."""

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: str,
    ) -> None:
        """Initialize with structured error context."""
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_body = response_body


class PulpMavenClient:
    """HTTP client for Pulp Maven deploy operations."""

    def __init__(self, config: PulpConfig, distribution: str) -> None:
        """Initialize with connection config and target distribution."""
        self._config = config
        self._distribution = distribution
        _validate_auth(config)

        verify: ssl.SSLContext | bool = config.verify_ssl
        if verify and config.ca_cert is not None:
            try:
                verify = ssl.create_default_context(
                    cafile=str(config.ca_cert),
                )
                # Internal CAs may omit the "critical" flag on Basic
                # Constraints; Python 3.14+ rejects them by default.
                verify.verify_flags &= ~ssl.VERIFY_X509_STRICT
            except (ssl.SSLError, OSError) as e:
                raise PulpError(
                    f"Failed to load CA certificate from {config.ca_cert}: {e}",
                    status_code=0,
                    response_body="",
                ) from e

        if config.auth_type == AUTH_TYPE_CERT:
            if not isinstance(verify, ssl.SSLContext):
                verify = ssl.create_default_context()
                verify.verify_flags &= ~ssl.VERIFY_X509_STRICT
            try:
                verify.load_cert_chain(
                    certfile=str(config.client_cert),
                    keyfile=str(config.client_key),
                )
            except (ssl.SSLError, OSError) as e:
                raise PulpError(
                    f"Failed to load client certificate: {e}",
                    status_code=0,
                    response_body="",
                ) from e

        auth = None
        tbr_ready = config.auth_type == AUTH_TYPE_TBR
        if tbr_ready and config.username and config.password:
            auth = (config.username, config.password)

        self._client = httpx.Client(
            base_url=config.base_url,
            verify=verify,
            timeout=300.0,
            auth=auth,
        )

    def __enter__(self) -> PulpMavenClient:
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit context manager and close client."""
        self.close()

    def upload_artifact(
        self,
        file_path: Path,
        relative_path: str,
    ) -> UploadResult:
        """Upload a single artifact via PUT.

        Args:
            file_path: Local path to the artifact file.
            relative_path: Maven repository-layout path.

        Returns:
            UploadResult with status and Pulp HREF.

        Raises:
            PulpError: If the upload fails.

        """
        url = f"{MAVEN_DEPLOY_PATH}{self._distribution}/{relative_path}"

        try:
            with file_path.open("rb") as f:
                response = self._client.put(url, content=f)
        except httpx.ConnectError as e:
            raise PulpError(
                f"Connection failed: {e}",
                status_code=0,
                response_body="",
            ) from e
        except httpx.TimeoutException as e:
            raise PulpError(
                f"Request timed out: {e}",
                status_code=0,
                response_body="",
            ) from e

        if response.status_code >= 400:
            body = response.text
            if response.status_code == 404:
                raise PulpError(
                    f"Distribution "
                    f"'{self._distribution}' "
                    f"not found (404). "
                    f"Check --pulp-repository.",
                    status_code=response.status_code,
                    response_body=body,
                )
            summary = body[:200]
            if len(body) > 200:
                summary += "... (truncated)"
            raise PulpError(
                f"Upload failed ({response.status_code}): {summary}",
                status_code=response.status_code,
                response_body=body,
            )

        pulp_href = ""
        try:
            data = response.json()
            if isinstance(data, dict):
                pulp_href = str(data.get("pulp_href", ""))
        except (ValueError, KeyError):
            pass

        return UploadResult(
            relative_path=relative_path,
            status_code=response.status_code,
            pulp_href=pulp_href,
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
