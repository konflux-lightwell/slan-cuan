"""Trustify (TPA) REST API client with OIDC authentication."""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import httpx

SBOM_UPLOAD_PATH = "api/v2/sbom"
TRANSIENT_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})
TOKEN_EXPIRY_BUFFER_SECONDS = 15


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


class TrustifyError(Exception):
    """Exception raised when a Trustify API call fails."""

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


class TrustifyAuthError(TrustifyError):
    """Exception raised when OIDC authentication fails."""


class TrustifyClient:
    """Synchronous HTTP client for Trustify SBOM operations."""

    def __init__(self, config: TrustifyConfig) -> None:
        """Initialize with connection config and OIDC credentials."""
        self._config = config
        self._access_token: str | None = None
        self._token_expiration: float = 0.0

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
                raise TrustifyError(
                    f"Failed to load CA certificate from {config.ca_cert}: {e}",
                    status_code=0,
                    response_body="",
                ) from e

        self._verify = verify
        self._client = httpx.Client(
            base_url=config.api_url,
            verify=verify,
            timeout=300.0,
        )

    def __enter__(self) -> TrustifyClient:
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

    def _fetch_token(self) -> None:
        """Fetch OAuth2 access token from SSO endpoint.

        Raises:
            TrustifyAuthError: If token fetch fails or response is invalid.

        """
        try:
            response = httpx.post(
                self._config.sso_token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._config.sso_client_id,
                    "client_secret": self._config.sso_client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                verify=self._verify,
                timeout=30.0,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise TrustifyAuthError(
                f"Failed to connect to SSO endpoint: {e}",
                status_code=0,
                response_body="",
            ) from e

        if response.status_code >= 400:
            raise TrustifyAuthError(
                f"OIDC authentication failed ({response.status_code})",
                status_code=response.status_code,
                response_body=response.text,
            )

        try:
            token_data = response.json()
        except ValueError as e:
            raise TrustifyAuthError(
                f"Invalid JSON response from SSO endpoint: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        if not isinstance(token_data, dict):
            raise TrustifyAuthError(
                "SSO response is not a JSON object",
                status_code=response.status_code,
                response_body=response.text,
            )

        if "error" in token_data:
            error_desc = token_data.get("error_description", token_data["error"])
            raise TrustifyAuthError(
                f"SSO error: {error_desc}",
                status_code=response.status_code,
                response_body=response.text,
            )

        access_token = token_data.get("access_token")
        if not access_token:
            raise TrustifyAuthError(
                "Missing access_token in SSO response",
                status_code=response.status_code,
                response_body=response.text,
            )

        try:
            expires_in = int(token_data.get("expires_in", 3600))
        except (ValueError, TypeError):
            expires_in = 3600
        self._access_token = str(access_token)
        self._token_expiration = (
            time.monotonic() + expires_in - TOKEN_EXPIRY_BUFFER_SECONDS
        )

    def _ensure_valid_token(self) -> None:
        """Ensure a valid access token is available."""
        if (
            self._access_token is None
            or time.monotonic() >= self._token_expiration
        ):
            self._fetch_token()

    def upload_sbom(self, sbom_path: Path) -> SBOMUploadResult:
        """Upload a CycloneDX SBOM to Trustify.

        Args:
            sbom_path: Path to the SBOM JSON file.

        Returns:
            SBOMUploadResult with URN and file metadata.

        Raises:
            TrustifyError: If the upload fails.

        """
        self._ensure_valid_token()

        sbom_bytes = sbom_path.read_bytes()
        url = f"{SBOM_UPLOAD_PATH}"

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

        last_exception: Exception | None = None
        for attempt in range(self._config.retries):
            try:
                response = self._client.post(
                    url,
                    content=sbom_bytes,
                    headers=headers,
                )

                if response.status_code < 400:
                    # Success
                    try:
                        data = response.json()
                        if not isinstance(data, dict):
                            raise TrustifyError(
                                "Trustify response is not a JSON object",
                                status_code=response.status_code,
                                response_body=response.text,
                            )

                        sbom_id = data.get("id")
                        if not sbom_id:
                            raise TrustifyError(
                                "Missing 'id' in Trustify response",
                                status_code=response.status_code,
                                response_body=response.text,
                            )

                        return SBOMUploadResult(
                            file_path=str(sbom_path),
                            file_size=len(sbom_bytes),
                            sbom_urn=str(sbom_id),
                        )
                    except ValueError as e:
                        raise TrustifyError(
                            f"Invalid JSON response: {e}",
                            status_code=response.status_code,
                            response_body=response.text,
                        ) from e

                # HTTP error - check if transient
                if response.status_code not in TRANSIENT_STATUS_CODES:
                    # Non-transient error
                    body = response.text
                    summary = body[:200]
                    if len(body) > 200:
                        summary += "... (truncated)"
                    raise TrustifyError(
                        f"SBOM upload failed ({response.status_code}): {summary}",
                        status_code=response.status_code,
                        response_body=body,
                    )

                # Transient error - retry
                last_exception = TrustifyError(
                    f"Transient error ({response.status_code})",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_exception = e

            # Exponential backoff
            if attempt < self._config.retries - 1:
                wait_seconds = 1 * (2**attempt)
                time.sleep(wait_seconds)

        # All retries exhausted
        if last_exception:
            if isinstance(last_exception, TrustifyError):
                raise last_exception
            raise TrustifyError(
                (
                    f"SBOM upload failed after {self._config.retries} "
                    f"retries: {last_exception}"
                ),
                status_code=0,
                response_body="",
            ) from last_exception

        raise TrustifyError(
            f"SBOM upload failed after {self._config.retries} retries",
            status_code=0,
            response_body="",
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
