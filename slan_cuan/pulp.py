"""Pulp REST API clients for Maven and File repositories."""

from __future__ import annotations

import hashlib
import json
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

import httpx

# Content API URL path templates
CONTENT_API_PATH_TEMPLATE = (
    "/api/pulp/{domain}/api/v3/content/maven/artifact/upload/"
)
METADATA_API_PATH_TEMPLATE = (
    "/api/pulp/{domain}/api/v3/content/maven/metadata/upload/"
)
REPO_API_PATH_TEMPLATE = "/api/pulp/{domain}/api/v3/repositories/maven/maven/"

# Pulp File plugin API URL path templates
FILE_CONTENT_API_PATH_TEMPLATE = "/api/pulp/{domain}/api/v3/content/file/files/"
FILE_REPO_API_PATH_TEMPLATE = "/api/pulp/{domain}/api/v3/repositories/file/file/"

# Task polling configuration
TASK_POLL_INTERVAL_SECONDS = 2.0
TASK_POLL_TIMEOUT_SECONDS = 600.0

# HTTP client and error handling constants
DEFAULT_TIMEOUT_SECONDS = 300.0
ERROR_BODY_MAX_LENGTH = 200

AUTH_TYPE_TBR: str = "tbr"
AUTH_TYPE_CERT: str = "cert"
AUTH_TYPES: frozenset[str] = frozenset({AUTH_TYPE_TBR, AUTH_TYPE_CERT})


@dataclass(frozen=True)
class PulpConfig:
    """Connection configuration for a Pulp instance."""

    base_url: str
    verify_ssl: bool
    ca_cert: Path | None = None
    domain: str | None = None
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
class ContentUnit:
    """A content unit returned by the synchronous upload endpoint."""

    pulp_href: str
    relative_path: str
    group_id: str
    artifact_id: str
    version: str
    filename: str


@dataclass(frozen=True)
class FileContentUnit:
    """A content unit returned by the Pulp File upload endpoint."""

    pulp_href: str
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class ModifyResult:
    """Result of a repository modify operation."""

    task_href: str
    state: str
    repository_version: str | None
    content_units_added: int


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


class _PulpClientBase:
    """Shared HTTP client logic for Pulp repository operations."""

    _repo_api_path_template: str
    _repo_not_found_message: str

    def __init__(self, config: PulpConfig, distribution: str) -> None:
        """Initialize with connection config and target distribution."""
        self._config = config
        self._distribution = distribution
        _validate_auth(config)

        base_url = config.base_url
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

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
            base_url=base_url,
            verify=verify,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            auth=auth,
        )

    def __enter__(self) -> Self:
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

    def poll_task(
        self,
        task_href: str,
        timeout: float = TASK_POLL_TIMEOUT_SECONDS,
        interval: float = TASK_POLL_INTERVAL_SECONDS,
    ) -> dict[str, object]:
        """Poll a Pulp task until completion or timeout.

        Args:
            task_href: The task href returned from an async operation.
            timeout: Maximum time to wait in seconds.
            interval: Seconds to sleep between polls.

        Returns:
            The completed task response as a dict.

        Raises:
            PulpError: If the task fails, is canceled, or times out.

        """
        start = time.time()
        while True:
            try:
                response = self._client.get(task_href)
            except httpx.ConnectError as e:
                raise PulpError(
                    f"Connection failed while polling task: {e}",
                    status_code=0,
                    response_body="",
                ) from e
            except httpx.TimeoutException as e:
                raise PulpError(
                    f"Request timed out while polling task: {e}",
                    status_code=0,
                    response_body="",
                ) from e

            if response.status_code >= 400:
                body = response.text
                summary = body[:ERROR_BODY_MAX_LENGTH]
                if len(body) > ERROR_BODY_MAX_LENGTH:
                    summary += "... (truncated)"
                raise PulpError(
                    f"Task polling failed ({response.status_code}): {summary}",
                    status_code=response.status_code,
                    response_body=body,
                )

            try:
                task_data = response.json()
                if not isinstance(task_data, dict):
                    raise PulpError(
                        "Task API returned non-dict response",
                        status_code=response.status_code,
                        response_body=response.text,
                    )

                state = task_data.get("state", "")
                if state == "completed":
                    return task_data
                if state in ("failed", "canceled"):
                    error_details = task_data.get("error", {})
                    error_msg = str(error_details.get("description", state))
                    raise PulpError(
                        f"Task {state}: {error_msg}",
                        status_code=response.status_code,
                        response_body=response.text,
                    )

            except (ValueError, KeyError) as e:
                raise PulpError(
                    f"Failed to parse task response: {e}",
                    status_code=response.status_code,
                    response_body=response.text,
                ) from e

            if time.time() - start > timeout:
                raise PulpError(
                    f"Task polling timed out after {timeout}s (state: {state})",
                    status_code=0,
                    response_body=response.text,
                )

            time.sleep(interval)

    def modify_repository(
        self,
        repository_href: str,
        content_unit_hrefs: list[str],
    ) -> ModifyResult:
        """Add content units to a repository in a single version.

        Args:
            repository_href: The pulp_href of the repository.
            content_unit_hrefs: List of content unit pulp_href values to add.

        Returns:
            ModifyResult with task details and repository version.

        Raises:
            PulpError: If the modify request fails or task polling fails.

        """
        url = f"{repository_href}modify/"
        payload = {"add_content_units": content_unit_hrefs}

        try:
            response = self._client.post(url, json=payload)
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
            summary = body[:ERROR_BODY_MAX_LENGTH]
            if len(body) > ERROR_BODY_MAX_LENGTH:
                summary += "... (truncated)"
            raise PulpError(
                f"Repository modify failed ({response.status_code}): {summary}",
                status_code=response.status_code,
                response_body=body,
            )

        try:
            response_data = response.json()
            if not isinstance(response_data, dict):
                raise PulpError(
                    "Modify API returned non-dict response",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            task_href = str(response_data["task"])
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse modify response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        task_data = self.poll_task(task_href)

        repository_version = None
        created_resources = task_data.get("created_resources", [])
        if isinstance(created_resources, list) and created_resources:
            repository_version = str(created_resources[0])

        return ModifyResult(
            task_href=task_href,
            state=str(task_data.get("state", "")),
            repository_version=repository_version,
            content_units_added=len(content_unit_hrefs),
        )

    def resolve_repository(self, name: str) -> str:
        """Look up a repository by name, return its pulp_href.

        Args:
            name: The repository name to look up.

        Returns:
            The pulp_href of the repository.

        Raises:
            PulpError: If the repository is not found or domain is not configured.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for repository lookup. "
                "Set --pulp-domain or use legacy deploy endpoint.",
                status_code=0,
                response_body="",
            )

        url = self._repo_api_path_template.format(domain=self._config.domain)

        try:
            response = self._client.get(url, params={"name": name})
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
            summary = body[:ERROR_BODY_MAX_LENGTH]
            if len(body) > ERROR_BODY_MAX_LENGTH:
                summary += "... (truncated)"
            raise PulpError(
                f"Repository lookup failed ({response.status_code}): {summary}",
                status_code=response.status_code,
                response_body=body,
            )

        try:
            response_data = response.json()
            if not isinstance(response_data, dict):
                raise PulpError(
                    "Repository API returned non-dict response",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            results = response_data.get("results", [])
            if not results:
                raise PulpError(
                    self._repo_not_found_message.format(name=name),
                    status_code=404,
                    response_body=response.text,
                )

            return str(results[0]["pulp_href"])
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse repository lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


class PulpMavenClient(_PulpClientBase):
    """HTTP client for Pulp Maven deploy operations."""

    _repo_api_path_template = REPO_API_PATH_TEMPLATE
    _repo_not_found_message = (
        "Repository '{name}' not found. Check --pulp-repository."
    )

    def upload_content(
        self,
        file_path: Path,
        relative_path: str,
        group_id: str = "",
        artifact_id: str = "",
        version: str = "",
        filename: str = "",
        repository_href: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> ContentUnit:
        """Upload a file and create a Maven content unit in one step.

        Posts the file directly to the content API endpoint,
        which creates both the artifact and the content unit.

        Args:
            file_path: Local path to the artifact file.
            relative_path: Maven repository-layout path.
            group_id: Maven group ID.
            artifact_id: Maven artifact ID.
            version: Maven version.
            filename: Filename of the artifact.
            repository_href: Optional repository href to associate
                the content unit with during creation.
            labels: Optional dict of labels to attach to the content unit.

        Returns:
            ContentUnit with pulp_href and parsed GAV coordinates.

        Raises:
            PulpError: If the upload fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content API uploads. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = CONTENT_API_PATH_TEMPLATE.format(domain=self._config.domain)

        data: dict[str, str] = {
            "relative_path": relative_path,
        }
        if group_id:
            data["group_id"] = group_id
        if artifact_id:
            data["artifact_id"] = artifact_id
        if version:
            data["version"] = version
        if filename:
            data["filename"] = filename
        if repository_href:
            data["repository"] = repository_href
            data["overwrite"] = "true"
        if labels:
            data["pulp_labels"] = json.dumps(labels)

        try:
            with file_path.open("rb") as f:
                files = {
                    "file": (
                        file_path.name,
                        f,
                        "application/octet-stream",
                    ),
                }
                response = self._client.post(
                    url,
                    data=data,
                    files=files,
                )
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
            summary = body[:ERROR_BODY_MAX_LENGTH]
            if len(body) > ERROR_BODY_MAX_LENGTH:
                summary += "... (truncated)"
            raise PulpError(
                f"Content upload failed ({response.status_code}): {summary}",
                status_code=response.status_code,
                response_body=body,
            )

        try:
            response_data = response.json()
            if not isinstance(response_data, dict):
                raise PulpError(
                    "Content API returned non-dict response",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            return ContentUnit(
                pulp_href=str(response_data["pulp_href"]),
                relative_path=str(
                    response_data.get("relative_path", relative_path)
                ),
                group_id=str(response_data.get("group_id") or group_id),
                artifact_id=str(response_data.get("artifact_id") or artifact_id),
                version=str(response_data.get("version") or version),
                filename=str(response_data.get("filename") or filename),
            )
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse content unit response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def upload_metadata(
        self,
        file_path: Path,
        relative_path: str,
        group_id: str = "",
        artifact_id: str = "",
        version: str = "",
        filename: str = "",
        labels: dict[str, str] | None = None,
    ) -> ContentUnit:
        """Upload a Maven metadata XML file as a MavenMetadata content unit.

        Posts the file to the metadata content API endpoint, which
        expects a sha256 digest computed from the file contents.

        Args:
            file_path: Local path to the metadata file.
            relative_path: Maven repository-layout path.
            group_id: Maven group ID.
            artifact_id: Maven artifact ID.
            version: Maven version (optional for metadata).
            filename: Filename of the metadata file.
            labels: Optional dict of labels to attach to the content unit.

        Returns:
            ContentUnit with pulp_href and parsed coordinates.

        Raises:
            PulpError: If the upload fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content API uploads. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = METADATA_API_PATH_TEMPLATE.format(domain=self._config.domain)

        file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

        data: dict[str, str] = {
            "relative_path": relative_path,
            "sha256": file_hash,
        }
        if group_id:
            data["group_id"] = group_id
        if artifact_id:
            data["artifact_id"] = artifact_id
        if version:
            data["version"] = version
        if filename:
            data["filename"] = filename
        if labels:
            data["pulp_labels"] = json.dumps(labels)

        try:
            with file_path.open("rb") as f:
                files = {
                    "file": (
                        file_path.name,
                        f,
                        "application/octet-stream",
                    ),
                }
                response = self._client.post(
                    url,
                    data=data,
                    files=files,
                )
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
            summary = body[:ERROR_BODY_MAX_LENGTH]
            if len(body) > ERROR_BODY_MAX_LENGTH:
                summary += "... (truncated)"
            raise PulpError(
                f"Metadata upload failed ({response.status_code}): {summary}",
                status_code=response.status_code,
                response_body=body,
            )

        try:
            response_data = response.json()
            if not isinstance(response_data, dict):
                raise PulpError(
                    "Metadata API returned non-dict response",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            return ContentUnit(
                pulp_href=str(response_data["pulp_href"]),
                relative_path=str(
                    response_data.get("relative_path", relative_path)
                ),
                group_id=str(response_data.get("group_id") or group_id),
                artifact_id=str(response_data.get("artifact_id") or artifact_id),
                version=str(response_data.get("version") or version),
                filename=str(response_data.get("filename") or filename),
            )
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse metadata response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e


class PulpFileClient(_PulpClientBase):
    """HTTP client for Pulp File repository operations."""

    _repo_api_path_template = FILE_REPO_API_PATH_TEMPLATE
    _repo_not_found_message = (
        "File repository '{name}' not found. Check --pulp-file-repository."
    )

    def upload_content(
        self,
        file_path: Path,
        relative_path: str,
        sha256: str,
        repository_href: str | None = None,
    ) -> FileContentUnit:
        """Upload a file to the Pulp File content API.

        Args:
            file_path: Local path to the file.
            relative_path: Path within the file repository.
            sha256: SHA-256 hex digest of the file.
            repository_href: Optional repository href to associate
                the content unit with during creation.

        Returns:
            FileContentUnit with pulp_href and metadata.

        Raises:
            PulpError: If the upload fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content API uploads. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = FILE_CONTENT_API_PATH_TEMPLATE.format(domain=self._config.domain)

        data: dict[str, str] = {
            "relative_path": relative_path,
            "sha256": sha256,
        }
        if repository_href:
            data["repository"] = repository_href

        try:
            with file_path.open("rb") as f:
                files = {
                    "file": (
                        file_path.name,
                        f,
                        "application/octet-stream",
                    ),
                }
                response = self._client.post(
                    url,
                    data=data,
                    files=files,
                )
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
            summary = body[:ERROR_BODY_MAX_LENGTH]
            if len(body) > ERROR_BODY_MAX_LENGTH:
                summary += "... (truncated)"
            raise PulpError(
                f"File upload failed ({response.status_code}): {summary}",
                status_code=response.status_code,
                response_body=body,
            )

        try:
            response_data = response.json()
            if not isinstance(response_data, dict):
                raise PulpError(
                    "File content API returned non-dict response",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            return FileContentUnit(
                pulp_href=str(response_data["pulp_href"]),
                relative_path=str(
                    response_data.get("relative_path", relative_path)
                ),
                sha256=str(response_data.get("sha256", sha256)),
            )
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse file content unit response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e
