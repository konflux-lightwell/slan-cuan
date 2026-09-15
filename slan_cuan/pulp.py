"""Pulp REST API clients for Maven and File repositories."""

from __future__ import annotations

import hashlib
import json
import random
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import click
import httpx

from slan_cuan.http import (
    HttpApiError,
    create_ssl_context,
    parse_json_dict,
    request,
)

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
FILE_PUBLICATION_API_PATH_TEMPLATE = (
    "/api/pulp/{domain}/api/v3/publications/file/file/"
)
FILE_DISTRIBUTION_API_PATH_TEMPLATE = (
    "/api/pulp/{domain}/api/v3/distributions/file/file/"
)

# Task polling configuration
TASK_POLL_INITIAL_INTERVAL_SECONDS = 2.0
TASK_POLL_MAX_INTERVAL_SECONDS = 15.0
TASK_POLL_BACKOFF_FACTOR = 1.5
TASK_POLL_JITTER_FACTOR = 0.2
TASK_POLL_TIMEOUT_SECONDS = 1800.0
TASK_CANCEL_TIMEOUT_SECONDS = 15.0


def _utc_timestamp() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# HTTP client and error handling constants
DEFAULT_TIMEOUT_SECONDS = 300.0

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
    task_timeout: float = TASK_POLL_TIMEOUT_SECONDS
    verbose: bool = False


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


def _validate_config(config: PulpConfig) -> None:
    """Validate connection and operational config fields.

    Raises:
        PulpError: If required credentials or parameters are invalid.

    """
    if config.task_timeout <= 0:
        raise PulpError(
            f"task_timeout must be positive, got {config.task_timeout}",
            status_code=0,
            response_body="",
        )
    _validate_auth(config)


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


class PulpError(HttpApiError):
    """Exception raised when a Pulp API call fails."""


class _PulpClientBase:
    """Shared HTTP client logic for Pulp repository operations."""

    _repo_api_path_template: str
    _repo_not_found_message: str

    def __init__(self, config: PulpConfig, distribution: str) -> None:
        """Initialize with connection config and target distribution."""
        self._config = config
        self._distribution = distribution
        _validate_config(config)

        base_url = config.base_url
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        verify = create_ssl_context(config.ca_cert, config.verify_ssl, PulpError)

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

    def _request(
        self,
        method: str,
        url: str,
        operation: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an HTTP request with optional verbose logging."""
        if self._config.verbose:
            details: list[str] = []
            if "params" in kwargs and kwargs["params"]:
                details.append(f"params={kwargs['params']}")
            if "data" in kwargs and kwargs["data"]:
                safe_data = {
                    k: (
                        "***"
                        if any(
                            s in k.lower()
                            for s in ("password", "secret", "token", "key")
                        )
                        else v
                    )
                    for k, v in kwargs["data"].items()
                }
                details.append(f"data={safe_data}")
            if "json" in kwargs and kwargs["json"]:
                details.append(f"json={kwargs['json']}")
            if "files" in kwargs and kwargs["files"]:
                details.append(f"files={list(kwargs['files'].keys())}")
            payload_str = f" [{', '.join(details)}]" if details else ""
            click.echo(
                f"[{_utc_timestamp()}]  Pulp request: {method} {url}{payload_str}"
            )

        response = request(
            self._client,
            method,
            url,
            operation,
            PulpError,
            **kwargs,
        )

        if self._config.verbose:
            details = []
            try:
                data = response.json()
                if isinstance(data, dict):
                    state = data.get("state")
                    if state:
                        details.append(f"state={state}")
                        if state == "waiting":
                            waiting_on = self._find_blocking_task(data)
                            if waiting_on:
                                details.append(f"waiting_on={waiting_on}")
                    elif "task" in data:
                        details.append(f"task={data['task']}")
            except Exception:
                pass
            extra = f" [{', '.join(details)}]" if details else ""
            click.echo(
                f"[{_utc_timestamp()}]  Pulp response: "
                f"{response.status_code}{extra}"
            )

        return response

    def cancel_task(self, task_href: str) -> str:
        """Attempt to cancel a Pulp task.

        Sends a PATCH request setting the task state to 'canceled' using a
        short cancellation timeout (TASK_CANCEL_TIMEOUT_SECONDS).

        Args:
            task_href: The task href to cancel.

        Returns:
            A descriptive string of the cancellation outcome.

        """
        try:
            response = self._request(
                "PATCH",
                task_href,
                "Task cancel",
                timeout=TASK_CANCEL_TIMEOUT_SECONDS,
                json={"state": "canceled"},
            )
            if response.status_code in (200, 202):
                return "cancellation requested in Pulp"
            return f"cancellation returned HTTP {response.status_code}"
        except PulpError as e:
            if e.status_code == 409:
                return (
                    "cancellation returned 409 Conflict "
                    "(task may have already finished or canceled)"
                )
            if self._config.verbose:
                click.echo(f"  Failed to cancel task {task_href}: {e}")
            msg = f"HTTP {e.status_code}" if e.status_code else str(e)
            return f"cancellation attempt failed: {msg}"
        except Exception as e:
            if self._config.verbose:
                click.echo(f"  Failed to cancel task {task_href}: {e}")
            return f"cancellation attempt failed: {e}"

    def _find_blocking_task(
        self, task_data: dict[str, object] | None
    ) -> str | None:
        """Find the task that a waiting task is waiting on.

        Checks:
        1. Explicit parent task if set on task_data.
        2. Any active (running) task reserving the same resources.
        3. An earlier task in 'waiting' state that is ahead in queue for the
           same resources.

        Returns:
            The pulp_href of the blocking task, or None if none identified.

        """
        if not task_data or not isinstance(task_data, dict):
            return None

        if "_cached_waiting_on" in task_data:
            cached = task_data["_cached_waiting_on"]
            return str(cached) if cached is not None else None

        blocker: str | None = None

        # 1. Direct parent task
        parent = task_data.get("parent_task")
        if parent and isinstance(parent, str):
            blocker = parent
        else:
            # 2. Check reserved resources
            resources = task_data.get("reserved_resources_record")
            current_task_href = str(task_data.get("pulp_href") or "")
            if isinstance(resources, list) and resources:
                if current_task_href and "/tasks/" in current_task_href:
                    tasks_base = (
                        current_task_href.split("/tasks/")[0] + "/tasks/"
                    )
                else:
                    domain = self._config.domain
                    tasks_base = (
                        f"/api/pulp/{domain}/api/v3/tasks/"
                        if domain
                        else "/api/v3/tasks/"
                    )

                res_filter = ",".join(str(r) for r in resources)

                try:
                    res = self._client.get(
                        tasks_base,
                        params={
                            "reserved_resources__in": res_filter,
                            "state": "running",
                            "limit": 1,
                        },
                        timeout=2.0,
                    )
                    if res.status_code == 200:
                        data = res.json()
                        if isinstance(data, dict):
                            results = data.get("results", [])
                            if results and isinstance(results, list):
                                candidate = results[0].get("pulp_href")
                                if (
                                    candidate
                                    and candidate != current_task_href
                                ):
                                    blocker = str(candidate)
                except Exception:
                    pass

                # If no running blocker found, check earlier waiting tasks
                if not blocker:
                    pulp_created = task_data.get("pulp_created")
                    params: dict[str, Any] = {
                        "reserved_resources__in": res_filter,
                        "state": "waiting",
                        "ordering": "pulp_created",
                        "limit": 2,
                    }
                    if pulp_created and isinstance(pulp_created, str):
                        params["pulp_created__lt"] = pulp_created

                    try:
                        res = self._client.get(
                            tasks_base,
                            params=params,
                            timeout=2.0,
                        )
                        if res.status_code == 200:
                            data = res.json()
                            if isinstance(data, dict):
                                results = data.get("results", [])
                                if results and isinstance(results, list):
                                    for item in results:
                                        candidate = item.get("pulp_href")
                                        if (
                                            candidate
                                            and candidate != current_task_href
                                        ):
                                            blocker = str(candidate)
                                            break
                    except Exception:
                        pass

        task_data["_cached_waiting_on"] = blocker
        return blocker

    def _handle_timeout(
        self,
        task_href: str,
        timeout: float,
        state: str,
        response_text: str,
        waiting_on: str | None = None,
    ) -> None:
        """Handle timeout by canceling if waiting and raising PulpError."""
        canceled_note = ""
        if state == "waiting":
            outcome = self.cancel_task(task_href)
            canceled_note = f" ({outcome})"
        elif state not in ("completed", "failed", "canceled"):
            canceled_note = f" (cancellation skipped: task state is {state})"
        state_str = state
        if state == "waiting" and waiting_on:
            state_str = f"waiting, waiting on: {waiting_on}"
        msg = (
            f"Task polling timed out after {timeout}s "
            f"(state: {state_str}){canceled_note}"
        )
        raise PulpError(
            msg,
            status_code=0,
            response_body=response_text,
        )

    def _check_task_status(
        self,
        task_href: str,
        req_timeout: float,
    ) -> tuple[dict[str, object], str, str]:
        """Fetch and parse current task status.

        Returns:
            Tuple of (task_data, state, raw_response_text).

        """
        response = self._request(
            "GET",
            task_href,
            "Task polling",
            timeout=req_timeout,
        )
        task_data = parse_json_dict(response, "Task", PulpError)
        state = str(task_data.get("state", ""))
        return task_data, state, response.text

    def poll_task(
        self,
        task_href: str,
        timeout: float | None = None,
    ) -> dict[str, object]:
        """Poll a Pulp task until completion or timeout.

        Applies exponential backoff with random jitter between poll attempts.
        If timeout is exceeded, attempts to cancel the task in Pulp before
        raising PulpError.

        Args:
            task_href: The task href returned from an async operation.
            timeout: Maximum time to wait in seconds (defaults to
                config.task_timeout).

        Returns:
            The completed task response as a dict.

        Raises:
            PulpError: If the task fails, is canceled, or times out.
            ValueError: If timeout is not positive.

        """
        if timeout is None:
            timeout = self._config.task_timeout
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")

        start = time.monotonic()
        deadline = start + timeout
        current_interval = TASK_POLL_INITIAL_INTERVAL_SECONDS
        current_state = ""
        current_waiting_on: str | None = None
        last_response_text = ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Double-check task status before timing out or canceling
                req_timeout = min(DEFAULT_TIMEOUT_SECONDS, 10.0)
                try:
                    fresh_data, fresh_state, fresh_text = self._check_task_status(
                        task_href, req_timeout
                    )
                except Exception:
                    fresh_data, fresh_state, fresh_text = (
                        None,
                        current_state,
                        last_response_text,
                    )

                if fresh_state == "completed" and fresh_data is not None:
                    if self._config.verbose:
                        created = fresh_data.get("created_resources", [])
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task completed: "
                            f"{task_href} (created_resources={created})"
                        )
                    return fresh_data

                fresh_waiting_on = (
                    self._find_blocking_task(fresh_data)
                    if fresh_state == "waiting" and fresh_data is not None
                    else None
                )

                if current_state and fresh_state != current_state:
                    current_state = fresh_state
                    current_waiting_on = fresh_waiting_on
                    last_response_text = fresh_text
                    start = time.monotonic()
                    deadline = start + timeout
                    if self._config.verbose:
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task {task_href} "
                            f"transitioned to '{fresh_state}'; "
                            f"resetting wait deadline for {timeout}s"
                        )
                    continue

                if (
                    current_state == "waiting"
                    and fresh_state == "waiting"
                    and current_waiting_on is not None
                    and fresh_waiting_on != current_waiting_on
                ):
                    current_waiting_on = fresh_waiting_on
                    last_response_text = fresh_text
                    start = time.monotonic()
                    deadline = start + timeout
                    if self._config.verbose:
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task {task_href} "
                            f"waiting blocker changed: {current_waiting_on} "
                            f"-> {fresh_waiting_on}; resetting wait deadline "
                            f"for {timeout}s"
                        )
                    continue

                self._handle_timeout(
                    task_href,
                    timeout,
                    fresh_state,
                    fresh_text,
                    waiting_on=current_waiting_on,
                )

            req_timeout = min(DEFAULT_TIMEOUT_SECONDS, max(1.0, remaining))
            response = self._request(
                "GET",
                task_href,
                "Task polling",
                timeout=req_timeout,
            )
            last_response_text = response.text

            try:
                task_data = parse_json_dict(response, "Task", PulpError)
                new_state = str(task_data.get("state", ""))
                new_waiting_on = (
                    self._find_blocking_task(task_data)
                    if new_state == "waiting"
                    else None
                )

                if current_state and new_state != current_state:
                    start = time.monotonic()
                    deadline = start + timeout
                    if self._config.verbose:
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task {task_href} "
                            f"transitioned to '{new_state}'; "
                            f"resetting wait deadline for {timeout}s"
                        )
                elif (
                    current_state == "waiting"
                    and new_state == "waiting"
                    and current_waiting_on is not None
                    and new_waiting_on != current_waiting_on
                ):
                    start = time.monotonic()
                    deadline = start + timeout
                    if self._config.verbose:
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task {task_href} "
                            f"waiting blocker changed: {current_waiting_on} "
                            f"-> {new_waiting_on}; resetting wait deadline "
                            f"for {timeout}s"
                        )

                current_state = new_state
                current_waiting_on = new_waiting_on

                if new_state == "completed":
                    if self._config.verbose:
                        created = task_data.get("created_resources", [])
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task completed: "
                            f"{task_href} (created_resources={created})"
                        )
                    return task_data
                if new_state in ("failed", "canceled"):
                    error_details = task_data.get("error", {})
                    error_msg = str(
                        error_details.get("description", new_state)
                        if isinstance(error_details, dict)
                        else new_state
                    )
                    traceback_str = (
                        str(error_details.get("traceback", "")).strip()
                        if isinstance(error_details, dict)
                        else ""
                    )
                    parts = [f"Task {new_state}: {error_msg}"]
                    if traceback_str:
                        parts.append(f"Traceback:\n{traceback_str}")
                    parts.append(f"Task: {task_href}")
                    raise PulpError(
                        "\n".join(parts),
                        status_code=response.status_code,
                        response_body=response.text,
                    )

            except (ValueError, KeyError) as e:
                raise PulpError(
                    f"Failed to parse task response: {e}",
                    status_code=response.status_code,
                    response_body=response.text,
                ) from e

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                continue

            jitter = current_interval * TASK_POLL_JITTER_FACTOR
            sleep_time = random.uniform(
                max(0.1, current_interval - jitter),
                current_interval + jitter,
            )
            sleep_time = min(sleep_time, remaining)
            time.sleep(sleep_time)

            current_interval = min(
                TASK_POLL_MAX_INTERVAL_SECONDS,
                current_interval * TASK_POLL_BACKOFF_FACTOR,
            )

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

        response = self._request(
            "POST",
            url,
            "Repository modify",
            json=payload,
        )

        try:
            response_data = parse_json_dict(response, "Modify", PulpError)
            task_href = str(response_data["task"])
            if self._config.verbose:
                click.echo(f"[{_utc_timestamp()}]  Pulp task queued: {task_href}")
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

        response = self._request(
            "GET",
            url,
            "Repository lookup",
            params={"name": name},
        )

        try:
            response_data = parse_json_dict(response, "Repository", PulpError)
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

        with file_path.open("rb") as f:
            files = {
                "file": (
                    file_path.name,
                    f,
                    "application/octet-stream",
                ),
            }
            response = self._request(
                "POST",
                url,
                "Content upload",
                data=data,
                files=files,
            )

        try:
            response_data = parse_json_dict(response, "Content", PulpError)
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

        with file_path.open("rb") as f:
            files = {
                "file": (
                    file_path.name,
                    f,
                    "application/octet-stream",
                ),
            }
            response = self._request(
                "POST",
                url,
                "Metadata upload",
                data=data,
                files=files,
            )

        try:
            response_data = parse_json_dict(response, "Metadata", PulpError)
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

        with file_path.open("rb") as f:
            files = {
                "file": (
                    file_path.name,
                    f,
                    "application/octet-stream",
                ),
            }
            response = self._request(
                "POST",
                url,
                "File upload",
                data=data,
                files=files,
            )

        try:
            response_data = parse_json_dict(response, "File content", PulpError)

            if "task" in response_data:
                task_href = str(response_data["task"])
                if self._config.verbose:
                    click.echo(
                        f"[{_utc_timestamp()}]  Pulp task queued: {task_href}"
                    )
                task_data = self.poll_task(task_href)
                created = task_data.get("created_resources", [])
                if not isinstance(created, list) or not created:
                    raise PulpError(
                        "File upload task completed but created no resources",
                        status_code=response.status_code,
                        response_body=response.text,
                    )
                content_href = next(
                    (str(r) for r in created if "/content/file/files/" in str(r)),
                    str(created[-1]),
                )
                content_response = self._request(
                    "GET",
                    content_href,
                    "File content lookup",
                )
                response_data = parse_json_dict(
                    content_response, "File content", PulpError
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

    def create_publication(self, repository_href: str) -> str:
        """Create a File publication for a repository.

        Args:
            repository_href: The pulp_href of the repository.

        Returns:
            The pulp_href of the created publication.

        Raises:
            PulpError: If the publication fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for publication creation. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = FILE_PUBLICATION_API_PATH_TEMPLATE.format(
            domain=self._config.domain
        )
        payload = {"repository": repository_href}

        response = self._request(
            "POST",
            url,
            "Publication creation",
            json=payload,
        )

        try:
            response_data = parse_json_dict(response, "Publication", PulpError)
            task_href = str(response_data["task"])
            if self._config.verbose:
                click.echo(f"[{_utc_timestamp()}]  Pulp task queued: {task_href}")
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse publication response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        task_data = self.poll_task(task_href)

        created_resources = task_data.get("created_resources", [])
        if not isinstance(created_resources, list) or not created_resources:
            raise PulpError(
                "Publication task completed but created no resources",
                status_code=0,
                response_body="",
            )

        return str(created_resources[0])

    def resolve_distribution(self, name: str) -> str:
        """Look up a file distribution by name, return its pulp_href.

        Args:
            name: The distribution name to look up.

        Returns:
            The pulp_href of the distribution.

        Raises:
            PulpError: If the distribution is not found or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for distribution lookup. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = FILE_DISTRIBUTION_API_PATH_TEMPLATE.format(
            domain=self._config.domain
        )

        response = self._request(
            "GET",
            url,
            "Distribution lookup",
            params={"name": name},
        )

        try:
            response_data = parse_json_dict(response, "Distribution", PulpError)
            results = response_data.get("results", [])
            if not results:
                raise PulpError(
                    f"Distribution '{name}' not found. "
                    "Check --pulp-file-repository.",
                    status_code=404,
                    response_body=response.text,
                )

            return str(results[0]["pulp_href"])
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse distribution lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def update_distribution(
        self, distribution_href: str, publication_href: str
    ) -> None:
        """Update a distribution to serve a new publication.

        Args:
            distribution_href: The pulp_href of the distribution.
            publication_href: The pulp_href of the publication to serve.

        Raises:
            PulpError: If the update fails.

        """
        payload = {"publication": publication_href, "repository": ""}

        response = self._request(
            "PATCH",
            distribution_href,
            "Distribution update",
            json=payload,
        )

        try:
            response_data = parse_json_dict(
                response, "Distribution update", PulpError
            )
            task_href = str(response_data["task"])
            if self._config.verbose:
                click.echo(f"[{_utc_timestamp()}]  Pulp task queued: {task_href}")
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse distribution update response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        self.poll_task(task_href)
