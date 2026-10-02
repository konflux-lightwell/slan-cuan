"""Pulp REST API clients for File repository operations."""

from __future__ import annotations

from pathlib import Path

import click

from slan_cuan.http import parse_json_dict
from slan_cuan.pulp.clients.base import PulpClientBase
from slan_cuan.pulp.constants import (
    FILE_CONTENT_API_PATH_TEMPLATE,
    FILE_DISTRIBUTION_API_PATH_TEMPLATE,
    FILE_PUBLICATION_API_PATH_TEMPLATE,
    FILE_REPO_API_PATH_TEMPLATE,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import FileContentUnit
from slan_cuan.pulp.utils import utc_timestamp


class PulpFileClient(PulpClientBase):
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
                        f"[{utc_timestamp()}]  Pulp task queued: {task_href}"
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
                click.echo(f"[{utc_timestamp()}]  Pulp task queued: {task_href}")
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
                click.echo(f"[{utc_timestamp()}]  Pulp task queued: {task_href}")
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse distribution update response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        self.poll_task(task_href)
