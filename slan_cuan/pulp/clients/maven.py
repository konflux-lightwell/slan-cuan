"""Pulp REST API clients for Maven deploy operations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from slan_cuan.http import parse_json_dict
from slan_cuan.pulp.clients.base import PulpClientBase
from slan_cuan.pulp.constants import (
    CONTENT_API_PATH_TEMPLATE,
    METADATA_API_PATH_TEMPLATE,
    REPO_API_PATH_TEMPLATE,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import ContentUnit


class PulpMavenClient(PulpClientBase):
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
