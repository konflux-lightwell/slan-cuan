"""Tests for the Pulp Maven client (slan_cuan/pulp/clients/maven.py)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from slan_cuan.pulp.clients.maven import PulpMavenClient
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig


def _content_handler(
    content_response: dict[str, object] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Create a handler for single-step content upload."""
    if content_response is None:
        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc123/",
            "relative_path": "org/example/test/1.0.0/test-1.0.0.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test-1.0.0.jar",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v3/content/maven/artifact/" in url:
            return httpx.Response(200, json=content_response)
        return httpx.Response(404)

    return handler


class TestUploadContent:
    """Tests for upload_content() single-step method."""

    def test_upload_content_success(self, tmp_path: Path) -> None:
        """Single POST returns ContentUnit with correct fields."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        handler = _content_handler()
        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            artifact_file,
            "org/example/test/1.0.0/test-1.0.0.jar",
            group_id="org.example",
            artifact_id="test",
            version="1.0.0",
            filename="test-1.0.0.jar",
        )

        assert result.pulp_href == "/api/v3/content/maven/artifact/abc123/"
        assert result.relative_path == "org/example/test/1.0.0/test-1.0.0.jar"
        assert result.group_id == "org.example"
        assert result.artifact_id == "test"
        assert result.version == "1.0.0"
        assert result.filename == "test-1.0.0.jar"

    def test_upload_content_with_gav(self, tmp_path: Path) -> None:
        """Verify GAV fields are sent as multipart form data."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_fields: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            ct = request.headers.get("content-type", "")
            if "multipart" in ct:
                body = request.content.decode("utf-8", errors="replace")
                for field in [
                    "relative_path",
                    "group_id",
                    "artifact_id",
                    "version",
                ]:
                    if f'name="{field}"' in body:
                        captured_fields[field] = field
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/abc/",
                    "relative_path": "org/example/test.jar",
                    "group_id": "org.example",
                    "artifact_id": "test",
                    "version": "1.0.0",
                    "filename": "test.jar",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(
            artifact_file,
            "org/example/test.jar",
            group_id="org.example",
            artifact_id="test",
            version="1.0.0",
        )

        assert "relative_path" in captured_fields
        assert "group_id" in captured_fields

    def test_upload_content_error(self, tmp_path: Path) -> None:
        """Server returns 500, raises PulpError."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 500
        assert "Content upload failed" in exc_info.value.message

    def test_upload_content_duplicate(self, tmp_path: Path) -> None:
        """Server returns 400 for duplicate, raises PulpError."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="Bad Request: duplicate content")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 400
        assert "Content upload failed" in exc_info.value.message

    def test_upload_content_url_construction(self, tmp_path: Path) -> None:
        """Verify single POST URL uses domain template."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_url = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/abc/",
                    "relative_path": "org/example/test.jar",
                    "group_id": "org.example",
                    "artifact_id": "test",
                    "version": "1.0.0",
                    "filename": "test.jar",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(artifact_file, "org/example/test.jar")

        assert captured_url is not None
        content_url = "/api/pulp/lightwell/api/v3/content/maven/artifact/"
        assert content_url in captured_url

    def test_upload_content_multipart(self, tmp_path: Path) -> None:
        """Verify POST uses multipart form data with file."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_content_type = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_content_type
            captured_content_type = request.headers.get("content-type", "")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/abc/",
                    "relative_path": "org/example/test.jar",
                    "group_id": "org.example",
                    "artifact_id": "test",
                    "version": "1.0.0",
                    "filename": "test.jar",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(artifact_file, "org/example/test.jar")

        assert captured_content_type is not None
        assert "multipart" in captured_content_type.lower()

    def test_upload_content_requires_domain(self, tmp_path: Path) -> None:
        """Config with domain=None, verify PulpError about domain."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain=None,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(artifact_file, "org/example/test.jar")

        assert "Domain is required" in exc_info.value.message
        assert exc_info.value.status_code == 0

    def test_upload_content_connection_error(self, tmp_path: Path) -> None:
        """Mock ConnectError, verify PulpError."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 0
        assert "Connection failed" in exc_info.value.message

    def test_upload_content_timeout(self, tmp_path: Path) -> None:
        """Mock TimeoutException, verify PulpError."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("Request timed out")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 0
        assert "Request timed out" in exc_info.value.message

    def test_upload_content_with_labels(self, tmp_path: Path) -> None:
        """Call upload_content with labels, verify pulp_labels field in body."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_body = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/abc/",
                    "relative_path": "org/example/test.jar",
                    "group_id": "org.example",
                    "artifact_id": "test",
                    "version": "1.0.0",
                    "filename": "test.jar",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(
            artifact_file,
            "org/example/test.jar",
            labels={
                "source_image": "quay.io/test/image@sha256:def",
            },
        )

        assert captured_body is not None
        assert 'name="pulp_labels"' in captured_body

        # Extract JSON value from multipart body
        import re

        pattern = r'name="pulp_labels".*?\r\n\r\n(.*?)\r\n--'
        match = re.search(pattern, captured_body, re.DOTALL)
        assert match is not None
        labels_json = match.group(1)
        decoded_labels = json.loads(labels_json)
        assert decoded_labels == {
            "source_image": "quay.io/test/image@sha256:def",
        }

    def test_upload_content_without_labels(self, tmp_path: Path) -> None:
        """Call upload_content without labels, verify no pulp_labels field."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_body = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/abc/",
                    "relative_path": "org/example/test.jar",
                    "group_id": "org.example",
                    "artifact_id": "test",
                    "version": "1.0.0",
                    "filename": "test.jar",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(artifact_file, "org/example/test.jar")

        assert captured_body is not None
        assert 'name="pulp_labels"' not in captured_body


class TestUploadMetadata:
    """Tests for upload_metadata() method."""

    def test_upload_metadata_success(self, tmp_path: Path) -> None:
        """Single POST returns ContentUnit for metadata."""
        metadata_file = tmp_path / "maven-metadata.xml"
        metadata_file.write_text("<metadata/>")

        metadata_response = {
            "pulp_href": "/api/v3/content/maven/metadata/abc123/",
            "relative_path": "com/example/artifact/maven-metadata.xml",
            "group_id": "com.example",
            "artifact_id": "artifact",
            "version": "",
            "filename": "maven-metadata.xml",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=metadata_response)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_metadata(
            metadata_file,
            "com/example/artifact/maven-metadata.xml",
            group_id="com.example",
            artifact_id="artifact",
            filename="maven-metadata.xml",
        )

        assert result.pulp_href == "/api/v3/content/maven/metadata/abc123/"
        assert result.group_id == "com.example"
        assert result.artifact_id == "artifact"

    def test_upload_metadata_url_construction(self, tmp_path: Path) -> None:
        """Verify POST URL uses metadata template."""
        metadata_file = tmp_path / "maven-metadata.xml"
        metadata_file.write_text("<metadata/>")

        captured_url = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/maven/metadata/abc/",
                    "relative_path": "com/example/artifact/maven-metadata.xml",
                    "group_id": "com.example",
                    "artifact_id": "artifact",
                    "version": "",
                    "filename": "maven-metadata.xml",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_metadata(
            metadata_file,
            "com/example/artifact/maven-metadata.xml",
        )

        assert captured_url is not None
        metadata_url = "/api/pulp/lightwell/api/v3/content/maven/metadata/"
        assert metadata_url in captured_url

    def test_upload_metadata_sends_sha256(self, tmp_path: Path) -> None:
        """Verify sha256 is included in form data."""
        metadata_file = tmp_path / "maven-metadata.xml"
        metadata_file.write_text("<metadata/>")

        captured_body = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/maven/metadata/abc/",
                    "relative_path": "com/example/artifact/maven-metadata.xml",
                    "group_id": "com.example",
                    "artifact_id": "artifact",
                    "version": "",
                    "filename": "maven-metadata.xml",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_metadata(
            metadata_file,
            "com/example/artifact/maven-metadata.xml",
        )

        assert captured_body is not None
        assert 'name="sha256"' in captured_body

    def test_upload_metadata_error(self, tmp_path: Path) -> None:
        """Server returns 500, raises PulpError."""
        metadata_file = tmp_path / "maven-metadata.xml"
        metadata_file.write_text("<metadata/>")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError) as exc_info:
            client.upload_metadata(
                metadata_file,
                "com/example/artifact/maven-metadata.xml",
            )

        assert exc_info.value.status_code == 500
        assert "Metadata upload failed" in exc_info.value.message

    def test_upload_metadata_requires_domain(self, tmp_path: Path) -> None:
        """Config with domain=None, verify PulpError."""
        metadata_file = tmp_path / "maven-metadata.xml"
        metadata_file.write_text("<metadata/>")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain=None,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        with pytest.raises(PulpError) as exc_info:
            client.upload_metadata(
                metadata_file,
                "com/example/artifact/maven-metadata.xml",
            )

        assert "Domain is required" in exc_info.value.message

    def test_upload_metadata_with_labels(self, tmp_path: Path) -> None:
        """Call upload_metadata with labels, verify pulp_labels field in body."""
        metadata_file = tmp_path / "maven-metadata.xml"
        metadata_file.write_text("<metadata/>")

        captured_body = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/maven/metadata/abc/",
                    "relative_path": "com/example/artifact/maven-metadata.xml",
                    "group_id": "com.example",
                    "artifact_id": "artifact",
                    "version": "",
                    "filename": "maven-metadata.xml",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_metadata(
            metadata_file,
            "com/example/artifact/maven-metadata.xml",
            labels={
                "source_image": "quay.io/test/image@sha256:def",
            },
        )

        assert captured_body is not None
        assert 'name="pulp_labels"' in captured_body

        # Extract JSON value from multipart body
        import re

        pattern = r'name="pulp_labels".*?\r\n\r\n(.*?)\r\n--'
        match = re.search(pattern, captured_body, re.DOTALL)
        assert match is not None
        labels_json = match.group(1)
        decoded_labels = json.loads(labels_json)
        assert decoded_labels == {
            "source_image": "quay.io/test/image@sha256:def",
        }
