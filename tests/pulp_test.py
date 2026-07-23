"""Tests for Pulp Maven client (slan_cuan/pulp.py)."""

from __future__ import annotations

import json
import ssl
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp import (
    AUTH_TYPE_CERT,
    AUTH_TYPE_TBR,
    PulpConfig,
    PulpError,
    PulpFileClient,
    PulpMavenClient,
    _validate_auth,
)


class TestPulpMavenClient:
    """Tests for PulpMavenClient operations."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        # Should not raise
        client.close()


class TestPulpError:
    """Tests for PulpError exception."""

    def test_pulp_error_attributes(self) -> None:
        """Verify message, status_code, response_body are preserved."""
        error = PulpError(
            message="Upload failed",
            status_code=500,
            response_body="Internal Server Error",
        )

        assert error.message == "Upload failed"
        assert error.status_code == 500
        assert error.response_body == "Internal Server Error"
        assert str(error) == "Upload failed"


class TestPulpConfig:
    """Tests for PulpConfig."""

    @patch("slan_cuan.pulp.ssl.create_default_context")
    def test_ca_cert_creates_ssl_context(
        self, mock_create_ctx: Mock, tmp_path: Path
    ) -> None:
        """When ca_cert is set, an SSLContext is built from it."""
        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("PEM data")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            ca_cert=ca_file,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        mock_create_ctx.assert_called_once_with(
            cafile=str(ca_file),
        )
        client.close()

    def test_ca_cert_invalid_pem_raises_pulp_error(self, tmp_path: Path) -> None:
        """Malformed CA cert raises PulpError, not ssl.SSLError."""
        ca_file = tmp_path / "bad-ca.crt"
        ca_file.write_text("not a real certificate")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            ca_cert=ca_file,
            username="testuser",
            password="testpass",
        )

        with pytest.raises(PulpError) as exc_info:
            PulpMavenClient(config, "test-dist")

        assert "Failed to load CA certificate" in exc_info.value.message

    def test_ca_cert_ignored_when_insecure(self) -> None:
        """When verify_ssl=False, ca_cert is ignored."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            ca_cert=Path("/some/ca.crt"),
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert config.verify_ssl is False
        client.close()

    def test_verify_ssl_propagates(self, tmp_path: Path) -> None:
        """Create client with verify_ssl=False, verify propagation."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc/",
            "relative_path": "org/example/test.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test.jar",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=content_response)

        transport = httpx.MockTransport(handler)

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        assert config.verify_ssl is False

        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            verify=False,
        )

        result = client.upload_content(artifact_file, "org/example/test.jar")
        assert result.pulp_href == "/api/v3/content/maven/artifact/abc/"

    def test_base_url_without_scheme_gets_https(self) -> None:
        """A base_url without a scheme gets https:// prepended."""
        config = PulpConfig(
            base_url="packages.redhat.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "https://packages.redhat.com"
        client.close()

    def test_base_url_with_https_unchanged(self) -> None:
        """A base_url with https:// is not modified."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "https://pulp.example.com"
        client.close()

    def test_base_url_with_http_unchanged(self) -> None:
        """A base_url with http:// is not modified."""
        config = PulpConfig(
            base_url="http://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "http://pulp.example.com"
        client.close()


class TestValidateAuth:
    """Tests for _validate_auth authentication validation."""

    def test_validate_auth_tbr_missing_username(self) -> None:
        """TBR auth without username raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            password="testpass",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "TBR auth requires" in exc_info.value.message
        assert "--pulp-username" in exc_info.value.message
        assert "--pulp-password" in exc_info.value.message

    def test_validate_auth_tbr_missing_password(self) -> None:
        """TBR auth without password raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            username="testuser",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "TBR auth requires" in exc_info.value.message
        assert "--pulp-username" in exc_info.value.message
        assert "--pulp-password" in exc_info.value.message

    def test_validate_auth_cert_missing_cert(self, tmp_path: Path) -> None:
        """Certificate auth without client_cert raises PulpError."""
        key_file = tmp_path / "client.key"
        key_file.write_text("key content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_key=key_file,
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Certificate auth requires" in exc_info.value.message
        assert "--pulp-client-cert" in exc_info.value.message
        assert "--pulp-client-key" in exc_info.value.message

    def test_validate_auth_cert_missing_key(self, tmp_path: Path) -> None:
        """Certificate auth without client_key raises PulpError."""
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_cert=cert_file,
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Certificate auth requires" in exc_info.value.message
        assert "--pulp-client-cert" in exc_info.value.message
        assert "--pulp-client-key" in exc_info.value.message

    def test_validate_auth_invalid_type(self) -> None:
        """Invalid auth_type raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type="invalid",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Invalid auth type 'invalid'" in exc_info.value.message
        assert "cert" in exc_info.value.message
        assert "tbr" in exc_info.value.message

    def test_tbr_auth_sends_basic_header(self, tmp_path: Path) -> None:
        """TBR auth configures httpx.Client with basic auth."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_auth_header = None

        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc/",
            "relative_path": "org/example/test.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test.jar",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_auth_header
            captured_auth_header = request.headers.get("Authorization")
            return httpx.Response(200, json=content_response)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            auth=("testuser", "testpass"),
        )

        client.upload_content(artifact_file, "org/example/test.jar")

        assert captured_auth_header is not None
        assert captured_auth_header.startswith("Basic ")

    def test_cert_auth_loads_ssl_context(self, tmp_path: Path) -> None:
        """Cert auth loads cert chain with correct paths."""
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert content")
        key_file = tmp_path / "client.key"
        key_file.write_text("key content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_cert=cert_file,
            client_key=key_file,
        )

        with patch("slan_cuan.pulp.ssl.SSLContext.load_cert_chain") as mock_load:
            try:
                PulpMavenClient(config, "test-dist")
            except (ssl.SSLError, OSError):
                pass

            mock_load.assert_called_once_with(
                certfile=str(cert_file),
                keyfile=str(key_file),
            )


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


class TestPollTask:
    """Tests for poll_task() method."""

    @patch("slan_cuan.pulp.time.sleep")
    def test_poll_task_immediate_completion(self, mock_sleep: Mock) -> None:
        """Task returns 'completed' on first poll."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [
                        "/api/v3/repositories/maven/maven/uuid/versions/1/",
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.poll_task("/api/v3/tasks/task-uuid/")

        assert result["state"] == "completed"
        mock_sleep.assert_not_called()

    @patch("slan_cuan.pulp.time.sleep")
    def test_poll_task_eventual_completion(self, mock_sleep: Mock) -> None:
        """First poll 'running', second poll 'completed'."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return httpx.Response(200, json={"state": "running"})
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [],
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.poll_task("/api/v3/tasks/task-uuid/")

        assert result["state"] == "completed"
        assert call_count == 2
        mock_sleep.assert_called()

    @patch("slan_cuan.pulp.time.sleep")
    def test_poll_task_failed(self, mock_sleep: Mock) -> None:
        """Task returns 'failed' with error details, verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "failed",
                    "error": {"description": "Content validation failed"},
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.poll_task("/api/v3/tasks/task-uuid/")

        assert "Task failed" in exc_info.value.message
        assert "Content validation failed" in exc_info.value.message

    @patch("slan_cuan.pulp.time.sleep")
    def test_poll_task_canceled(self, mock_sleep: Mock) -> None:
        """Task returns 'canceled', verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"state": "canceled", "error": {}},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.poll_task("/api/v3/tasks/task-uuid/")

        assert "Task canceled" in exc_info.value.message

    @patch("slan_cuan.pulp.time.sleep")
    def test_poll_task_timeout(self, mock_sleep: Mock) -> None:
        """Use very short timeout, verify PulpError with 'timed out'."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"state": "running"})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.poll_task(
                "/api/v3/tasks/task-uuid/",
                timeout=0.01,
                interval=0.005,
            )

        assert "timed out" in exc_info.value.message


class TestModifyRepository:
    """Tests for modify_repository() method."""

    @patch("slan_cuan.pulp.time.sleep")
    def test_modify_repository_success(self, mock_sleep: Mock) -> None:
        """Mock 202 with task href, then completed task, verify ModifyResult."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1

            # First call is the modify POST
            if "modify/" in str(request.url):
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            # Second call is the task poll
            else:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [
                            "/api/v3/repositories/maven/maven/uuid/versions/2/",
                        ],
                    },
                )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [
                "/api/v3/content/maven/artifact/abc/",
                "/api/v3/content/maven/artifact/def/",
            ],
        )

        assert result.task_href == "/api/v3/tasks/task-uuid/"
        assert result.state == "completed"
        repo_ver = "/api/v3/repositories/maven/maven/uuid/versions/2/"
        assert result.repository_version == repo_ver
        assert result.content_units_added == 2

    def test_modify_repository_error_status(self) -> None:
        """Mock 500, verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.modify_repository(
                "/api/v3/repositories/maven/maven/uuid/",
                ["/api/v3/content/maven/artifact/abc/"],
            )

        assert exc_info.value.status_code == 500
        assert "Repository modify failed" in exc_info.value.message

    @patch("slan_cuan.pulp.time.sleep")
    def test_modify_repository_request_payload(self, mock_sleep: Mock) -> None:
        """Capture JSON body, verify add_content_units payload."""
        captured_payload = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload

            # Capture modify request
            if "modify/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            # Task poll
            else:
                return httpx.Response(
                    200,
                    json={"state": "completed", "created_resources": []},
                )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [
                "/api/v3/content/maven/artifact/abc/",
                "/api/v3/content/maven/artifact/def/",
            ],
        )

        assert captured_payload is not None
        assert "add_content_units" in captured_payload
        assert len(captured_payload["add_content_units"]) == 2
        units = captured_payload["add_content_units"]
        assert "/api/v3/content/maven/artifact/abc/" in units


class TestResolveRepository:
    """Tests for resolve_repository() method."""

    def test_resolve_repository_success(self) -> None:
        """Mock 200 with results list, verify returned pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "count": 1,
                    "results": [
                        {
                            "pulp_href": (
                                "/api/v3/repositories/maven/maven/uuid123/"
                            ),
                            "name": "lightwell-test",
                        }
                    ],
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
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_repository("lightwell-test")

        assert href == "/api/v3/repositories/maven/maven/uuid123/"

    def test_resolve_repository_not_found(self) -> None:
        """Mock 200 with empty results, verify PulpError(404)."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"count": 0, "results": []},
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
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.resolve_repository("nonexistent-repo")

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.message
        assert "nonexistent-repo" in exc_info.value.message

    def test_resolve_repository_requires_domain(self) -> None:
        """Config with domain=None, verify PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain=None,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        with pytest.raises(PulpError) as exc_info:
            client.resolve_repository("test-repo")

        assert "Domain is required" in exc_info.value.message
        assert exc_info.value.status_code == 0

    def test_resolve_repository_url_construction(self) -> None:
        """Capture URL, verify domain template and name param."""
        captured_url = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/maven/maven/uuid/"}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="mydom",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_repository("my-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/repositories/maven/maven/" in captured_url
        assert "name=my-repo" in captured_url


def _file_content_handler(
    content_response: dict[str, object] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Create a handler for Pulp File content upload."""
    if content_response is None:
        content_response = {
            "pulp_href": "/api/v3/content/file/files/abc123/",
            "relative_path": "BUILD123/gav-index.osv.json",
            "sha256": "deadbeef" * 8,
        }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v3/content/file/files/" in url:
            return httpx.Response(200, json=content_response)
        return httpx.Response(404)

    return handler


class TestPulpFileClient:
    """Tests for PulpFileClient operations."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client.close()

    def test_upload_content_success(self, tmp_path: Path) -> None:
        """Single POST returns FileContentUnit with correct fields."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        handler = _file_content_handler()
        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
        )

        assert result.pulp_href == "/api/v3/content/file/files/abc123/"
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_url(self, tmp_path: Path) -> None:
        """Upload hits the File content API path."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "B/test.osv.json",
                    "sha256": "abc",
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(test_file, "B/test.osv.json", sha256="abc")

        assert captured_url is not None
        assert "/api/pulp/testdomain/api/v3/content/file/files/" in captured_url

    def test_upload_content_multipart_fields(self, tmp_path: Path) -> None:
        """Verify form data includes relative_path and sha256."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        captured_body: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "B/test.osv.json",
                    "sha256": "abcdef",
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(test_file, "B/test.osv.json", sha256="abcdef")

        assert captured_body is not None
        assert "relative_path" in captured_body
        assert "B/test.osv.json" in captured_body
        assert "sha256" in captured_body
        assert "abcdef" in captured_body

    def test_upload_content_error(self, tmp_path: Path) -> None:
        """Error response raises PulpError."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError, match="File upload failed"):
            client.upload_content(test_file, "B/test.osv.json", sha256="abc")

    def test_upload_content_domain_required(self, tmp_path: Path) -> None:
        """Missing domain raises PulpError."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")

        with pytest.raises(PulpError, match="Domain is required"):
            client.upload_content(test_file, "B/test.osv.json", sha256="abc")

    def test_resolve_repository_success(self) -> None:
        """Successful lookup returns pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/repositories/file/file/uuid/")}
                    ]
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_repository("my-file-repo")
        assert href == "/api/v3/repositories/file/file/uuid/"

    def test_resolve_repository_not_found(self) -> None:
        """Empty results raises PulpError with 404."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError, match="not found"):
            client.resolve_repository("nonexistent-repo")

    def test_resolve_repository_url(self) -> None:
        """Verify the File repository API path is used."""
        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/repositories/file/file/uuid/")}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="mydom",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_repository("my-file-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/repositories/file/file/" in captured_url
        assert "name=my-file-repo" in captured_url

    @patch("slan_cuan.pulp.time.sleep")
    def test_modify_repository_success(self, mock_sleep: Mock) -> None:
        """Modify adds content units and returns ModifyResult."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            url = str(request.url)
            if "modify" in url:
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            if "tasks" in url:
                call_count += 1
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [
                            "/api/v3/repositories/file/file/uuid/versions/1/"
                        ],
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/file/file/uuid/",
            ["/api/v3/content/file/files/abc/"],
        )

        assert result.content_units_added == 1
        assert result.state == "completed"
        assert result.repository_version is not None
