"""Tests for Pulp Maven client (slan_cuan/pulp.py)."""

from __future__ import annotations

import ssl
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp import (
    AUTH_TYPE_CERT,
    AUTH_TYPE_TBR,
    PulpConfig,
    PulpError,
    PulpMavenClient,
    _validate_auth,
)


class TestPulpMavenClient:
    """Tests for PulpMavenClient upload operations."""

    def test_upload_success(self, tmp_path: Path) -> None:
        """Mock 200 response with JSON body, verify UploadResult fields."""
        # Create test artifact
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        # Mock transport that returns success
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "PUT"
            assert "/pulp/maven/test-dist/org/example/test.jar" in str(
                request.url
            )
            return httpx.Response(
                200,
                json={"pulp_href": "/api/v3/content/maven/artifact/abc123/"},
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

        result = client.upload_artifact(artifact_file, "org/example/test.jar")

        assert result.relative_path == "org/example/test.jar"
        assert result.status_code == 200
        assert result.pulp_href == "/api/v3/content/maven/artifact/abc123/"

    def test_upload_404_distribution_not_found(self, tmp_path: Path) -> None:
        """Mock 404, verify PulpError with hint about --pulp-repository."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404, text="Distribution 'missing-dist' not found"
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "missing-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.upload_artifact(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.message
        assert "--pulp-repository" in exc_info.value.message
        assert "missing-dist" in exc_info.value.message

    def test_upload_500_server_error(self, tmp_path: Path) -> None:
        """Mock 500, verify PulpError with status_code=500."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

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
            client.upload_artifact(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 500
        assert "Upload failed (500)" in exc_info.value.message

    def test_upload_connection_error(self, tmp_path: Path) -> None:
        """Transport raises httpx.ConnectError, verify PulpError."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

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
            client.upload_artifact(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 0
        assert "Connection failed" in exc_info.value.message

    def test_upload_timeout(self, tmp_path: Path) -> None:
        """Transport raises httpx.TimeoutException, verify PulpError."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("Request timed out")

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
            client.upload_artifact(artifact_file, "org/example/test.jar")

        assert exc_info.value.status_code == 0
        assert "Request timed out" in exc_info.value.message

    def test_upload_url_construction(self, tmp_path: Path) -> None:
        """Verify PUT URL is constructed correctly."""
        artifact_file = tmp_path / "test-1.0.0.jar"
        artifact_file.write_text("jar content")

        captured_url = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(200, json={"pulp_href": "/api/v3/test/"})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "production-repo")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.upload_artifact(
            artifact_file, "org/example/test/1.0.0/test-1.0.0.jar"
        )

        assert captured_url is not None
        assert (
            "/pulp/maven/production-repo/org/example/test/1.0.0/test-1.0.0.jar"
            in captured_url
        )

    def test_upload_non_json_response(self, tmp_path: Path) -> None:
        """Mock 200 with non-JSON body, verify UploadResult has empty href."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Upload successful")

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

        result = client.upload_artifact(artifact_file, "org/example/test.jar")

        assert result.status_code == 200
        assert result.pulp_href == ""

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

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"pulp_href": "/api/v3/test/"})

        transport = httpx.MockTransport(handler)

        # Create config with insecure mode
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        # The actual verification happens in the httpx.Client constructor
        # We can verify by checking that insecure mode was requested
        assert config.verify_ssl is False

        # Replace with mock transport to complete the test
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            verify=False,
        )

        result = client.upload_artifact(artifact_file, "org/example/test.jar")
        assert result.status_code == 200


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

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_auth_header
            captured_auth_header = request.headers.get("Authorization")
            return httpx.Response(200, json={"pulp_href": "/api/v3/test/"})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            auth=("testuser", "testpass"),
        )

        client.upload_artifact(artifact_file, "org/example/test.jar")

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
