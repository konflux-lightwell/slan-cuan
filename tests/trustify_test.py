"""Tests for Trustify client (slan_cuan/trustify.py)."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.trustify import (
    TrustifyAuthError,
    TrustifyClient,
    TrustifyConfig,
    TrustifyError,
)


class TestTrustifyClientAuth:
    """Tests for OIDC token fetching."""

    def test_fetch_token_success(self) -> None:
        """Mock SSO endpoint returning token, verify _access_token is set."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            mock_post.return_value = httpx.Response(
                200,
                json={"access_token": "tok123", "expires_in": 300},
            )

            client = TrustifyClient(config)
            client._fetch_token()

            assert client._access_token == "tok123"
            assert client._token_expiration > time.monotonic()
            client.close()

    def test_fetch_token_bad_credentials(self) -> None:
        """SSO returns 401, verify TrustifyAuthError raised."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="wrong-secret",
            verify_ssl=True,
        )

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            mock_post.return_value = httpx.Response(401, text="Unauthorized")

            client = TrustifyClient(config)
            with pytest.raises(TrustifyAuthError) as exc_info:
                client._fetch_token()

            assert exc_info.value.status_code == 401
            assert "OIDC authentication failed" in exc_info.value.message
            client.close()

    def test_fetch_token_sso_unreachable(self) -> None:
        """Transport raises httpx.ConnectError, verify TrustifyAuthError."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            mock_post.side_effect = httpx.ConnectError("Connection refused")

            client = TrustifyClient(config)
            with pytest.raises(TrustifyAuthError) as exc_info:
                client._fetch_token()

            assert exc_info.value.status_code == 0
            assert "Failed to connect to SSO endpoint" in exc_info.value.message
            client.close()

    def test_fetch_token_missing_access_token(self) -> None:
        """SSO returns 200 with empty object, verify TrustifyAuthError."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            mock_post.return_value = httpx.Response(200, json={})

            client = TrustifyClient(config)
            with pytest.raises(TrustifyAuthError) as exc_info:
                client._fetch_token()

            assert (
                "Missing access_token in SSO response" in exc_info.value.message
            )
            client.close()

    def test_fetch_token_error_in_response(self) -> None:
        """SSO returns error field, verify TrustifyAuthError with description."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="wrong-secret",
            verify_ssl=True,
        )

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            mock_post.return_value = httpx.Response(
                200,
                json={
                    "error": "unauthorized_client",
                    "error_description": "Invalid client secret",
                },
            )

            client = TrustifyClient(config)
            with pytest.raises(TrustifyAuthError) as exc_info:
                client._fetch_token()

            assert "Invalid client secret" in exc_info.value.message
            client.close()

    def test_ensure_valid_token_refreshes_expired(self) -> None:
        """Set token_expiration to past, verify _fetch_token() is called."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        client = TrustifyClient(config)
        client._access_token = "old-token"
        client._token_expiration = time.monotonic() - 100

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            mock_post.return_value = httpx.Response(
                200,
                json={"access_token": "new-token", "expires_in": 300},
            )

            client._ensure_valid_token()

            assert client._access_token == "new-token"
            mock_post.assert_called_once()
            client.close()

    def test_ensure_valid_token_skips_if_valid(self) -> None:
        """Set token and future expiration, verify _fetch_token() NOT called."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        client = TrustifyClient(config)
        client._access_token = "valid-token"
        client._token_expiration = time.monotonic() + 3600

        with patch("slan_cuan.trustify.httpx.post") as mock_post:
            client._ensure_valid_token()

            mock_post.assert_not_called()
            client.close()


class TestTrustifyClientUpload:
    """Tests for SBOM upload operations."""

    def test_upload_sbom_success(self, tmp_path: Path) -> None:
        """Mock SSO and Trustify API, verify SBOMUploadResult fields."""
        sbom_file = tmp_path / "cyclonedx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            assert "api/v2/sbom" in str(request.url)
            assert request.headers["Authorization"] == "Bearer test-token"
            return httpx.Response(
                200,
                json={"id": "urn:uuid:test-123"},
            )

        transport = httpx.MockTransport(handler)
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        client = TrustifyClient(config)
        client._access_token = "test-token"
        client._token_expiration = time.monotonic() + 3600
        client._client = httpx.Client(
            transport=transport, base_url="https://trustify.example.com"
        )

        result = client.upload_sbom(sbom_file)

        assert result.file_path == str(sbom_file)
        assert result.file_size == len(sbom_file.read_bytes())
        assert result.sbom_urn == "urn:uuid:test-123"
        client.close()

    def test_upload_sbom_transient_retry(self, tmp_path: Path) -> None:
        """First 2 requests return 503, third returns 200, verify retry."""
        sbom_file = tmp_path / "cyclonedx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count <= 2:
                return httpx.Response(503, text="Service Unavailable")
            return httpx.Response(200, json={"id": "urn:uuid:success"})

        transport = httpx.MockTransport(handler)
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
            retries=3,
        )

        client = TrustifyClient(config)
        client._access_token = "test-token"
        client._token_expiration = time.monotonic() + 3600
        client._client = httpx.Client(
            transport=transport, base_url="https://trustify.example.com"
        )

        with patch("slan_cuan.trustify.time.sleep"):
            result = client.upload_sbom(sbom_file)

        assert attempt_count == 3
        assert result.sbom_urn == "urn:uuid:success"
        client.close()

    def test_upload_sbom_non_transient_failure(self, tmp_path: Path) -> None:
        """Return 403, verify TrustifyError raised immediately (not retried)."""
        sbom_file = tmp_path / "cyclonedx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            attempt_count += 1
            return httpx.Response(403, text="Forbidden")

        transport = httpx.MockTransport(handler)
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
            retries=3,
        )

        client = TrustifyClient(config)
        client._access_token = "test-token"
        client._token_expiration = time.monotonic() + 3600
        client._client = httpx.Client(
            transport=transport, base_url="https://trustify.example.com"
        )

        with pytest.raises(TrustifyError) as exc_info:
            client.upload_sbom(sbom_file)

        assert exc_info.value.status_code == 403
        assert "SBOM upload failed (403)" in exc_info.value.message
        assert attempt_count == 1
        client.close()

    def test_upload_sbom_connection_error_retry(self, tmp_path: Path) -> None:
        """Transport raises ConnectError for first attempt, succeeds on second."""
        sbom_file = tmp_path / "cyclonedx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count == 1:
                raise httpx.ConnectError("Connection refused")
            return httpx.Response(200, json={"id": "urn:uuid:retry-success"})

        transport = httpx.MockTransport(handler)
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
            retries=3,
        )

        client = TrustifyClient(config)
        client._access_token = "test-token"
        client._token_expiration = time.monotonic() + 3600
        client._client = httpx.Client(
            transport=transport, base_url="https://trustify.example.com"
        )

        with patch("slan_cuan.trustify.time.sleep"):
            result = client.upload_sbom(sbom_file)

        assert attempt_count == 2
        assert result.sbom_urn == "urn:uuid:retry-success"
        client.close()

    def test_upload_sbom_all_retries_exhausted(self, tmp_path: Path) -> None:
        """Always return 503, verify TrustifyError raised after max retries."""
        sbom_file = tmp_path / "cyclonedx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        attempt_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            attempt_count += 1
            return httpx.Response(503, text="Service Unavailable")

        transport = httpx.MockTransport(handler)
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
            retries=3,
        )

        client = TrustifyClient(config)
        client._access_token = "test-token"
        client._token_expiration = time.monotonic() + 3600
        client._client = httpx.Client(
            transport=transport, base_url="https://trustify.example.com"
        )

        with pytest.raises(TrustifyError) as exc_info:
            with patch("slan_cuan.trustify.time.sleep"):
                client.upload_sbom(sbom_file)

        assert attempt_count == 3
        assert "Transient error (503)" in exc_info.value.message
        client.close()

    def test_upload_sbom_response_truncation(self, tmp_path: Path) -> None:
        """Return 400 with long body, verify error message truncation."""
        sbom_file = tmp_path / "cyclonedx.json"
        sbom_file.write_text('{"bomFormat": "CycloneDX"}')

        long_body = "x" * 300

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text=long_body)

        transport = httpx.MockTransport(handler)
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )

        client = TrustifyClient(config)
        client._access_token = "test-token"
        client._token_expiration = time.monotonic() + 3600
        client._client = httpx.Client(
            transport=transport, base_url="https://trustify.example.com"
        )

        with pytest.raises(TrustifyError) as exc_info:
            client.upload_sbom(sbom_file)

        assert "... (truncated)" in exc_info.value.message
        client.close()


class TestTrustifyClientSSL:
    """Tests for TLS/SSL configuration."""

    @patch("slan_cuan.trustify.ssl.create_default_context")
    def test_ca_cert_creates_ssl_context(
        self, mock_create_ctx: Mock, tmp_path: Path
    ) -> None:
        """When ca_cert is set, an SSLContext is built from it."""
        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("PEM data")

        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
            ca_cert=ca_file,
        )
        client = TrustifyClient(config)

        mock_create_ctx.assert_called_once_with(cafile=str(ca_file))
        client.close()

    def test_ca_cert_invalid_raises_error(self, tmp_path: Path) -> None:
        """Malformed CA cert raises TrustifyError."""
        ca_file = tmp_path / "bad-ca.crt"
        ca_file.write_text("not a real certificate")

        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
            ca_cert=ca_file,
        )

        with pytest.raises(TrustifyError) as exc_info:
            TrustifyClient(config)

        assert "Failed to load CA certificate" in exc_info.value.message

    def test_ca_cert_ignored_when_insecure(self) -> None:
        """When verify_ssl=False, ca_cert is ignored."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=False,
            ca_cert=Path("/some/ca.crt"),
        )
        client = TrustifyClient(config)
        assert config.verify_ssl is False
        client.close()


class TestTrustifyClientClose:
    """Tests for client cleanup."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = TrustifyConfig(
            api_url="https://trustify.example.com",
            sso_token_url="https://sso.example.com/token",
            sso_client_id="client-id",
            sso_client_secret="client-secret",
            verify_ssl=True,
        )
        client = TrustifyClient(config)

        # Should not raise
        client.close()


class TestTrustifyError:
    """Tests for TrustifyError exception."""

    def test_trustify_error_attributes(self) -> None:
        """Verify message, status_code, response_body are preserved."""
        error = TrustifyError(
            message="Upload failed",
            status_code=500,
            response_body="Internal Server Error",
        )

        assert error.message == "Upload failed"
        assert error.status_code == 500
        assert error.response_body == "Internal Server Error"
        assert str(error) == "Upload failed"
