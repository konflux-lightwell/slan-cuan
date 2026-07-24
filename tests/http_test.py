"""Tests for shared HTTP helpers (slan_cuan/http.py)."""

from __future__ import annotations

import ssl
from pathlib import Path

import httpx
import pytest

from slan_cuan.http import (
    HttpApiError,
    create_ssl_context,
    parse_json_dict,
    raise_for_status,
    request,
)


class _TestError(HttpApiError):
    """Concrete subclass for testing error_cls dispatch."""


class TestHttpApiError:
    """Tests for HttpApiError base exception."""

    def test_attributes_preserved(self) -> None:
        """Verify message, status_code, response_body are stored."""
        error = HttpApiError(
            message="something broke",
            status_code=502,
            response_body="Bad Gateway",
        )
        assert error.message == "something broke"
        assert error.status_code == 502
        assert error.response_body == "Bad Gateway"
        assert str(error) == "something broke"

    def test_subclass_is_catchable_as_base(self) -> None:
        """A subclass instance is caught by except HttpApiError."""
        with pytest.raises(HttpApiError):
            raise _TestError("fail", status_code=500, response_body="")


class TestCreateSslContext:
    """Tests for create_ssl_context()."""

    def test_returns_bool_when_no_ca_cert(self) -> None:
        """No ca_cert returns verify_ssl unchanged."""
        result = create_ssl_context(None, True, _TestError)
        assert result is True

    def test_returns_false_when_insecure(self) -> None:
        """verify_ssl=False returns False even with ca_cert."""
        result = create_ssl_context(Path("/fake.crt"), False, _TestError)
        assert result is False

    def test_returns_ssl_context_with_valid_ca(self, tmp_path: Path) -> None:
        """Valid CA cert produces an SSLContext."""
        from unittest.mock import patch

        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("PEM data")

        with patch("slan_cuan.http.ssl.create_default_context") as mock_ctx:
            result = create_ssl_context(ca_file, True, _TestError)

        mock_ctx.assert_called_once_with(cafile=str(ca_file))
        assert (
            isinstance(result, ssl.SSLContext) or result is mock_ctx.return_value
        )

    def test_invalid_ca_raises_error_cls(self, tmp_path: Path) -> None:
        """Malformed CA cert raises the provided error_cls."""
        ca_file = tmp_path / "bad.crt"
        ca_file.write_text("not a certificate")

        with pytest.raises(_TestError) as exc_info:
            create_ssl_context(ca_file, True, _TestError)

        assert "Failed to load CA certificate" in exc_info.value.message
        assert exc_info.value.status_code == 0


class TestRaiseForStatus:
    """Tests for raise_for_status()."""

    def test_no_raise_on_success(self) -> None:
        """Status 200 does not raise."""
        response = httpx.Response(200, text="OK")
        raise_for_status(response, "Test op", _TestError)

    def test_no_raise_on_redirect(self) -> None:
        """Status 301 does not raise."""
        response = httpx.Response(301, text="Moved")
        raise_for_status(response, "Test op", _TestError)

    def test_raises_on_400(self) -> None:
        """Status 400 raises with operation in message."""
        response = httpx.Response(400, text="Bad Request")
        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Upload", _TestError)

        assert "Upload failed (400)" in exc_info.value.message
        assert exc_info.value.status_code == 400
        assert exc_info.value.response_body == "Bad Request"

    def test_raises_on_500(self) -> None:
        """Status 500 raises with status in message."""
        response = httpx.Response(500, text="Internal Server Error")
        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Fetch", _TestError)

        assert exc_info.value.status_code == 500

    def test_truncates_long_body(self) -> None:
        """Body longer than ERROR_BODY_MAX_LENGTH is truncated."""
        long_body = "x" * 300
        response = httpx.Response(500, text=long_body)

        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Op", _TestError)

        assert "... (truncated)" in exc_info.value.message
        assert exc_info.value.response_body == long_body

    def test_short_body_not_truncated(self) -> None:
        """Body shorter than limit is not truncated."""
        short_body = "short error"
        response = httpx.Response(500, text=short_body)

        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Op", _TestError)

        assert "... (truncated)" not in exc_info.value.message
        assert short_body in exc_info.value.message


class TestParseJsonDict:
    """Tests for parse_json_dict()."""

    def test_returns_dict_on_valid_json(self) -> None:
        """Valid JSON object returns dict."""
        response = httpx.Response(200, json={"key": "value"})
        result = parse_json_dict(response, "Test", _TestError)
        assert result == {"key": "value"}

    def test_raises_on_non_dict(self) -> None:
        """JSON array raises error."""
        response = httpx.Response(200, json=[1, 2, 3])
        with pytest.raises(_TestError) as exc_info:
            parse_json_dict(response, "Test", _TestError)

        assert "non-dict response" in exc_info.value.message

    def test_raises_on_invalid_json(self) -> None:
        """Non-JSON body raises error."""
        response = httpx.Response(
            200,
            text="not json",
            headers={"content-type": "application/json"},
        )
        with pytest.raises(_TestError) as exc_info:
            parse_json_dict(response, "Parse", _TestError)

        assert "Failed to parse" in exc_info.value.message


class TestRequest:
    """Tests for request()."""

    def test_success_returns_response(self) -> None:
        """Successful GET returns the response."""
        transport = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"ok": True})
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        response = request(client, "GET", "/test", "Fetch", _TestError)
        assert response.status_code == 200
        client.close()

    def test_raises_on_connect_error(self) -> None:
        """ConnectError is wrapped in error_cls."""
        transport = httpx.MockTransport(
            lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/test", "Fetch", _TestError)

        assert "Connection failed" in exc_info.value.message
        assert exc_info.value.status_code == 0
        client.close()

    def test_raises_on_timeout(self) -> None:
        """TimeoutException is wrapped in error_cls."""
        transport = httpx.MockTransport(
            lambda req: (_ for _ in ()).throw(httpx.TimeoutException("timed out"))
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/test", "Fetch", _TestError)

        assert "Request timed out" in exc_info.value.message
        assert exc_info.value.status_code == 0
        client.close()

    def test_raises_on_http_error(self) -> None:
        """HTTP 500 is caught by raise_for_status inside request()."""
        transport = httpx.MockTransport(
            lambda req: httpx.Response(500, text="Server Error")
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/test", "Fetch", _TestError)

        assert exc_info.value.status_code == 500
        client.close()

    def test_passes_kwargs_through(self) -> None:
        """Keyword args (json, params, etc.) reach the transport."""
        captured_body = None

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = req.content
            return httpx.Response(200, text="ok")

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport, base_url="https://example.com")
        request(
            client,
            "POST",
            "/test",
            "Send",
            _TestError,
            json={"key": "value"},
        )
        assert captured_body is not None
        assert b"key" in captured_body
        client.close()
