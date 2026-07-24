"""Shared HTTP request helpers for REST API clients."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import httpx

ERROR_BODY_MAX_LENGTH = 200


class HttpApiError(Exception):
    """Base exception for HTTP API failures."""

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


def create_ssl_context(
    ca_cert: Path | None,
    verify_ssl: bool,
    error_cls: type[HttpApiError],
) -> ssl.SSLContext | bool:
    """Build an SSL verification context from a CA certificate.

    Args:
        ca_cert: Path to a CA certificate file, or None.
        verify_ssl: Whether SSL verification is enabled.
        error_cls: Exception class to raise on failure.

    Returns:
        An SSLContext when ca_cert is provided and verify_ssl is True,
        otherwise the boolean verify_ssl value.

    Raises:
        error_cls: If the CA certificate cannot be loaded.

    """
    verify: ssl.SSLContext | bool = verify_ssl
    if verify and ca_cert is not None:
        try:
            verify = ssl.create_default_context(cafile=str(ca_cert))
            # Internal CAs may omit the "critical" flag on Basic
            # Constraints; Python 3.14+ rejects them by default.
            verify.verify_flags &= ~ssl.VERIFY_X509_STRICT
        except (ssl.SSLError, OSError) as e:
            raise error_cls(
                f"Failed to load CA certificate from {ca_cert}: {e}",
                status_code=0,
                response_body="",
            ) from e
    return verify


def raise_for_status(
    response: httpx.Response,
    operation: str,
    error_cls: type[HttpApiError],
) -> None:
    """Raise if the response has an HTTP error status.

    Args:
        response: The HTTP response to check.
        operation: Human-readable name for error messages.
        error_cls: Exception class to raise on failure.

    Raises:
        error_cls: If status_code >= 400.

    """
    if response.status_code >= 400:
        body = response.text
        summary = body[:ERROR_BODY_MAX_LENGTH]
        if len(body) > ERROR_BODY_MAX_LENGTH:
            summary += "... (truncated)"
        raise error_cls(
            f"{operation} failed ({response.status_code}): {summary}",
            status_code=response.status_code,
            response_body=body,
        )


def parse_json_dict(
    response: httpx.Response,
    operation: str,
    error_cls: type[HttpApiError],
) -> dict[str, object]:
    """Parse a JSON response body and validate it is a dict.

    Args:
        response: The HTTP response to parse.
        operation: Human-readable name for error messages.
        error_cls: Exception class to raise on failure.

    Returns:
        The parsed JSON object as a dict.

    Raises:
        error_cls: If the body is not valid JSON or not a dict.

    """
    try:
        data = response.json()
    except ValueError as e:
        raise error_cls(
            f"Failed to parse {operation} response: {e}",
            status_code=response.status_code,
            response_body=response.text,
        ) from e

    if not isinstance(data, dict):
        raise error_cls(
            f"{operation} returned non-dict response",
            status_code=response.status_code,
            response_body=response.text,
        )
    return data


def request(
    client: httpx.Client,
    method: str,
    url: str,
    operation: str,
    error_cls: type[HttpApiError],
    **kwargs: Any,
) -> httpx.Response:
    """Send an HTTP request with standardised error handling.

    Wraps ``client.request()`` to catch transport errors and check the
    response status, converting both into *error_cls* instances.

    Args:
        client: The httpx client to use.
        method: HTTP method (GET, POST, PATCH, ...).
        url: Request URL (absolute or relative to client base_url).
        operation: Human-readable name for error messages.
        error_cls: Exception class to raise on failure.
        **kwargs: Forwarded to ``client.request()``.

    Returns:
        The HTTP response (status < 400).

    Raises:
        error_cls: On transport errors or HTTP error status.

    """
    try:
        response = client.request(method, url, **kwargs)
    except httpx.ConnectError as e:
        raise error_cls(
            f"Connection failed: {e}",
            status_code=0,
            response_body="",
        ) from e
    except httpx.TimeoutException as e:
        raise error_cls(
            f"Request timed out: {e}",
            status_code=0,
            response_body="",
        ) from e

    raise_for_status(response, operation, error_cls)
    return response
