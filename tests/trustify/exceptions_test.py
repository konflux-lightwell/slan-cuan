"""Tests for Trustify exceptions (slan_cuan/trustify/exceptions.py)."""

from __future__ import annotations

from slan_cuan.trustify.exceptions import TrustifyError


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
