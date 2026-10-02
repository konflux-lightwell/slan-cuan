"""Tests for Pulp exceptions (slan_cuan/pulp/exceptions.py)."""

from __future__ import annotations

from slan_cuan.pulp.exceptions import PulpError


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
