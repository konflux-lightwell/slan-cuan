"""Pulp REST API exceptions."""

from slan_cuan.http import HttpApiError


class PulpError(HttpApiError):
    """Exception raised when a Pulp API call fails."""
