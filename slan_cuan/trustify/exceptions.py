"""Trustify REST API exceptions."""

from slan_cuan.http import HttpApiError


class TrustifyError(HttpApiError):
    """Exception raised when a Trustify API call fails."""


class TrustifyAuthError(TrustifyError):
    """Exception raised when OIDC authentication fails."""
