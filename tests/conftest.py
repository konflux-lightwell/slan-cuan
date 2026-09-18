"""Shared test configuration and fixtures."""

import sys
from unittest.mock import MagicMock

if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ImportError:
        _requests = MagicMock()

        class _RequestException(Exception):
            pass

        class _ConnectionError(_RequestException):
            pass

        _requests.exceptions.RequestException = _RequestException
        _requests.exceptions.ConnectionError = _ConnectionError
        sys.modules["requests"] = _requests

_krbticket = MagicMock()
sys.modules.setdefault("krbticket", _krbticket)

_requests_gssapi = MagicMock()
sys.modules.setdefault("requests_gssapi", _requests_gssapi)

sys.modules.setdefault("fath_cuan.osidb", MagicMock())
