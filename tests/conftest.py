"""Shared test configuration and fixtures."""

import sys
from unittest.mock import MagicMock

# Stub the novabucks package before any slan_cuan module is imported, so that
# ``from novabucks.utils.logs import setup_logging`` and similar imports resolve
# without the private dependency being installed.
_novabucks = MagicMock()
sys.modules.setdefault("novabucks", _novabucks)
sys.modules.setdefault("novabucks.utils", _novabucks.utils)
sys.modules.setdefault("novabucks.utils.logs", _novabucks.utils.logs)
sys.modules.setdefault("novabucks.workflows", _novabucks.workflows)
