"""Pulp REST API clients and shared types."""

from slan_cuan.pulp.clients import PulpClientBase, PulpFileClient, PulpMavenClient
from slan_cuan.pulp.constants import (
    AUTH_TYPE_CERT,
    AUTH_TYPE_TBR,
    AUTH_TYPES,
    CONTENT_API_PATH_TEMPLATE,
    DEFAULT_TIMEOUT_SECONDS,
    FILE_CONTENT_API_PATH_TEMPLATE,
    FILE_DISTRIBUTION_API_PATH_TEMPLATE,
    FILE_REPO_API_PATH_TEMPLATE,
    MAVEN_DISTRIBUTION_API_PATH_TEMPLATE,
    METADATA_API_PATH_TEMPLATE,
    REPO_API_PATH_TEMPLATE,
    TASK_CANCEL_TIMEOUT_SECONDS,
    TASK_POLL_TIMEOUT_SECONDS,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import (
    ContentUnit,
    FileContentUnit,
    MavenDistribution,
    ModifyResult,
    PulpConfig,
)
from slan_cuan.pulp.tasks import (
    BlockerLookup,
    BlockerLookupStatus,
    PulpTaskPoller,
)

# Pulp CLI wrapper — additive, no REST change.
try:
    from slan_cuan.pulp.cli import (  # noqa: F401
        PULP_BIN,
        modify_file_repository,
        modify_python_repository,
        run_hosted_pulp,
        upload_file_content,
        upload_python_content,
    )
except ImportError:  # pragma: no cover — cli optional in some envs
    pass

__all__ = [
    "AUTH_TYPE_CERT",
    "AUTH_TYPE_TBR",
    "AUTH_TYPES",
    "BlockerLookup",
    "BlockerLookupStatus",
    "CONTENT_API_PATH_TEMPLATE",
    "ContentUnit",
    "DEFAULT_TIMEOUT_SECONDS",
    "FILE_CONTENT_API_PATH_TEMPLATE",
    "FILE_DISTRIBUTION_API_PATH_TEMPLATE",
    "FILE_REPO_API_PATH_TEMPLATE",
    "FileContentUnit",
    "METADATA_API_PATH_TEMPLATE",
    "MAVEN_DISTRIBUTION_API_PATH_TEMPLATE",
    "MavenDistribution",
    "ModifyResult",
    "PULP_BIN",
    "PulpClientBase",
    "PulpConfig",
    "PulpError",
    "PulpFileClient",
    "PulpMavenClient",
    "PulpTaskPoller",
    "REPO_API_PATH_TEMPLATE",
    "modify_file_repository",
    "modify_python_repository",
    "run_hosted_pulp",
    "upload_file_content",
    "upload_python_content",
    "TASK_CANCEL_TIMEOUT_SECONDS",
    "TASK_POLL_TIMEOUT_SECONDS",
]
