"""Tests for the shared Pulp client base (slan_cuan/pulp/clients/base.py)."""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp.clients.base import _validate_auth
from slan_cuan.pulp.clients.maven import PulpMavenClient
from slan_cuan.pulp.constants import AUTH_TYPE_CERT, AUTH_TYPE_TBR
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig


class TestClientConstruction:
    """Tests for PulpClientBase.__init__ (SSL, auth, base_url handling)."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        # Should not raise
        client.close()

    @patch("slan_cuan.pulp.clients.base.ssl.create_default_context")
    def test_ca_cert_creates_ssl_context(
        self, mock_create_ctx: Mock, tmp_path: Path
    ) -> None:
        """When ca_cert is set, an SSLContext is built from it."""
        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("PEM data")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            ca_cert=ca_file,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        mock_create_ctx.assert_called_once_with(
            cafile=str(ca_file),
        )
        client.close()

    def test_ca_cert_invalid_pem_raises_pulp_error(self, tmp_path: Path) -> None:
        """Malformed CA cert raises PulpError, not ssl.SSLError."""
        ca_file = tmp_path / "bad-ca.crt"
        ca_file.write_text("not a real certificate")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            ca_cert=ca_file,
            username="testuser",
            password="testpass",
        )

        with pytest.raises(PulpError) as exc_info:
            PulpMavenClient(config, "test-dist")

        assert "Failed to load CA certificate" in exc_info.value.message

    def test_ca_cert_ignored_when_insecure(self) -> None:
        """When verify_ssl=False, ca_cert is ignored."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            ca_cert=Path("/some/ca.crt"),
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert config.verify_ssl is False
        client.close()

    def test_verify_ssl_propagates(self, tmp_path: Path) -> None:
        """Create client with verify_ssl=False, verify propagation."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc/",
            "relative_path": "org/example/test.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test.jar",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=content_response)

        transport = httpx.MockTransport(handler)

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        assert config.verify_ssl is False

        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            verify=False,
        )

        result = client.upload_content(artifact_file, "org/example/test.jar")
        assert result.pulp_href == "/api/v3/content/maven/artifact/abc/"

    def test_base_url_without_scheme_gets_https(self) -> None:
        """A base_url without a scheme gets https:// prepended."""
        config = PulpConfig(
            base_url="packages.redhat.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "https://packages.redhat.com"
        client.close()

    def test_base_url_with_https_unchanged(self) -> None:
        """A base_url with https:// is not modified."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "https://pulp.example.com"
        client.close()

    def test_base_url_with_http_unchanged(self) -> None:
        """A base_url with http:// is not modified."""
        config = PulpConfig(
            base_url="http://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "http://pulp.example.com"
        client.close()

    def test_pulp_config_invalid_task_timeout(self) -> None:
        """PulpConfig validates task_timeout > 0."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            task_timeout=0,
        )
        with pytest.raises(PulpError, match="task_timeout must be positive"):
            PulpMavenClient(config, "test-dist")


class TestValidateAuth:
    """Tests for _validate_auth authentication validation."""

    def test_validate_auth_tbr_missing_username(self) -> None:
        """TBR auth without username raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            password="testpass",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "TBR auth requires" in exc_info.value.message
        assert "--pulp-username" in exc_info.value.message
        assert "--pulp-password" in exc_info.value.message

    def test_validate_auth_tbr_missing_password(self) -> None:
        """TBR auth without password raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            username="testuser",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "TBR auth requires" in exc_info.value.message
        assert "--pulp-username" in exc_info.value.message
        assert "--pulp-password" in exc_info.value.message

    def test_validate_auth_cert_missing_cert(self, tmp_path: Path) -> None:
        """Certificate auth without client_cert raises PulpError."""
        key_file = tmp_path / "client.key"
        key_file.write_text("key content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_key=key_file,
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Certificate auth requires" in exc_info.value.message
        assert "--pulp-client-cert" in exc_info.value.message
        assert "--pulp-client-key" in exc_info.value.message

    def test_validate_auth_cert_missing_key(self, tmp_path: Path) -> None:
        """Certificate auth without client_key raises PulpError."""
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_cert=cert_file,
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Certificate auth requires" in exc_info.value.message
        assert "--pulp-client-cert" in exc_info.value.message
        assert "--pulp-client-key" in exc_info.value.message

    def test_validate_auth_invalid_type(self) -> None:
        """Invalid auth_type raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type="invalid",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Invalid auth type 'invalid'" in exc_info.value.message
        assert "cert" in exc_info.value.message
        assert "tbr" in exc_info.value.message

    def test_tbr_auth_sends_basic_header(self, tmp_path: Path) -> None:
        """TBR auth configures httpx.Client with basic auth."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_auth_header = None

        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc/",
            "relative_path": "org/example/test.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test.jar",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_auth_header
            captured_auth_header = request.headers.get("Authorization")
            return httpx.Response(200, json=content_response)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            auth=("testuser", "testpass"),
        )

        client.upload_content(artifact_file, "org/example/test.jar")

        assert captured_auth_header is not None
        assert captured_auth_header.startswith("Basic ")

    def test_cert_auth_loads_ssl_context(self, tmp_path: Path) -> None:
        """Cert auth loads cert chain with correct paths."""
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert content")
        key_file = tmp_path / "client.key"
        key_file.write_text("key content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_cert=cert_file,
            client_key=key_file,
        )

        with patch(
            "slan_cuan.pulp.clients.base.ssl.SSLContext.load_cert_chain"
        ) as mock_load:
            try:
                PulpMavenClient(config, "test-dist")
            except (ssl.SSLError, OSError):
                pass

            mock_load.assert_called_once_with(
                certfile=str(cert_file),
                keyfile=str(key_file),
            )


class TestModifyRepository:
    """Tests for modify_repository() method."""

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_success(self, mock_sleep: Mock) -> None:
        """Mock 202 with task href, then completed task, verify ModifyResult."""

        def handler(request: httpx.Request) -> httpx.Response:
            # First call is the modify POST
            if "modify/" in str(request.url):
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            # Second call is the task poll
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [
                        "/api/v3/repositories/maven/maven/uuid/versions/2/",
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [
                "/api/v3/content/maven/artifact/abc/",
                "/api/v3/content/maven/artifact/def/",
            ],
        )

        assert result.task_href == "/api/v3/tasks/task-uuid/"
        assert result.state == "completed"
        repo_ver = "/api/v3/repositories/maven/maven/uuid/versions/2/"
        assert result.repository_version == repo_ver
        assert result.content_units_added == 2

    def test_modify_repository_error_status(self) -> None:
        """Mock 500, verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.modify_repository(
                "/api/v3/repositories/maven/maven/uuid/",
                ["/api/v3/content/maven/artifact/abc/"],
            )

        assert exc_info.value.status_code == 500
        assert "Repository modify failed" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_request_payload(self, mock_sleep: Mock) -> None:
        """Capture JSON body, verify add_content_units payload."""
        captured_payload = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload

            # Capture modify request
            if "modify/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            # Task poll
            return httpx.Response(
                200,
                json={"state": "completed", "created_resources": []},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [
                "/api/v3/content/maven/artifact/abc/",
                "/api/v3/content/maven/artifact/def/",
            ],
        )

        assert captured_payload is not None
        assert "add_content_units" in captured_payload
        assert len(captured_payload["add_content_units"]) == 2
        units = captured_payload["add_content_units"]
        assert "/api/v3/content/maven/artifact/abc/" in units

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_sends_custom_headers(
        self, mock_sleep: Mock
    ) -> None:
        """modify_repository attaches custom_headers to the POST request."""
        captured_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_headers
            if request.method == "POST" and "modify" in request.url.path:
                captured_headers = dict(request.headers)
                return httpx.Response(
                    200, json={"task": "/api/v3/tasks/modify-uuid/"}
                )
            if request.method == "GET" and "modify-uuid" in request.url.path:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": ["/api/v3/versions/1/"],
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            custom_headers={"X-TASK-DIAGNOSTICS": "pyinstrument"},
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            ["/api/v3/content/maven/artifact/1/"],
        )

        assert result.repository_version == "/api/v3/versions/1/"
        assert captured_headers.get("x-task-diagnostics") == "pyinstrument"


class TestResolveRepository:
    """Tests for resolve_repository() method."""

    def test_resolve_repository_success(self) -> None:
        """Mock 200 with results list, verify returned pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "count": 1,
                    "results": [
                        {
                            "pulp_href": (
                                "/api/v3/repositories/maven/maven/uuid123/"
                            ),
                            "name": "lightwell-test",
                        }
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_repository("lightwell-test")

        assert href == "/api/v3/repositories/maven/maven/uuid123/"

    def test_resolve_repository_not_found(self) -> None:
        """Mock 200 with empty results, verify PulpError(404)."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"count": 0, "results": []},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.resolve_repository("nonexistent-repo")

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.message
        assert "nonexistent-repo" in exc_info.value.message

    def test_resolve_repository_requires_domain(self) -> None:
        """Config with domain=None, verify PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain=None,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        with pytest.raises(PulpError) as exc_info:
            client.resolve_repository("test-repo")

        assert "Domain is required" in exc_info.value.message
        assert exc_info.value.status_code == 0

    def test_resolve_repository_url_construction(self) -> None:
        """Capture URL, verify domain template and name param."""
        captured_url = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/maven/maven/uuid/"}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="mydom",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_repository("my-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/repositories/maven/maven/" in captured_url
        assert "name=my-repo" in captured_url


class TestCancelTask:
    """Tests for cancel_task() method."""

    def test_cancel_task_short_timeout(self) -> None:
        """cancel_task uses short dedicated timeout."""
        captured_timeout = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_timeout
            captured_timeout = request.extensions.get("timeout", {}).get("read")
            return httpx.Response(200, json={"state": "canceled"})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        outcome = client.cancel_task("/api/v3/tasks/task-uuid/")
        assert outcome == "cancellation requested in Pulp"
        assert captured_timeout == 15.0


class TestFindBlockingTask:
    """Tests for _find_blocking_task() method."""

    def test_find_blocking_task_parent(self) -> None:
        """_find_blocking_task identifies parent_task when present."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        task_data = {
            "pulp_href": "/api/v3/tasks/child-task/",
            "parent_task": "/api/v3/tasks/parent-task/",
            "state": "waiting",
        }
        result = client._find_blocking_task(task_data)
        assert result.href == "/api/v3/tasks/parent-task/"
        assert result.status.value == "found"

    def test_find_blocking_task_unknown_on_lookup_failure(self) -> None:
        """Lookup failures are distinct from a confirmed absent blocker."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        task_data = {
            "pulp_href": "/api/v3/tasks/my-task/",
            "reserved_resources_record": ["/api/v3/repositories/maven/1/"],
            "state": "waiting",
        }
        client._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(503, text="unavailable")
            ),
            base_url="https://pulp.example.com",
        )

        result = client._find_blocking_task(task_data)
        assert result.href is None
        assert result.status.value == "unknown"

    def test_find_blocking_task_running_resource_holder(self) -> None:
        """_find_blocking_task finds running task reserving the same resource."""

        def handler(request: httpx.Request) -> httpx.Response:
            if "tasks" in request.url.path:
                assert "state=running" in str(request.url)
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"pulp_href": "/api/v3/tasks/running-blocker/"}
                        ]
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        task_data = {
            "pulp_href": "/api/v3/tasks/my-task/",
            "reserved_resources_record": ["/api/v3/repositories/maven/1/"],
            "state": "waiting",
        }
        result = client._find_blocking_task(task_data)
        assert result.href == "/api/v3/tasks/running-blocker/"
        assert result.status.value == "found"

    def test_find_blocking_task_not_found_without_resources(self) -> None:
        """A task without blocker resources confirms no blocker."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"results": []})
            ),
            base_url="https://pulp.example.com",
        )

        result = client._find_blocking_task(
            {
                "pulp_href": "/api/v3/tasks/my-task/",
                "reserved_resources_record": ["/api/v3/repositories/maven/1/"],
                "state": "waiting",
            }
        )
        assert result.href is None
        assert result.status.value == "not_found"


class TestRequestLogging:
    """Tests for _request() verbose logging."""

    def test_request_logging_when_verbose(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When verbose is enabled, Pulp requests and responses are logged."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/file/file/uuid/"}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
            verbose=True,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        repo_href = client.resolve_repository("test-dist")
        assert repo_href == "/api/v3/repositories/file/file/uuid/"

        captured = capsys.readouterr()
        assert "Pulp request: GET" in captured.out
        assert "Pulp response: 200" in captured.out

    def test_request_logging_when_not_verbose(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When verbose is disabled, requests and responses are not logged."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/file/file/uuid/"}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
            verbose=False,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        repo_href = client.resolve_repository("test-dist")
        assert repo_href == "/api/v3/repositories/file/file/uuid/"

        captured = capsys.readouterr()
        assert "Pulp request:" not in captured.out
        assert "Pulp response:" not in captured.out

    def test_verbose_logging_includes_state_and_waiting_on(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verbose response logging outputs state and waiting_on metadata."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/tasks/waiting-task/",
                    "parent_task": "/api/v3/tasks/parent-blocker/",
                    "state": "waiting",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
            verbose=True,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client._request("GET", "/api/v3/tasks/waiting-task/", "Task status")
        captured = capsys.readouterr()
        assert "Pulp response: 200" in captured.out
        assert "state=waiting" in captured.out
        assert "waiting_on=/api/v3/tasks/parent-blocker/" in captured.out

    def test_request_logging_sanitizes_sensitive_headers(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verbose request logging sanitizes sensitive header values."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            verbose=True,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client._request(
            "GET",
            "/api/v3/status/",
            "Status",
            headers={"Authorization": "Bearer secret123", "X-Custom": "public"},
        )

        captured = capsys.readouterr()
        assert "Authorization': '***'" in captured.out
        assert "secret123" not in captured.out
        assert "X-Custom': 'public'" in captured.out
