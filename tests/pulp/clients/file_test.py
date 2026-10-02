"""Tests for the Pulp File client (slan_cuan/pulp/clients/file.py)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp.clients.file import PulpFileClient
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig


def _file_content_handler(
    content_response: dict[str, object] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Create a handler for Pulp File content upload."""
    if content_response is None:
        content_response = {
            "pulp_href": "/api/v3/content/file/files/abc123/",
            "relative_path": "BUILD123/gav-index.osv.json",
            "sha256": "deadbeef" * 8,
        }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v3/content/file/files/" in url:
            return httpx.Response(200, json=content_response)
        return httpx.Response(404)

    return handler


class TestPulpFileClient:
    """Tests for PulpFileClient operations."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client.close()

    def test_upload_content_success(self, tmp_path: Path) -> None:
        """Single POST returns FileContentUnit with correct fields."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        handler = _file_content_handler()
        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
        )

        assert result.pulp_href == "/api/v3/content/file/files/abc123/"
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_async_task(self, tmp_path: Path) -> None:
        """Async 202 response polls task and fetches created resource."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        task_href = "/api/pulp/testdomain/api/v3/tasks/task-uuid/"
        content_href = "/api/v3/content/file/files/new123/"

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/api/v3/content/file/files/" in url and request.method == "POST":
                return httpx.Response(202, json={"task": task_href})
            if task_href in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [content_href],
                    },
                )
            if content_href in url:
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": content_href,
                        "relative_path": "BUILD123/gav-index.osv.json",
                        "sha256": "deadbeef" * 8,
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
        )

        assert result.pulp_href == content_href
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_async_task_with_repo_version_resource(
        self, tmp_path: Path
    ) -> None:
        """Async task creating repo version and content unit resolves content."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        task_href = "/api/pulp/testdomain/api/v3/tasks/task-uuid/"
        repo_ver_href = (
            "/api/pulp/testdomain/api/v3/repositories/file/file/uuid/versions/1/"
        )
        content_href = "/api/v3/content/file/files/new123/"

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/api/v3/content/file/files/" in url and request.method == "POST":
                return httpx.Response(202, json={"task": task_href})
            if task_href in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [repo_ver_href, content_href],
                    },
                )
            if content_href in url:
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": content_href,
                        "relative_path": "BUILD123/gav-index.osv.json",
                        "sha256": "deadbeef" * 8,
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
            repository_href="/api/pulp/testdomain/api/v3/repositories/file/file/uuid/",
        )

        assert result.pulp_href == content_href
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_async_task_no_resources(self, tmp_path: Path) -> None:
        """Async task that creates no resources raises PulpError."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        task_href = "/api/pulp/testdomain/api/v3/tasks/task-uuid/"

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/api/v3/content/file/files/" in url and request.method == "POST":
                return httpx.Response(202, json={"task": task_href})
            if task_href in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [],
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError, match="created no resources"):
            client.upload_content(
                test_file,
                "BUILD123/gav-index.osv.json",
                sha256="deadbeef" * 8,
            )

    def test_upload_content_url(self, tmp_path: Path) -> None:
        """Upload hits the File content API path."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "B/test.osv.json",
                    "sha256": "abc",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(test_file, "B/test.osv.json", sha256="abc")

        assert captured_url is not None
        assert "/api/pulp/testdomain/api/v3/content/file/files/" in captured_url

    def test_upload_content_multipart_fields(self, tmp_path: Path) -> None:
        """Verify form data includes relative_path and sha256."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        captured_body: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "B/test.osv.json",
                    "sha256": "abcdef",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(test_file, "B/test.osv.json", sha256="abcdef")

        assert captured_body is not None
        assert "relative_path" in captured_body
        assert "B/test.osv.json" in captured_body
        assert "sha256" in captured_body
        assert "abcdef" in captured_body

    def test_upload_content_error(self, tmp_path: Path) -> None:
        """Error response raises PulpError."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError, match="File upload failed"):
            client.upload_content(test_file, "B/test.osv.json", sha256="abc")

    def test_upload_content_domain_required(self, tmp_path: Path) -> None:
        """Missing domain raises PulpError."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")

        with pytest.raises(PulpError, match="Domain is required"):
            client.upload_content(test_file, "B/test.osv.json", sha256="abc")

    def test_resolve_repository_success(self) -> None:
        """Successful lookup returns pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/repositories/file/file/uuid/")}
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
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_repository("my-file-repo")
        assert href == "/api/v3/repositories/file/file/uuid/"

    def test_resolve_repository_not_found(self) -> None:
        """Empty results raises PulpError with 404."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError, match="not found"):
            client.resolve_repository("nonexistent-repo")

    def test_resolve_repository_url(self) -> None:
        """Verify the File repository API path is used."""
        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/repositories/file/file/uuid/")}
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_repository("my-file-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/repositories/file/file/" in captured_url
        assert "name=my-file-repo" in captured_url

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_success(self, mock_sleep: Mock) -> None:
        """Modify adds content units and returns ModifyResult."""

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "modify" in url:
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            if "tasks" in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [
                            "/api/v3/repositories/file/file/uuid/versions/1/"
                        ],
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/file/file/uuid/",
            ["/api/v3/content/file/files/abc/"],
        )

        assert result.content_units_added == 1
        assert result.state == "completed"
        assert result.repository_version is not None

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_create_publication_success(self, mock_sleep: Mock) -> None:
        """Publication returns the created publication href."""

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "publications" in url:
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/pub-task/"},
                )
            if "tasks" in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [
                            "/api/v3/publications/file/file/pub-uuid/"
                        ],
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.create_publication("/api/v3/repositories/file/file/uuid/")
        assert href == "/api/v3/publications/file/file/pub-uuid/"

    def test_create_publication_error(self) -> None:
        """Error response raises PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError, match="Publication creation failed"):
            client.create_publication("/api/v3/repositories/file/file/uuid/")

    def test_create_publication_requires_domain(self) -> None:
        """Missing domain raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")

        with pytest.raises(PulpError, match="Domain is required"):
            client.create_publication("/api/v3/repositories/file/file/uuid/")

    def test_resolve_distribution_success(self) -> None:
        """Successful lookup returns pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": (
                                "/api/v3/distributions/file/file/dist-uuid/"
                            )
                        }
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
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_distribution("my-file-repo")
        assert href == "/api/v3/distributions/file/file/dist-uuid/"

    def test_resolve_distribution_not_found(self) -> None:
        """Empty results raises PulpError with 404."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError, match="not found"):
            client.resolve_distribution("nonexistent")

    def test_resolve_distribution_url(self) -> None:
        """Verify the distribution API path is used."""
        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/distributions/file/file/uuid/")}
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_distribution("my-file-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/distributions/file/file/" in captured_url
        assert "name=my-file-repo" in captured_url

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_update_distribution_success(self, mock_sleep: Mock) -> None:
        """PATCH updates the distribution and polls the task."""
        captured_method: str | None = None
        captured_body: bytes | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_method, captured_body
            url = str(request.url)
            if "distributions" in url and request.method == "PATCH":
                captured_method = request.method
                captured_body = request.content
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/dist-task/"},
                )
            if "tasks" in url:
                return httpx.Response(
                    200, json={"state": "completed", "created_resources": []}
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
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.update_distribution(
            "/api/v3/distributions/file/file/dist-uuid/",
            "/api/v3/publications/file/file/pub-uuid/",
        )

        assert captured_method == "PATCH"
        assert captured_body is not None
        import json

        body = json.loads(captured_body)
        assert body == {
            "publication": "/api/v3/publications/file/file/pub-uuid/",
            "repository": "",
        }

    def test_update_distribution_error(self) -> None:
        """Error response on PATCH raises PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError, match="Distribution update failed"):
            client.update_distribution(
                "/api/v3/distributions/file/file/dist-uuid/",
                "/api/v3/publications/file/file/pub-uuid/",
            )

    # _request() verbose logging is base.py behavior; see
    # tests/pulp/clients/base_test.py::TestRequestLogging.
