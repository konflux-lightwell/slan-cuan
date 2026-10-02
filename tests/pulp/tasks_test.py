"""Tests for Pulp task polling (slan_cuan/pulp/tasks.py)."""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp.clients.maven import PulpMavenClient
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig
from slan_cuan.pulp.tasks import PulpTaskPoller


class TestPollTask:
    """Tests for poll_task() method, backed by PulpTaskPoller."""

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_immediate_completion(self, mock_sleep: Mock) -> None:
        """Task returns 'completed' on first poll."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [
                        "/api/v3/repositories/maven/maven/uuid/versions/1/",
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

        result = client.poll_task("/api/v3/tasks/task-uuid/")

        assert result["state"] == "completed"
        mock_sleep.assert_not_called()

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_eventual_completion(self, mock_sleep: Mock) -> None:
        """First poll 'running', second poll 'completed'."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return httpx.Response(200, json={"state": "running"})
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [],
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

        result = client.poll_task("/api/v3/tasks/task-uuid/")

        assert result["state"] == "completed"
        assert call_count == 2
        mock_sleep.assert_called()

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_failed(self, mock_sleep: Mock) -> None:
        """Task returns 'failed' with error details, verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "failed",
                    "error": {"description": "Content validation failed"},
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

        with pytest.raises(PulpError) as exc_info:
            client.poll_task("/api/v3/tasks/task-uuid/")

        assert "Task failed" in exc_info.value.message
        assert "Content validation failed" in exc_info.value.message
        assert "/api/v3/tasks/task-uuid/" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_failed_with_traceback(self, mock_sleep: Mock) -> None:
        """Task failure includes traceback from Pulp error response."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "failed",
                    "error": {
                        "description": "Content validation failed",
                        "traceback": "Traceback (most recent call last):\n"
                        '  File "pulp", line 42\n'
                        "ValueError: duplicate key",
                    },
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

        with pytest.raises(PulpError) as exc_info:
            client.poll_task("/api/v3/tasks/task-uuid/")

        assert "Task failed" in exc_info.value.message
        assert "Traceback:" in exc_info.value.message
        assert "duplicate key" in exc_info.value.message
        assert "/api/v3/tasks/task-uuid/" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_canceled(self, mock_sleep: Mock) -> None:
        """Task returns 'canceled', verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"state": "canceled", "error": {}},
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

        with pytest.raises(PulpError) as exc_info:
            client.poll_task("/api/v3/tasks/task-uuid/")

        assert "Task canceled" in exc_info.value.message
        assert "/api/v3/tasks/task-uuid/" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout(self, mock_sleep: Mock) -> None:
        """Use very short timeout, verify PulpError with 'timed out'."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PATCH":
                return httpx.Response(200, json={"state": "canceled"})
            return httpx.Response(200, json={"state": "waiting"})

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
            client.poll_task(
                "/api/v3/tasks/task-uuid/",
                timeout=0.01,
            )

        assert "timed out" in exc_info.value.message
        assert "(cancellation requested in Pulp)" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout_cancels_task_in_pulp(
        self, mock_sleep: Mock
    ) -> None:
        """Verify PATCH with state=canceled is sent on timeout."""
        patch_called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal patch_called
            if request.method == "PATCH":
                patch_called = True
                assert request.url.path == "/api/v3/tasks/task-uuid/"
                data = json.loads(request.read())
                assert data == {"state": "canceled"}
                return httpx.Response(200, json={"state": "canceled"})
            return httpx.Response(200, json={"state": "waiting"})

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
            client.poll_task(
                "/api/v3/tasks/task-uuid/",
                timeout=0.01,
            )

        assert patch_called is True
        assert "timed out" in exc_info.value.message
        assert "(cancellation requested in Pulp)" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_backoff_and_jitter(self, mock_sleep: Mock) -> None:
        """Verify backoff increases sleep duration with jitter within range."""
        polls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal polls
            polls += 1
            if polls < 4:
                return httpx.Response(200, json={"state": "waiting"})
            return httpx.Response(
                200, json={"state": "completed", "created_resources": []}
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

        client.poll_task("/api/v3/tasks/task-uuid/")

        assert mock_sleep.call_count == 3
        sleep_durations = [call.args[0] for call in mock_sleep.call_args_list]
        # Attempt 1: base 2.0, jitter 0.2 (0.4) -> [1.6, 2.4]
        assert 1.59 <= sleep_durations[0] <= 2.41
        # Attempt 2: base 3.0, jitter 0.2 (0.6) -> [2.4, 3.6]
        assert 2.39 <= sleep_durations[1] <= 3.61
        # Attempt 3: base 4.5, jitter 0.2 (0.9) -> [3.6, 5.4]
        assert 3.59 <= sleep_durations[2] <= 5.41

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout_cancellation_conflict_409(
        self, mock_sleep: Mock
    ) -> None:
        """Pulp 409 Conflict during cancel is reported in timeout error."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PATCH":
                return httpx.Response(409, text="Task already finished")
            return httpx.Response(200, json={"state": "waiting"})

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
            client.poll_task(
                "/api/v3/tasks/task-uuid/",
                timeout=0.01,
            )

        assert "timed out" in exc_info.value.message
        assert "409 Conflict" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout_cancellation_error_500(
        self, mock_sleep: Mock
    ) -> None:
        """Pulp 500 error during cancel is safely recorded without crashing."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PATCH":
                return httpx.Response(500, text="Internal Server Error")
            return httpx.Response(200, json={"state": "waiting"})

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
            client.poll_task(
                "/api/v3/tasks/task-uuid/",
                timeout=0.01,
            )

        assert "timed out" in exc_info.value.message
        assert "cancellation attempt failed: HTTP 500" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout_status_check_completed(
        self, mock_sleep: Mock
    ) -> None:
        """When timeout expires, fresh check finding completed returns cleanly."""
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(200, json={"state": "waiting"})
            # Second call is the timeout re-check
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": ["/api/v3/versions/1/"],
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

        result = client.poll_task("/api/v3/tasks/task-uuid/", timeout=0.01)
        assert result.get("state") == "completed"
        assert result.get("created_resources") == ["/api/v3/versions/1/"]

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_resets_deadline_on_transition_to_running(
        self, mock_sleep: Mock
    ) -> None:
        """When deadline expires, discovering running resets deadline."""
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                # Initial poll: waiting
                return httpx.Response(200, json={"state": "waiting"})
            if calls == 2:
                # Deadline check: transitioned to running -> deadline reset!
                return httpx.Response(200, json={"state": "running"})
            if calls == 3:
                # Poll under new deadline: running
                return httpx.Response(200, json={"state": "running"})
            # Completes before second deadline expires
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": ["/api/v3/versions/2/"],
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

        result = client.poll_task("/api/v3/tasks/task-uuid/", timeout=0.01)
        assert result.get("state") == "completed"
        assert calls >= 4

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout_skips_cancellation_when_running(
        self, mock_sleep: Mock
    ) -> None:
        """When timeout expires while running, cancellation is skipped."""
        patch_called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal patch_called
            if request.method == "PATCH":
                patch_called = True
                return httpx.Response(200, json={"state": "canceled"})
            return httpx.Response(200, json={"state": "running"})

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
            client.poll_task("/api/v3/tasks/task-uuid/", timeout=0.01)

        assert patch_called is False
        assert "timed out" in exc_info.value.message
        assert "(state: running)" in exc_info.value.message
        assert (
            "(cancellation skipped: task state is running)"
            in exc_info.value.message
        )

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_canceling_state_is_nonterminal(
        self, mock_sleep: Mock
    ) -> None:
        """Task in 'canceling' state is polled until completed or canceled."""
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(200, json={"state": "canceling"})
            return httpx.Response(200, json={"state": "canceled", "error": {}})

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
            client.poll_task("/api/v3/tasks/task-uuid/")

        assert calls == 2
        assert "Task canceled" in exc_info.value.message

    def test_poll_task_parameter_validation(self) -> None:
        """poll_task validates input timeout fail-fast."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        with pytest.raises(ValueError, match="timeout must be positive"):
            client.poll_task("/api/v3/tasks/x/", timeout=0)


class TestBlockerTracking:
    """Tests for PulpTaskPoller's deadline reset on blocker changes."""

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_resets_deadline_on_blocker_change(
        self, mock_sleep: Mock
    ) -> None:
        """poll_task resets wait deadline when blocking task changes."""
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                # First poll: waiting on blocker 1
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": "/api/v3/tasks/my-task/",
                        "parent_task": "/api/v3/tasks/blocker-1/",
                        "state": "waiting",
                    },
                )
            if calls == 2:
                # Deadline check: blocker changed to blocker 2 -> resets deadline!
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": "/api/v3/tasks/my-task/",
                        "parent_task": "/api/v3/tasks/blocker-2/",
                        "state": "waiting",
                    },
                )
            if calls == 3:
                # Next poll under reset deadline: completed
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": "/api/v3/tasks/my-task/",
                        "state": "completed",
                        "created_resources": [],
                    },
                )
            return httpx.Response(200, json={"state": "completed"})

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

        result = client.poll_task("/api/v3/tasks/my-task/", timeout=0.01)
        assert result.get("state") == "completed"
        assert calls >= 3

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_timeout_includes_waiting_on(
        self, mock_sleep: Mock
    ) -> None:
        """poll_task timeout error mentions the blocking task."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PATCH":
                return httpx.Response(200, json={"state": "canceled"})
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/tasks/my-task/",
                    "parent_task": "/api/v3/tasks/stuck-blocker/",
                    "state": "waiting",
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

        with pytest.raises(PulpError) as exc_info:
            client.poll_task("/api/v3/tasks/my-task/", timeout=0.01)

        assert "waiting, waiting on: /api/v3/tasks/stuck-blocker/" in str(
            exc_info.value
        )
        assert "cancellation requested in Pulp" in str(exc_info.value)

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_network_error_on_recheck_does_not_reset_deadline(
        self, mock_sleep: Mock
    ) -> None:
        """Network error on timeout status re-check does not extend deadline."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "PATCH":
                return httpx.Response(200, json={"state": "canceled"})
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/tasks/my-task/",
                    "parent_task": "/api/v3/tasks/blocker-1/",
                    "state": "waiting",
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

        with patch.object(
            client,
            "_check_task_status",
            side_effect=PulpError("Connection refused", 0, ""),
        ):
            with pytest.raises(PulpError) as exc_info:
                client.poll_task("/api/v3/tasks/my-task/", timeout=0.01)

        assert "timed out after 0.01s" in str(exc_info.value)
        assert "cancellation requested in Pulp" in str(exc_info.value)

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_poll_task_exceeds_max_total_timeout(self, mock_sleep: Mock) -> None:
        """Wall-clock ceiling terminates polling despite blocker changes."""
        counter = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal counter
            if request.method == "PATCH":
                return httpx.Response(200, json={"state": "canceled"})
            counter += 1
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/tasks/my-task/",
                    "parent_task": f"/api/v3/tasks/churning-blocker-{counter}/",
                    "state": "waiting",
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

        with pytest.raises(PulpError) as exc_info:
            # timeout=10s per blocker, but max_total_timeout=0.01s ceiling
            client.poll_task(
                "/api/v3/tasks/my-task/",
                timeout=10.0,
                max_total_timeout=0.01,
            )

        assert "exceeded maximum total wall-clock time of 0.01s" in str(
            exc_info.value
        )
        assert "cancellation requested in Pulp" in str(exc_info.value)


class TestPulpTaskPollerInternals:
    """Direct unit tests for PulpTaskPoller internals."""

    def test_calculate_sleep_jitter_on_remaining_clamp(self) -> None:
        """_calculate_sleep retains jitter when bounded by remaining time."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        poller = PulpTaskPoller(client, "/api/v3/tasks/t1/", timeout=60.0)
        poller.current_interval = 20.0

        samples = [poller._calculate_sleep(remaining=5.0) for _ in range(50)]
        assert all(0.1 <= s <= 5.0 for s in samples)
        # Verify samples are varied (jittered), not all identical to 5.0
        assert len(set(samples)) > 1

    def test_poll_task_logs_profile_artifact_nested(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """poll_task logs profiler links from nested structures."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [],
                    "extra_data": {
                        "pyinstrument_profile": "/pulp/nested/profile.html"
                    },
                },
            )

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

        task_data = client.poll_task("/api/v3/tasks/task-uuid/")
        assert task_data["state"] == "completed"

        captured = capsys.readouterr()
        assert (
            "Pulp task profile (pyinstrument_profile): /pulp/nested/profile.html"
            in captured.out
        )
