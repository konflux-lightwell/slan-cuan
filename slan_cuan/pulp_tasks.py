"""State-aware polling for asynchronous Pulp tasks."""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from typing import Any

import click

from slan_cuan.http import parse_json_dict

TASK_POLL_INITIAL_INTERVAL_SECONDS = 2.0
TASK_POLL_MAX_INTERVAL_SECONDS = 30.0
TASK_POLL_BACKOFF_FACTOR = 1.5
TASK_POLL_JITTER_FACTOR = 0.2
TASK_POLL_TIMEOUT_SECONDS = 1800.0
DEFAULT_TIMEOUT_SECONDS = 300.0


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PulpTaskPoller:
    """State machine and polling manager for an asynchronous Pulp task."""

    def __init__(
        self,
        client: Any,
        task_href: str,
        timeout: float | None = None,
        max_total_timeout: float | None = None,
        error_cls: type[Exception] = Exception,
    ) -> None:
        """Initialize the poller and its per-state and absolute deadlines."""
        self._client = client
        self._error_cls = error_cls
        self.task_href = task_href

        if timeout is None:
            timeout = client._config.task_timeout
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        self.timeout = timeout

        if max_total_timeout is None:
            max_total_timeout = client._config.max_total_task_timeout
            if max_total_timeout is None:
                max_total_timeout = 2.0 * timeout
        if max_total_timeout <= 0:
            raise ValueError(
                f"max_total_timeout must be positive, got {max_total_timeout}"
            )
        self.max_total_timeout = max_total_timeout

        self.overall_start = time.monotonic()
        self.absolute_deadline = self.overall_start + self.max_total_timeout
        self.start = self.overall_start
        self.deadline = self.start + self.timeout

        self.current_interval = TASK_POLL_INITIAL_INTERVAL_SECONDS
        self.current_state = ""
        self.current_waiting_on: str | None = None
        self.last_response_text = ""

    def _transition_to(
        self,
        new_state: str,
        new_waiting_on: str | None,
        text: str,
    ) -> None:
        self.current_state = new_state
        self.current_waiting_on = new_waiting_on
        self.last_response_text = text
        self.start = time.monotonic()
        self.deadline = self.start + self.timeout
        self.current_interval = TASK_POLL_INITIAL_INTERVAL_SECONDS
        if self._client._config.verbose:
            click.echo(
                f"[{_utc_timestamp()}]  Pulp task {self.task_href} "
                f"transitioned to '{new_state}'; "
                f"resetting wait deadline for {self.timeout}s"
            )

    def _blocker_changed(
        self,
        new_waiting_on: str,
        text: str,
    ) -> None:
        old = self.current_waiting_on
        self.current_waiting_on = new_waiting_on
        self.last_response_text = text
        self.start = time.monotonic()
        self.deadline = self.start + self.timeout
        self.current_interval = TASK_POLL_INITIAL_INTERVAL_SECONDS
        if self._client._config.verbose:
            click.echo(
                f"[{_utc_timestamp()}]  Pulp task {self.task_href} "
                f"waiting blocker changed: {old} -> {new_waiting_on}; "
                f"resetting wait deadline for {self.timeout}s"
            )

    def _calculate_sleep(self, remaining: float) -> float:
        """Compute sleep duration with exponential backoff and jitter.

        Clamps sleep to remaining deadline time while preserving jitter
        to avoid deterministic thundering-herd synchronizations.
        """
        target_interval = min(self.current_interval, remaining)
        jitter = target_interval * TASK_POLL_JITTER_FACTOR
        min_sleep = max(0.1, target_interval - jitter)
        max_sleep = min(remaining, target_interval + jitter)
        if max_sleep <= min_sleep:
            return min(max(0.1, remaining), min_sleep)
        return random.uniform(min_sleep, max_sleep)

    def poll(self) -> dict[str, object]:
        """Execute the polling loop until task completion or timeout."""
        while True:
            now = time.monotonic()
            remaining_state = self.deadline - now
            remaining_total = self.absolute_deadline - now
            remaining = min(remaining_state, remaining_total)

            if remaining <= 0:
                is_total_timeout = remaining_total <= 0
                req_timeout = min(DEFAULT_TIMEOUT_SECONDS, 10.0)
                try:
                    fresh_data, fresh_state, fresh_text = (
                        self._client._check_task_status(
                            self.task_href, req_timeout
                        )
                    )
                except Exception:
                    fresh_data, fresh_state, fresh_text = (
                        None,
                        self.current_state,
                        self.last_response_text,
                    )

                if fresh_state == "completed" and fresh_data is not None:
                    if self._client._config.verbose:
                        created = fresh_data.get("created_resources", [])
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task completed: "
                            f"{self.task_href} (created_resources={created})"
                        )
                    return fresh_data

                fresh_waiting_on = (
                    self._client._find_blocking_task(fresh_data)
                    if fresh_state == "waiting" and fresh_data is not None
                    else None
                )

                if (
                    not is_total_timeout
                    and self.current_state
                    and fresh_state != self.current_state
                ):
                    self._transition_to(
                        fresh_state, fresh_waiting_on, fresh_text
                    )
                    continue

                if (
                    not is_total_timeout
                    and self.current_state == "waiting"
                    and fresh_state == "waiting"
                    and fresh_data is not None
                    and self.current_waiting_on is not None
                    and fresh_waiting_on is not None
                    and fresh_waiting_on != self.current_waiting_on
                ):
                    self._blocker_changed(fresh_waiting_on, fresh_text)
                    continue

                timeout_used = (
                    self.max_total_timeout if is_total_timeout else self.timeout
                )
                self._client._handle_timeout(
                    self.task_href,
                    timeout_used,
                    fresh_state,
                    fresh_text,
                    waiting_on=self.current_waiting_on,
                    is_total_timeout=is_total_timeout,
                )

            req_timeout = min(DEFAULT_TIMEOUT_SECONDS, max(1.0, remaining))
            response = self._client._request(
                "GET",
                self.task_href,
                "Task polling",
                timeout=req_timeout,
            )
            self.last_response_text = response.text

            try:
                task_data = parse_json_dict(response, "Task", self._error_cls)
                new_state = str(task_data.get("state", ""))
                new_waiting_on = (
                    self._client._find_blocking_task(task_data)
                    if new_state == "waiting"
                    else None
                )

                if self.current_state and new_state != self.current_state:
                    self._transition_to(
                        new_state, new_waiting_on, response.text
                    )
                elif (
                    self.current_state == "waiting"
                    and new_state == "waiting"
                    and self.current_waiting_on is not None
                    and new_waiting_on is not None
                    and new_waiting_on != self.current_waiting_on
                ):
                    self._blocker_changed(new_waiting_on, response.text)
                else:
                    self.current_state = new_state
                    self.current_waiting_on = new_waiting_on

                if new_state == "completed":
                    if self._client._config.verbose:
                        created = task_data.get("created_resources", [])
                        click.echo(
                            f"[{_utc_timestamp()}]  Pulp task completed: "
                            f"{self.task_href} (created_resources={created})"
                        )
                    return task_data
                if new_state in ("failed", "canceled"):
                    error_details = task_data.get("error", {})
                    error_msg = str(
                        error_details.get("description", new_state)
                        if isinstance(error_details, dict)
                        else new_state
                    )
                    traceback_str = (
                        str(error_details.get("traceback", "")).strip()
                        if isinstance(error_details, dict)
                        else ""
                    )
                    parts = [f"Task {new_state}: {error_msg}"]
                    if traceback_str:
                        parts.append(f"Traceback:\n{traceback_str}")
                    parts.append(f"Task: {self.task_href}")
                    raise self._error_cls(
                        "\n".join(parts),
                        status_code=response.status_code,
                        response_body=response.text,
                    )

            except (ValueError, KeyError) as e:
                raise self._error_cls(
                    f"Failed to parse task response: {e}",
                    status_code=response.status_code,
                    response_body=response.text,
                ) from e

            now = time.monotonic()
            remaining_state = self.deadline - now
            remaining_total = self.absolute_deadline - now
            remaining = min(remaining_state, remaining_total)
            if remaining <= 0:
                continue

            sleep_time = self._calculate_sleep(remaining)
            time.sleep(sleep_time)

            self.current_interval = min(
                TASK_POLL_MAX_INTERVAL_SECONDS,
                self.current_interval * TASK_POLL_BACKOFF_FACTOR,
            )

