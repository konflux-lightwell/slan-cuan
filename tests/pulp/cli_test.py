"""Tests for hosted-pulp CLI wrapper (slan_cuan/pulp/cli.py)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from slan_cuan.pulp.cli import (
    PULP_BIN,
    _global_args,
    _write_pulp_config,
    modify_file_repository,
    modify_python_repository,
    run_hosted_pulp,
    upload_file_content,
    upload_python_content,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig


def _cfg(**overrides: object) -> PulpConfig:
    """Default TBR config for lightwell domain."""
    base = {
        "base_url": "https://packages.redhat.com",
        "verify_ssl": True,
        "domain": "lightwell",
        "auth_type": "tbr",
        "username": "user",
        "password": "pass",
    }
    base.update(overrides)  # type: ignore[arg-type]
    return PulpConfig(**base)  # type: ignore[arg-type]


class TestGlobalArgs:
    """Global flag building from PulpConfig."""

    def test_tbr_minimal(self) -> None:
        """Base URL, domain mapped; credentials go to config, not argv."""
        cfg = _cfg()
        args = _global_args(cfg)
        assert "--base-url" in args
        assert "https://packages.redhat.com" in args
        assert "--domain" in args
        assert "lightwell" in args
        # Credentials protected via temp cli.toml (plumbing#457), not argv.
        assert "--username" not in args
        assert "--password" not in args
        assert "--output" in args
        assert "json" in args

    def test_credentials_in_config_not_argv(self, tmp_path: Path) -> None:
        """Username/password written to temp cli.toml, not argv."""
        cfg = _cfg(username="user", password="s3cr3t")
        path = _write_pulp_config(cfg)
        assert path is not None
        try:
            assert path.stat().st_mode & 0o777 == 0o600
            content = path.read_text()
            assert 'username = "user"' in content
            assert 'password = "s3cr3t"' in content
        finally:
            path.unlink(missing_ok=True)
        # None credentials → no file.
        cfg2 = _cfg(username=None, password=None)
        cfg2 = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            auth_type="tbr",
            username=None,
            password=None,
        )
        assert _write_pulp_config(cfg2) is None

    def test_dry_run_and_verbose(self) -> None:
        """Dry-run and -v injected."""
        cfg = _cfg()
        args = _global_args(cfg, dry_run=True, verbose=1)
        assert "--dry-run" in args
        assert "-v" in args

    def test_verbose_count(self) -> None:
        """Verbose count maps to multiple -v."""
        cfg = _cfg()
        args = _global_args(cfg, verbose=2)
        assert args.count("-v") == 2

    def test_wait_and_timeout(self) -> None:
        """Wait adds --wait and --wait-timeout from config."""
        cfg = _cfg(task_timeout=2700.0)
        args = _global_args(cfg, wait=True)
        assert "--wait" in args
        assert "--wait-timeout" in args
        assert "2700s" in args

    def test_wait_timeout_override(self) -> None:
        """Explicit wait_timeout overrides config."""
        cfg = _cfg(task_timeout=2700.0)
        args = _global_args(cfg, wait=True, wait_timeout=600)
        assert "600s" in args

    def test_cert_not_supported(self) -> None:
        """Cert auth raises PulpError (no CLI flag)."""
        cfg = _cfg(auth_type="cert", username=None, password=None)
        cfg = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            auth_type="cert",
            client_cert=Path("/tmp/cert"),
            client_key=Path("/tmp/key"),
        )
        with pytest.raises(PulpError, match="Certificate auth"):
            _global_args(cfg)

    def test_invalid_auth(self) -> None:
        """Invalid auth type raises."""
        cfg = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type="bogus",
            username="u",
            password="p",
        )
        with pytest.raises(PulpError, match="Invalid auth type"):
            _global_args(cfg)


class TestRunHostedPulp:
    """Subprocess invocation and parsing."""

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_success_json(self, mock_run: Mock) -> None:
        """Parses JSON output dict."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"pulp_href": "/a/b/"}',
            stderr="",
        )
        out = run_hosted_pulp("python", "repository", "list", config=_cfg())
        assert out["pulp_href"] == "/a/b/"
        # Verify global flags + subcommand in cmd.
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == PULP_BIN
        assert "python" in cmd
        assert "--base-url" in cmd

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_xdg_cache_default(self, mock_run: Mock) -> None:
        """XDG_CACHE_HOME defaults to writable path (plumbing#464)."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"pulp_href": "/a/"}',
            stderr="",
        )
        # Ensure env doesn't have it, then check it gets set.
        with patch.dict("os.environ", {}, clear=False):
            # Remove if present for test isolation
            os.environ.pop("XDG_CACHE_HOME", None)
            run_hosted_pulp("python", "repository", "list", config=_cfg())
            env = mock_run.call_args[1]["env"]
            assert env["XDG_CACHE_HOME"] == "/tmp/pulp-cli-cache"

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_xdg_cache_preserved(self, mock_run: Mock) -> None:
        """Operator-provided XDG_CACHE_HOME is preserved."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"pulp_href": "/a/"}',
            stderr="",
        )
        run_hosted_pulp(
            "python",
            "repository",
            "list",
            config=_cfg(),
            extra_env={"XDG_CACHE_HOME": "/custom/cache"},
        )
        env = mock_run.call_args[1]["env"]
        assert env["XDG_CACHE_HOME"] == "/custom/cache"

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_dry_run_returns_text(self, mock_run: Mock) -> None:
        """Dry-run returns raw DRY RUN text even with json output."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="DRY RUN: POST https://.../upload/",
            stderr="",
        )
        out = run_hosted_pulp(
            "python",
            "content",
            "upload",
            "--file",
            "/tmp/x",
            config=_cfg(),
            dry_run=True,
        )
        assert out == "DRY RUN: POST https://.../upload/"
        assert "--dry-run" in mock_run.call_args[0][0]

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_nonzero_raises(self, mock_run: Mock) -> None:
        """Non-zero exit raises PulpError with status_code."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="not found",
        )
        with pytest.raises(PulpError) as exc:
            run_hosted_pulp("python", "repository", "show", config=_cfg())
        assert exc.value.status_code == 1
        assert "not found" in str(exc.value)

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_credentials_not_on_argv(self, mock_run: Mock) -> None:
        """Password never on argv — written to temp config (plumbing#457)."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"pulp_href": "/a/"}',
            stderr="",
        )
        run_hosted_pulp(
            "python",
            "content",
            "upload",
            config=_cfg(username="u", password="s3cr3t"),
        )
        cmd = mock_run.call_args[0][0]
        assert "--password" not in cmd
        assert "s3cr3t" not in cmd

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_bad_json_raises(self, mock_run: Mock) -> None:
        """Invalid JSON raises PulpError."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="not json",
            stderr="",
        )
        with pytest.raises(PulpError, match="Failed to parse"):
            run_hosted_pulp("python", "content", "upload", config=_cfg())

    @patch("slan_cuan.pulp.cli.subprocess.run")
    def test_list_output_wrapped(self, mock_run: Mock) -> None:
        """List JSON is wrapped in {results: …}."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='[{"pulp_href": "/a/"}]',
            stderr="",
        )
        out = run_hosted_pulp("python", "repository", "list", config=_cfg())
        assert isinstance(out, dict)
        assert out["results"][0]["pulp_href"] == "/a/"


class TestUploadPythonContent:
    """Orphan upload for Python packages."""

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_returns_href(self, mock_run: Mock, tmp_path: Path) -> None:
        """Returns pulp_href from JSON."""
        f = tmp_path / "pkg-1.0-py3-none-any.whl"
        f.write_text("wheel")
        mock_run.return_value = {
            "pulp_href": "/pulp/api/v3/content/python/packages/uuid/"
        }
        href = upload_python_content(f, _cfg())
        assert href == "/pulp/api/v3/content/python/packages/uuid/"
        # Verify flags.
        args = mock_run.call_args[0]
        assert "python" in args
        assert "--file" in args
        assert str(f) in args
        assert "--sha256" in args

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_with_labels_and_attestations(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Pulp labels and attestations passed as JSON."""
        f = tmp_path / "pkg-1.0-py3-none-any.whl"
        f.write_text("wheel")
        mock_run.return_value = {"pulp_href": "/a/"}
        href = upload_python_content(
            f,
            _cfg(),
            sha256="deadbeef",
            pulp_labels={"source_image": "quay.io/a@sha256:abc"},
            attestations='[{"type":"pep740"}]',
        )
        assert href == "/a/"
        call_args = mock_run.call_args[0]
        assert "--pulp-labels" in call_args
        assert "--attestations" in call_args

    def test_missing_file(self, tmp_path: Path) -> None:
        """Missing file raises PulpError before CLI."""
        f = tmp_path / "missing.whl"
        with pytest.raises(PulpError, match="File not found"):
            upload_python_content(f, _cfg())

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_no_href_raises(self, mock_run: Mock, tmp_path: Path) -> None:
        """Response without pulp_href raises."""
        f = tmp_path / "pkg.whl"
        f.write_text("x")
        mock_run.return_value = {"other": "value"}
        with pytest.raises(PulpError, match="no pulp_href"):
            upload_python_content(f, _cfg())

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_dry_run_passthrough(self, mock_run: Mock, tmp_path: Path) -> None:
        """Dry-run returns raw string from wrapper."""
        f = tmp_path / "pkg.whl"
        f.write_text("x")
        mock_run.return_value = "DRY RUN: POST ..."
        # delegates dry_run; run_hosted_pulp returns str
        # We patch run_hosted_pulp to simulate dry-run path (it would return str).
        # Actual code checks isinstance(out, str) and returns it.
        # So emulate that.
        href = upload_python_content(f, _cfg(), dry_run=True)
        assert href == "DRY RUN: POST ..."


class TestModifyPythonRepository:
    """Associate step for Python repo."""

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_builds_args(self, mock_run: Mock) -> None:
        """Each href as separate --add-content-units."""
        mock_run.return_value = {"state": "completed", "pulp_href": "/tasks/1/"}
        hrefs = ["/a/", "/b/"]
        out = modify_python_repository("my-python-repo", hrefs, _cfg())
        assert out["state"] == "completed"
        call_args = mock_run.call_args[0]
        assert call_args.count("--add-content-units") == 2
        assert "--name" in call_args
        assert "my-python-repo" in call_args
        # wait flag via kwargs
        assert mock_run.call_args[1]["wait"] is True

    def test_no_hrefs(self) -> None:
        """Empty hrefs raises."""
        with pytest.raises(PulpError, match="No content hrefs"):
            modify_python_repository("repo", [], _cfg())

    def test_no_repo_name(self) -> None:
        """Empty repo name raises."""
        with pytest.raises(PulpError, match="Repository name"):
            modify_python_repository("", ["/a/"], _cfg())

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_dry_run_wrapped(self, mock_run: Mock) -> None:
        """Dry-run returns {dry_run: str}."""
        mock_run.return_value = "DRY RUN: POST .../modify/"
        out = modify_python_repository("repo", ["/a/"], _cfg(), dry_run=True)
        assert "dry_run" in out


class TestFileRepository:
    """File plugin helpers (for OSV future)."""

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_upload_file(self, mock_run: Mock, tmp_path: Path) -> None:
        """File upload builds relative-path."""
        f = tmp_path / "doc.json"
        f.write_text("{}")
        mock_run.return_value = {"pulp_href": "/file/1/"}
        href = upload_file_content(f, "doc.json", "abc123", _cfg())
        assert href == "/file/1/"
        assert "--relative-path" in mock_run.call_args[0]

    @patch("slan_cuan.pulp.cli.run_hosted_pulp")
    def test_modify_file(self, mock_run: Mock) -> None:
        """File modify mirrors python."""
        mock_run.return_value = {"state": "completed"}
        out = modify_file_repository("my-file-repo", ["/a/"], _cfg())
        assert out["state"] == "completed"
