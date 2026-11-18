"""Tests for the npm upload command."""

from __future__ import annotations

import io
import json
import tarfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.npm.closure_model import PYTHON_WHEELS_REPOSITORY
from slan_cuan.npm.metadata import (
    read_package_metadata as _real_read_package_metadata,
)
from slan_cuan.npm.upload import (
    COMPLIANCE_LABEL_KEY,
    DEFAULT_ATTESTATION_PREDICATE_TYPE,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import NpmContentUnit

_REPO_HREF = "/api/v3/repositories/npm/npm/abc/"
_REPO_VERSION_HREF = "/api/v3/repositories/npm/npm/abc/versions/5/"

_BASE_ARGS = [
    "npm",
    "upload",
    "--pulp-url",
    "https://pulp.example.com",
    "--pulp-repository",
    "npm-repo",
    "--pulp-domain",
    "lightwell",
    "--pulp-username",
    "user",
    "--pulp-password",
    "pass",
]


def _touch_tgz(files_dir: Path, name: str) -> Path:
    """Create an empty placeholder .tgz file under files_dir."""
    files_dir.mkdir(parents=True, exist_ok=True)
    tgz_path = files_dir / name
    tgz_path.write_bytes(b"")
    return tgz_path


def _make_valid_tgz(path: Path, name: str, version: str) -> None:
    """Write a genuinely valid npm package tarball (real gzip, real tar)."""
    package_json = json.dumps({"name": name, "version": version}).encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json)
        tar.addfile(info, io.BytesIO(package_json))


@pytest.fixture
def runner() -> CliRunner:
    """Return a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mocks():
    """Patch every external dependency of slan_cuan.npm.upload.

    Defaults to the "new package, no attestation, no sidecar" happy path;
    individual tests override return_value/side_effect as needed.
    """
    with ExitStack() as stack:
        client = MagicMock()
        client_cls = stack.enter_context(
            patch("slan_cuan.npm.upload.PulpNpmClient")
        )
        client_cls.return_value.__enter__.return_value = client
        resolve_repo = stack.enter_context(
            patch(
                "slan_cuan.npm.upload._resolve_repository",
                return_value=(_REPO_HREF, _REPO_VERSION_HREF),
            )
        )
        resolve_file_repo = stack.enter_context(
            patch(
                "slan_cuan.npm.upload._resolve_file_repository_href",
                return_value=None,
            )
        )
        read_metadata = stack.enter_context(
            patch("slan_cuan.npm.upload.read_package_metadata")
        )
        checksum = stack.enter_context(
            patch(
                "slan_cuan.npm.upload.compute_checksum",
                return_value="localsha",
            )
        )
        sign = stack.enter_context(patch("slan_cuan.npm.upload.sign_package"))
        publish_attestation = stack.enter_context(
            patch("slan_cuan.npm.upload.publish_attestation")
        )

        client.find_by_name_version.return_value = None
        client.upload_content.return_value = NpmContentUnit(
            pulp_href="/api/v3/content/npm/packages/new/",
            name="pkg",
            version="1.0.0",
        )
        client.get_labels.return_value = {}

        yield SimpleNamespace(
            client=client,
            client_cls=client_cls,
            resolve_repo=resolve_repo,
            resolve_file_repo=resolve_file_repo,
            read_metadata=read_metadata,
            checksum=checksum,
            sign=sign,
            publish_attestation=publish_attestation,
        )


class TestUploadCommand:
    """CLI-level tests for `slan-cuan npm upload`."""

    def test_upload_new_package_uploads_and_adds_to_repo(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A package with no existing match is uploaded and added."""
        files_dir = tmp_path / "files"
        tgz = _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.upload_content.assert_called_once_with(
            tgz, "pkg", "1.0.0", labels=None
        )
        mocks.client.modify_repository.assert_called_once_with(
            _REPO_HREF, ["/api/v3/content/npm/packages/new/"]
        )
        assert "Uploaded (1)" in result.output

    def test_upload_skips_identical_existing_package(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """Matching sha256 of an existing package skips the upload."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": "/api/v3/content/npm/packages/existing/",
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.upload_content.assert_not_called()
        assert "Skipped - already in Pulp (1)" in result.output

    def test_upload_replaces_mismatched_package_when_allowed(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A digest mismatch with --allow-content-replace replaces content.

        Verifies the remove -> destroy-holding-versions -> orphan-cleanup ->
        re-upload sequence happens, in that order.
        """
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        existing_href = "/api/v3/content/npm/packages/existing/"
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": existing_href,
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "remotesha"
        mocks.checksum.return_value = "localsha"
        mocks.client.list_repository_versions_holding.return_value = [
            "/api/v3/repositories/npm/npm/abc/versions/1/",
            "/api/v3/repositories/npm/npm/abc/versions/2/",
        ]

        result = runner.invoke(
            main,
            [
                *_BASE_ARGS,
                "--files-dir",
                str(files_dir),
                "--allow-content-replace",
            ],
        )

        assert result.exit_code == 0, result.output
        relevant = {
            "modify_repository",
            "list_repository_versions_holding",
            "destroy_repository_version",
            "orphan_cleanup",
            "upload_content",
        }
        order = [
            name for name, _, _ in mocks.client.mock_calls if name in relevant
        ]
        assert order == [
            "modify_repository",
            "list_repository_versions_holding",
            "destroy_repository_version",
            "destroy_repository_version",
            "orphan_cleanup",
            "upload_content",
            "modify_repository",
        ]
        mocks.client.modify_repository.assert_any_call(
            _REPO_HREF, [], remove_content_unit_hrefs=[existing_href]
        )
        mocks.client.orphan_cleanup.assert_called_once_with([existing_href])
        assert "Uploaded (1)" in result.output

    def test_upload_fails_mismatched_package_when_replace_not_allowed(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A digest mismatch without --allow-content-replace fails the file."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": "/api/v3/content/npm/packages/existing/",
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "remotesha"
        mocks.checksum.return_value = "localsha"

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code != 0
        mocks.client.modify_repository.assert_not_called()
        mocks.client.destroy_repository_version.assert_not_called()
        mocks.client.orphan_cleanup.assert_not_called()
        mocks.client.upload_content.assert_not_called()
        assert "Failed (1)" in result.output

    def test_upload_invalid_compliance_sidecar_fails_only_that_file(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """An invalid sidecar fails only its own file; the batch continues."""
        files_dir = tmp_path / "files"
        tgz_a = _touch_tgz(files_dir, "a-1.0.0.tgz")
        (files_dir / "a-1.0.0.tl-compliance.json").write_text(
            json.dumps({"compliance_level": "bad"})
        )
        tgz_b = _touch_tgz(files_dir, "b-1.0.0.tgz")

        def metadata_side_effect(path: Path) -> tuple[str, str]:
            return ("a", "1.0.0") if path == tgz_a else ("b", "1.0.0")

        mocks.read_metadata.side_effect = metadata_side_effect
        mocks.client.upload_content.return_value = NpmContentUnit(
            pulp_href="/href/b/", name="b", version="1.0.0"
        )

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code != 0
        assert "Uploaded (1)" in result.output
        assert "Failed (1)" in result.output
        assert str(tgz_b) in result.output
        assert str(tgz_a) in result.output
        mocks.client.upload_content.assert_called_once_with(
            tgz_b, "b", "1.0.0", labels=None
        )

    def test_upload_missing_package_json_fails_only_that_file(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A metadata-read failure fails only its own file; batch continues."""
        files_dir = tmp_path / "files"
        tgz_a = _touch_tgz(files_dir, "a-1.0.0.tgz")
        tgz_b = _touch_tgz(files_dir, "b-1.0.0.tgz")

        def metadata_side_effect(path: Path) -> tuple[str, str]:
            if path == tgz_a:
                raise click.ClickException("bad package.json")
            return ("b", "1.0.0")

        mocks.read_metadata.side_effect = metadata_side_effect
        mocks.client.upload_content.return_value = NpmContentUnit(
            pulp_href="/href/b/", name="b", version="1.0.0"
        )

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code != 0
        assert "Uploaded (1)" in result.output
        assert "Failed (1)" in result.output
        mocks.client.upload_content.assert_called_once_with(
            tgz_b, "b", "1.0.0", labels=None
        )

    def test_upload_applies_compliance_label_on_skip_path(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A valid sidecar on the skip path still sets the compliance label."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        (files_dir / "pkg-1.0.0.tl-compliance.json").write_text(
            json.dumps({"compliance_level": "L2"})
        )
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        existing_href = "/api/v3/content/npm/packages/existing/"
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": existing_href,
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.set_label.assert_called_once_with(
            existing_href, COMPLIANCE_LABEL_KEY, "L2"
        )

    def test_upload_skip_path_does_not_downgrade_compliance_label(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A sidecar level lower than Pulp's current level must not downgrade it.

        Pulp already holds L3 (e.g. previously raised by ``npm closure
        update``'s CAS protocol); this re-upload's sidecar says a stale L1.
        The identical-content skip path must never write the label
        downward.
        """
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        (files_dir / "pkg-1.0.0.tl-compliance.json").write_text(
            json.dumps({"compliance_level": "L1"})
        )
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        existing_href = "/api/v3/content/npm/packages/existing/"
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": existing_href,
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"
        mocks.client.get_labels.return_value = {COMPLIANCE_LABEL_KEY: "L3"}

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.set_label.assert_not_called()

    def test_upload_skip_path_raises_compliance_label_when_current_lower(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A sidecar level higher than Pulp's current level does get applied."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        (files_dir / "pkg-1.0.0.tl-compliance.json").write_text(
            json.dumps({"compliance_level": "L3"})
        )
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        existing_href = "/api/v3/content/npm/packages/existing/"
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": existing_href,
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"
        mocks.client.get_labels.return_value = {COMPLIANCE_LABEL_KEY: "L1"}

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.set_label.assert_called_once_with(
            existing_href, COMPLIANCE_LABEL_KEY, "L3"
        )

    def test_upload_skip_path_content_gone_during_label_write_is_warning(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """Content deleted concurrently during the label write warns, not fails.

        The content unit disappearing between our own sha256 check and the
        compliance label write is a narrow race; the upload itself already
        succeeded (identical content was confirmed present), so this must
        not fail the file.
        """
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        (files_dir / "pkg-1.0.0.tl-compliance.json").write_text(
            json.dumps({"compliance_level": "L3"})
        )
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        existing_href = "/api/v3/content/npm/packages/existing/"
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": existing_href,
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"
        mocks.client.get_labels.return_value = {COMPLIANCE_LABEL_KEY: "L1"}
        mocks.client.set_label.side_effect = PulpError(
            "not found", status_code=404, response_body=""
        )

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        assert "Skipped - already in Pulp (1)" in result.output
        assert "vanished" in result.output

    def test_upload_publishes_attestation_when_prefix_set(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """An attestation prefix triggers signing and OCI publish."""
        files_dir = tmp_path / "files"
        tgz = _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        (files_dir / "pkg-1.0.0.tgz.att").write_text("{}")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        mocks.client.upload_content.return_value = NpmContentUnit(
            pulp_href="/href/pkg/", name="pkg", version="1.0.0"
        )

        result = runner.invoke(
            main,
            [
                *_BASE_ARGS,
                "--files-dir",
                str(files_dir),
                "--attestation-image-prefix",
                "quay.io/foo/attestations",
            ],
        )

        assert result.exit_code == 0, result.output
        mocks.sign.assert_called_once()
        assert mocks.sign.call_args.args[0] == tgz
        assert (
            mocks.sign.call_args.kwargs["predicate_type"]
            == DEFAULT_ATTESTATION_PREDICATE_TYPE
        )
        mocks.publish_attestation.assert_called_once()
        pub_args, pub_kwargs = mocks.publish_attestation.call_args
        assert pub_args[0] is mocks.client
        assert pub_args[1] == tgz
        assert pub_args[2] == "/href/pkg/"
        assert (
            pub_kwargs["attestation_image_prefix"] == "quay.io/foo/attestations"
        )

    def test_upload_require_attestations_without_prefix_raises_before_processing(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """--require-attestations without a prefix fails fast, before any file."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")

        result = runner.invoke(
            main,
            [
                *_BASE_ARGS,
                "--files-dir",
                str(files_dir),
                "--require-attestations",
            ],
        )

        assert result.exit_code != 0
        mocks.read_metadata.assert_not_called()
        mocks.client_cls.assert_not_called()

    def test_upload_sidecar_upload_failure_is_warning_not_failure(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A sidecar upload failure warns but does not fail the package."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        (files_dir / "pkg-1.0.0.tl-compliance.json").write_text(
            json.dumps({"compliance_level": "L1"})
        )
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        mocks.resolve_file_repo.return_value = (
            "/api/v3/repositories/file/file/xyz/"
        )
        mocks.client.upload_content.return_value = NpmContentUnit(
            pulp_href="/href/pkg/", name="pkg", version="1.0.0"
        )
        mocks.client.upload_file_content.side_effect = PulpError(
            "boom", status_code=500, response_body=""
        )

        result = runner.invoke(
            main,
            [
                *_BASE_ARGS,
                "--files-dir",
                str(files_dir),
                "--pulp-file-repository",
                "npm-compliance",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Uploaded (1)" in result.output
        assert "WARNING" in result.output

    def test_upload_raises_click_exception_when_any_file_failed(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """Any failed file raises ClickException (exit 1) after the summary."""
        files_dir = tmp_path / "files"
        tgz_a = _touch_tgz(files_dir, "a-1.0.0.tgz")
        tgz_b = _touch_tgz(files_dir, "b-1.0.0.tgz")

        def metadata_side_effect(path: Path) -> tuple[str, str]:
            return ("a", "1.0.0") if path == tgz_a else ("b", "1.0.0")

        mocks.read_metadata.side_effect = metadata_side_effect
        mocks.client.upload_content.side_effect = [
            NpmContentUnit(pulp_href="/href/a/", name="a", version="1.0.0"),
            PulpError("fail upload", status_code=500, response_body=""),
        ]

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code != 0
        assert "npm Pulp Upload Summary" in result.output
        assert "Uploaded (1)" in result.output
        assert "Failed (1)" in result.output
        assert str(tgz_a) in result.output
        assert str(tgz_b) in result.output

    def test_upload_corrupt_tarball_fails_only_that_file(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A genuinely corrupt (non-gzip) .tgz fails only itself.

        Regression test: reading a truncated/corrupted/non-gzip archive
        raises tarfile.ReadError (a tarfile.TarError, not a PulpError or
        click.ClickException) from the real read_package_metadata — a
        realistic pipeline failure distinct from "valid archive missing
        package.json" (which read_package_metadata itself translates to
        click.ClickException). _process_one's except clause must catch
        this too, or the whole batch aborts uncaught before the valid
        file is ever processed.
        """
        files_dir = tmp_path / "files"
        files_dir.mkdir(parents=True)
        corrupt_tgz = files_dir / "bad-1.0.0.tgz"
        corrupt_tgz.write_bytes(b"this is not a gzip file at all")
        good_tgz = files_dir / "good-1.0.0.tgz"
        _make_valid_tgz(good_tgz, "good", "1.0.0")

        # Use the real read_package_metadata (not a canned return value) so
        # the corrupt file genuinely exercises tarfile's own error path.
        mocks.read_metadata.side_effect = _real_read_package_metadata
        mocks.client.upload_content.return_value = NpmContentUnit(
            pulp_href="/href/good/", name="good", version="1.0.0"
        )

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code != 0
        assert "npm Pulp Upload Summary" in result.output
        assert "Uploaded (1)" in result.output
        assert "Failed (1)" in result.output
        assert str(corrupt_tgz) in result.output
        mocks.client.upload_content.assert_called_once_with(
            good_tgz, "good", "1.0.0", labels=None
        )


class TestArtifactDetailFallback:
    """Existing-package artifact href: list row first, detail GET fallback."""

    def test_missing_artifact_falls_back_to_content_detail(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A list row without `artifact` triggers get_content(pulp_href)."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        existing_href = "/api/v3/content/npm/packages/existing/"
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": existing_href,
        }
        mocks.client.get_content.return_value = {
            "pulp_href": existing_href,
            "artifact": "/api/v3/artifacts/detail/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.get_content.assert_called_once_with(existing_href)
        mocks.client.get_artifact_sha256.assert_called_once_with(
            "/api/v3/artifacts/detail/"
        )
        assert "Skipped - already in Pulp (1)" in result.output

    def test_present_artifact_skips_content_detail_fetch(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A list row with `artifact` makes no extra detail GET."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": "/api/v3/content/npm/packages/existing/",
            "artifact": "/api/v3/artifacts/abc/",
        }
        mocks.client.get_artifact_sha256.return_value = "localsha"

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code == 0, result.output
        mocks.client.get_content.assert_not_called()
        mocks.client.get_artifact_sha256.assert_called_once_with(
            "/api/v3/artifacts/abc/"
        )

    def test_artifact_missing_from_list_and_detail_fails_file(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """No artifact in either response fails only that file."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        mocks.read_metadata.return_value = ("pkg", "1.0.0")
        mocks.client.find_by_name_version.return_value = {
            "pulp_href": "/api/v3/content/npm/packages/existing/",
        }
        mocks.client.get_content.return_value = {}

        result = runner.invoke(main, [*_BASE_ARGS, "--files-dir", str(files_dir)])

        assert result.exit_code != 0
        assert "no artifact href" in result.output
        mocks.client.get_artifact_sha256.assert_not_called()

    def test_malformed_artifact_digest_fails_only_that_file_no_replace(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A PulpError from get_artifact_sha256 fails just that one file.

        Even with --allow-content-replace, a malformed artifact response
        (no/null sha256) must never be treated as a digest mismatch that
        triggers the destructive replace path; the rest of the batch still
        proceeds.
        """
        files_dir = tmp_path / "files"
        tgz_a = _touch_tgz(files_dir, "a-1.0.0.tgz")
        tgz_b = _touch_tgz(files_dir, "b-1.0.0.tgz")

        def metadata_side_effect(path: Path) -> tuple[str, str]:
            return ("a", "1.0.0") if path == tgz_a else ("b", "1.0.0")

        def find_side_effect(
            name: str, version: str, version_href: str
        ) -> dict[str, str] | None:
            if name == "a":
                return {
                    "pulp_href": "/api/v3/content/npm/packages/a/",
                    "artifact": "/api/v3/artifacts/a/",
                }
            return None

        mocks.read_metadata.side_effect = metadata_side_effect
        mocks.client.find_by_name_version.side_effect = find_side_effect
        mocks.client.get_artifact_sha256.side_effect = PulpError(
            "Artifact response has no sha256",
            status_code=200,
            response_body="{}",
        )
        mocks.client.upload_content.return_value = NpmContentUnit(
            pulp_href="/href/b/", name="b", version="1.0.0"
        )

        result = runner.invoke(
            main,
            [
                *_BASE_ARGS,
                "--files-dir",
                str(files_dir),
                "--allow-content-replace",
            ],
        )

        assert result.exit_code != 0
        assert "Uploaded (1)" in result.output
        assert "Failed (1)" in result.output
        assert "no sha256" in result.output
        mocks.client.destroy_repository_version.assert_not_called()
        mocks.client.orphan_cleanup.assert_not_called()
        mocks.client.upload_content.assert_called_once_with(
            tgz_b, "b", "1.0.0", labels=None
        )


class TestPythonWheelsRepositoryGuard:
    """--pulp-repository main (the python-wheels repo) is refused early."""

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_upload_refuses_python_wheels_repository_before_any_io(
        self,
        runner: CliRunner,
        tmp_path: Path,
        mocks: SimpleNamespace,
        dry_run: bool,
    ) -> None:
        """Clear ClickException; no signing, Pulp client, or metadata read."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        args = list(_BASE_ARGS)
        args[args.index("--pulp-repository") + 1] = PYTHON_WHEELS_REPOSITORY

        result = runner.invoke(
            main,
            [
                *(["--dry-run"] if dry_run else []),
                *args,
                "--files-dir",
                str(files_dir),
                "--attestation-image-prefix",
                "quay.io/org/att",
            ],
        )

        assert result.exit_code != 0
        assert "python-wheels Pulp repository" in result.output
        assert "PULP_REPOSITORY=main" in result.output
        assert "Would upload" not in result.output
        mocks.client_cls.assert_not_called()
        mocks.resolve_repo.assert_not_called()
        mocks.resolve_file_repo.assert_not_called()
        mocks.sign.assert_not_called()
        mocks.publish_attestation.assert_not_called()
        mocks.read_metadata.assert_not_called()
        assert mocks.client.method_calls == []

    def test_upload_refuses_case_variant_of_python_wheels_repository(
        self,
        runner: CliRunner,
        tmp_path: Path,
        mocks: SimpleNamespace,
    ) -> None:
        """A case/whitespace variant like 'Main' is refused too."""
        files_dir = tmp_path / "files"
        _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        args = list(_BASE_ARGS)
        args[args.index("--pulp-repository") + 1] = "Main"

        result = runner.invoke(
            main,
            [
                *args,
                "--files-dir",
                str(files_dir),
                "--attestation-image-prefix",
                "quay.io/org/att",
            ],
        )

        assert result.exit_code != 0
        assert "python-wheels Pulp repository" in result.output
        assert mocks.client.method_calls == []


class TestUploadDryRun:
    """--dry-run previews `npm upload` without signing or any I/O."""

    def test_upload_dry_run_makes_no_calls(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """--dry-run names each tgz/sidecar and touches no Pulp/OCI/cosign."""
        files_dir = tmp_path / "files"
        tgz = _touch_tgz(files_dir, "pkg-1.0.0.tgz")
        sidecar = files_dir / "pkg-1.0.0.tl-compliance.json"
        sidecar.write_text(json.dumps({"compliance_level": "L2"}))

        result = runner.invoke(
            main,
            [
                "--dry-run",
                *_BASE_ARGS,
                "--files-dir",
                str(files_dir),
                "--allow-content-replace",
                "--attestation-image-prefix",
                "quay.io/org/att",
            ],
        )

        assert result.exit_code == 0, result.output
        assert f"Would upload {tgz}" in result.output
        assert str(sidecar) in result.output
        assert "quay.io/org/att" in result.output
        assert "--allow-content-replace" in result.output
        mocks.client_cls.assert_not_called()
        mocks.resolve_repo.assert_not_called()
        mocks.resolve_file_repo.assert_not_called()
        mocks.sign.assert_not_called()
        mocks.publish_attestation.assert_not_called()
        mocks.read_metadata.assert_not_called()
        assert mocks.client.method_calls == []
