"""Tests for npm package attestation signing and publishing."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from slan_cuan.npm.attestation import (
    attestation_oci_tag,
    normalize_oci_registry_base,
    publish_attestation,
    sign_package,
)
from slan_cuan.pulp.clients.npm import PulpNpmClient

_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
_BUILD_TYPE = "https://konflux-ci.dev/NpmPackageBuild@v1"
_BUILDER_ID = "https://konflux-ci.dev/calunga"

_VALID_SIGNATURES = [{"keyid": "", "sig": base64.b64encode(b"sig").decode()}]


def _valid_dsse() -> str:
    payload = base64.b64encode(b'{"predicateType": "x"}').decode()
    return json.dumps({"payload": payload, "signatures": _VALID_SIGNATURES})


def _output_signature_path(cmd: list[str]) -> Path:
    for arg in cmd:
        if arg.startswith("--output-signature="):
            return Path(arg.split("=", 1)[1])
    raise AssertionError(f"no --output-signature= arg in {cmd}")


def _cosign_success(dsse_content: str) -> Mock:
    """Return a subprocess.run side_effect writing dsse_content, exit 0."""

    def _run(cmd: list[str], **kwargs: object) -> Mock:
        _output_signature_path(cmd).write_text(dsse_content)
        return Mock(returncode=0, stdout="", stderr="")

    return _run


class TestNormalizeOciRegistryBase:
    """Tests for normalize_oci_registry_base."""

    def test_normalize_oci_registry_base_strips_tag_and_digest(self) -> None:
        """Strips a trailing :tag and @digest, passes through a bare base."""
        assert (
            normalize_oci_registry_base("quay.io/org/repo") == "quay.io/org/repo"
        )
        assert (
            normalize_oci_registry_base("quay.io/org/repo:latest")
            == "quay.io/org/repo"
        )
        assert (
            normalize_oci_registry_base("quay.io/org/repo@sha256:abc")
            == "quay.io/org/repo"
        )
        # A bare trailing "@" has nothing to strip.
        assert normalize_oci_registry_base("quay.io/org/repo@") == (
            "quay.io/org/repo@"
        )


class TestAttestationOciTag:
    """Tests for attestation_oci_tag."""

    def test_attestation_oci_tag_scoped_package(self) -> None:
        """Scoped names strip '@' and replace '/' with '--'."""
        assert (
            attestation_oci_tag("@scope/pkg", "1.2.3") == "scope--pkg-1.2.3-att"
        )

    def test_attestation_oci_tag_unscoped_package(self) -> None:
        """Unscoped names are used as-is."""
        assert attestation_oci_tag("express", "4.22.0") == "express-4.22.0-att"

    def test_attestation_oci_tag_scoped_and_unscoped_do_not_collide(self) -> None:
        """@a/b and a-b must produce different tags."""
        assert attestation_oci_tag("@a/b", "1.0.0") != attestation_oci_tag(
            "a-b", "1.0.0"
        )
        assert attestation_oci_tag("@a/b", "1.0.0") == "a--b-1.0.0-att"
        assert attestation_oci_tag("a-b", "1.0.0") == "a-b-1.0.0-att"

    def test_attestation_oci_tag_sanitizes_invalid_characters(self) -> None:
        """Characters outside [A-Za-z0-9._-] become '-'."""
        tag = attestation_oci_tag("pkg", "2.1.0+build.42")
        assert tag == "pkg-2.1.0-build.42-att"
        assert all(c.isalnum() or c in "._-" for c in tag)

    def test_attestation_oci_tag_scoped_name_with_build_metadata(self) -> None:
        """Scope replacement and build-metadata sanitization combine."""
        tag = attestation_oci_tag("@scope/pkg", "1.0.0+meta")
        assert tag == "scope--pkg-1.0.0-meta-att"

    def test_attestation_oci_tag_truncates_to_128_chars(self) -> None:
        """Result is capped at 128 characters."""
        tag = attestation_oci_tag("x" * 200, "1.0.0")
        assert len(tag) == 128


class TestSignPackage:
    """Tests for sign_package."""

    def test_sign_package_keyfile_mode(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Local keyfile present → --key <path>, no REKOR_URL → no-tlog."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        key_path = secret_dir / "cosign.key"
        key_path.write_text("fake-key")
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        with patch(
            "slan_cuan.npm.attestation.subprocess.run",
            side_effect=_cosign_success(_valid_dsse()),
        ) as mock_run:
            result = sign_package(
                tgz_path,
                predicate_type=_PREDICATE_TYPE,
                build_type=_BUILD_TYPE,
                builder_id=_BUILDER_ID,
                cosign_key_path=None,
                cosign_secret_dir=secret_dir,
                release_time=None,
                require_attestations=False,
            )

        assert result == tgz_path.with_name(tgz_path.name + ".att")
        assert result.exists()
        cmd = mock_run.call_args[0][0]
        assert "--key" in cmd
        assert cmd[cmd.index("--key") + 1] == str(key_path)
        assert "--tlog-upload=false" in cmd

        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "REKOR_URL" in err
        assert "--tlog-upload=false" in err

    def test_sign_package_keyfile_mode_uses_rekor_url_when_present(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A REKOR_URL file alongside the keyfile enables tlog upload."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "cosign.key").write_text("fake-key")
        (secret_dir / "REKOR_URL").write_text("https://rekor.example\n")
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        with patch(
            "slan_cuan.npm.attestation.subprocess.run",
            side_effect=_cosign_success(_valid_dsse()),
        ) as mock_run:
            sign_package(
                tgz_path,
                predicate_type=_PREDICATE_TYPE,
                build_type=_BUILD_TYPE,
                builder_id=_BUILDER_ID,
                cosign_key_path=None,
                cosign_secret_dir=secret_dir,
                release_time=None,
                require_attestations=False,
            )

        cmd = mock_run.call_args[0][0]
        assert "--rekor-url=https://rekor.example" in cmd
        assert "--tlog-upload=false" not in cmd
        # No signing-material warning when Rekor is actually configured.
        assert capsys.readouterr().err == ""

    def test_sign_package_kms_mode_requires_rekor_url(
        self, tmp_path: Path
    ) -> None:
        """SIGN_KEY present but no REKOR_URL raises ClickException."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "SIGN_KEY").write_text("arn:aws:kms:fake")
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        with patch("slan_cuan.npm.attestation.subprocess.run") as mock_run:
            with pytest.raises(click.ClickException, match="REKOR_URL"):
                sign_package(
                    tgz_path,
                    predicate_type=_PREDICATE_TYPE,
                    build_type=_BUILD_TYPE,
                    builder_id=_BUILDER_ID,
                    cosign_key_path=None,
                    cosign_secret_dir=secret_dir,
                    release_time=None,
                    require_attestations=False,
                )
        mock_run.assert_not_called()

    def test_sign_package_kms_mode_exports_aws_env_and_signs(
        self, tmp_path: Path
    ) -> None:
        """KMS mode with REKOR_URL signs using the SIGN_KEY content as --key."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "SIGN_KEY").write_text("arn:aws:kms:fake\n")
        (secret_dir / "REKOR_URL").write_text("https://rekor.example\n")
        (secret_dir / "AWS_DEFAULT_REGION").write_text("us-east-1\n")
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        captured_env: dict[str, str] = {}
        captured_predicate: dict = {}

        def _run(cmd: list[str], **kwargs: object) -> Mock:
            captured_env.update(kwargs.get("env") or {})
            predicate_arg = next(a for a in cmd if a.startswith("--predicate="))
            captured_predicate.update(
                json.loads(Path(predicate_arg.split("=", 1)[1]).read_text())
            )
            _output_signature_path(cmd).write_text(_valid_dsse())
            return Mock(returncode=0, stdout="", stderr="")

        with patch(
            "slan_cuan.npm.attestation.subprocess.run", side_effect=_run
        ) as mock_run:
            result = sign_package(
                tgz_path,
                predicate_type=_PREDICATE_TYPE,
                build_type=_BUILD_TYPE,
                builder_id=_BUILDER_ID,
                cosign_key_path=None,
                cosign_secret_dir=secret_dir,
                release_time="2026-11-16T00:00:00Z",
                require_attestations=True,
            )

        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index("--key") + 1] == "arn:aws:kms:fake"
        assert "--rekor-url=https://rekor.example" in cmd
        assert captured_env.get("AWS_DEFAULT_REGION") == "us-east-1"
        assert result is not None
        assert captured_predicate["runDetails"]["metadata"] == {
            "finishedOn": "2026-11-16T00:00:00Z"
        }

    def test_sign_package_no_material_and_not_required_returns_none(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No signing material + require_attestations=False → None."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        with patch("slan_cuan.npm.attestation.subprocess.run") as mock_run:
            result = sign_package(
                tgz_path,
                predicate_type=_PREDICATE_TYPE,
                build_type=_BUILD_TYPE,
                builder_id=_BUILDER_ID,
                cosign_key_path=None,
                cosign_secret_dir=secret_dir,
                release_time=None,
                require_attestations=False,
            )

        assert result is None
        mock_run.assert_not_called()

        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "skipping attestation" in err
        assert "require_attestations=False" in err

    def test_sign_package_no_material_and_required_raises(
        self, tmp_path: Path
    ) -> None:
        """No signing material + require_attestations=True → raises."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        with patch("slan_cuan.npm.attestation.subprocess.run") as mock_run:
            with pytest.raises(click.ClickException):
                sign_package(
                    tgz_path,
                    predicate_type=_PREDICATE_TYPE,
                    build_type=_BUILD_TYPE,
                    builder_id=_BUILDER_ID,
                    cosign_key_path=None,
                    cosign_secret_dir=secret_dir,
                    release_time=None,
                    require_attestations=True,
                )
        mock_run.assert_not_called()

    def test_sign_package_rejects_non_dsse_output(self, tmp_path: Path) -> None:
        """Cosign exits 0 but writes non-DSSE output → raises."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "cosign.key").write_text("fake-key")
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        bad_dsse = json.dumps({"payload": "abc"})  # missing "signatures"

        with patch(
            "slan_cuan.npm.attestation.subprocess.run",
            side_effect=_cosign_success(bad_dsse),
        ):
            with pytest.raises(click.ClickException, match="non-DSSE"):
                sign_package(
                    tgz_path,
                    predicate_type=_PREDICATE_TYPE,
                    build_type=_BUILD_TYPE,
                    builder_id=_BUILDER_ID,
                    cosign_key_path=None,
                    cosign_secret_dir=secret_dir,
                    release_time=None,
                    require_attestations=False,
                )

    def test_sign_package_raises_on_cosign_failure(self, tmp_path: Path) -> None:
        """A non-zero cosign exit code raises ClickException."""
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "cosign.key").write_text("fake-key")
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.write_bytes(b"fake-tarball")

        with patch(
            "slan_cuan.npm.attestation.subprocess.run",
            return_value=Mock(returncode=1, stdout="", stderr="boom"),
        ):
            with pytest.raises(click.ClickException, match="boom"):
                sign_package(
                    tgz_path,
                    predicate_type=_PREDICATE_TYPE,
                    build_type=_BUILD_TYPE,
                    builder_id=_BUILDER_ID,
                    cosign_key_path=None,
                    cosign_secret_dir=secret_dir,
                    release_time=None,
                    require_attestations=False,
                )


@pytest.fixture
def pulp_client() -> Mock:
    """Return a stub PulpNpmClient for asserting set_label calls."""
    return Mock(spec=PulpNpmClient)


class TestPublishAttestation:
    """Tests for publish_attestation."""

    def test_publish_attestation_resolves_name_version_when_omitted(
        self, tmp_path: Path, pulp_client: Mock
    ) -> None:
        """read_package_metadata is used only when name/version are None."""
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.with_name(tgz_path.name + ".att").write_text(_valid_dsse())

        with (
            patch(
                "slan_cuan.npm.attestation.read_package_metadata",
                return_value=("pkg", "1.0.0"),
            ) as mock_read,
            patch(
                "slan_cuan.npm.attestation.oci.push",
                return_value="sha256:" + "11" * 32,
            ),
        ):
            publish_attestation(
                pulp_client,
                tgz_path,
                "/pulp/api/v3/content/npm/packages/abc/",
                attestation_image_prefix="quay.io/org/repo",
                predicate_type=_PREDICATE_TYPE,
            )
            mock_read.assert_called_once_with(tgz_path)

            mock_read.reset_mock()
            publish_attestation(
                pulp_client,
                tgz_path,
                "/pulp/api/v3/content/npm/packages/abc/",
                attestation_image_prefix="quay.io/org/repo",
                predicate_type=_PREDICATE_TYPE,
                name="pkg",
                version="1.0.0",
            )
            mock_read.assert_not_called()

    def test_publish_attestation_pushes_with_required_annotations(
        self, tmp_path: Path, pulp_client: Mock
    ) -> None:
        """oci.push is called with the three required annotations."""
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        att_path = tgz_path.with_name(tgz_path.name + ".att")
        att_path.write_text(_valid_dsse())

        with patch(
            "slan_cuan.npm.attestation.oci.push",
            return_value="sha256:" + "22" * 32,
        ) as mock_push:
            publish_attestation(
                pulp_client,
                tgz_path,
                "/pulp/api/v3/content/npm/packages/abc/",
                attestation_image_prefix="quay.io/org/repo",
                predicate_type=_PREDICATE_TYPE,
                name="@scope/pkg",
                version="1.0.0",
            )

        mock_push.assert_called_once()
        call = mock_push.call_args
        assert call[0][0] == att_path
        assert call[0][1] == (
            "quay.io/org/repo:" + attestation_oci_tag("@scope/pkg", "1.0.0")
        )
        assert call[1]["annotations"] == {
            "org.opencontainers.image.title": "npm-package-attestation",
            "dev.lightwell.npm.name": "@scope/pkg",
            "dev.lightwell.npm.version": "1.0.0",
        }

    def test_publish_attestation_sets_three_pulp_labels(
        self, tmp_path: Path, pulp_client: Mock
    ) -> None:
        """set_label is called exactly 3 times with the expected values."""
        tgz_path = tmp_path / "pkg-1.0.0.tgz"
        tgz_path.with_name(tgz_path.name + ".att").write_text(_valid_dsse())
        digest = "sha256:" + "33" * 32
        content_href = "/pulp/api/v3/content/npm/packages/abc/"

        with patch("slan_cuan.npm.attestation.oci.push", return_value=digest):
            result = publish_attestation(
                pulp_client,
                tgz_path,
                content_href,
                attestation_image_prefix="quay.io/org/repo:latest",
                predicate_type=_PREDICATE_TYPE,
                name="pkg",
                version="1.0.0",
            )

        assert result == digest
        assert pulp_client.set_label.call_count == 3
        pulp_client.set_label.assert_any_call(
            content_href, "tl.oci_registry_base", "quay.io/org/repo"
        )
        pulp_client.set_label.assert_any_call(
            content_href, "tl.attestation_oci_digest", digest
        )
        pulp_client.set_label.assert_any_call(
            content_href, "tl.attestation_predicate_type", _PREDICATE_TYPE
        )
