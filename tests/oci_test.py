"""Tests for OCI registry operations using oras CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from slan_cuan.models import ImageReference
from slan_cuan.oci import OrasError, manifest_fetch, pull


class TestPull:
    """Tests for the pull() function."""

    @pytest.fixture
    def image_ref(self) -> ImageReference:
        """Create a sample image reference."""
        return ImageReference(
            registry="quay.io",
            repository="light-castle/tmp-pnc",
            tag=None,
            digest="sha256:abc123",
        )

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_success(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Successful oras pull completes without error."""
        mock_run.return_value = Mock(returncode=0, stderr="", stdout="")
        pull(image_ref, tmp_path)
        mock_run.assert_called_once()

        # Verify command structure
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "oras"
        assert cmd[1] == "pull"
        assert str(image_ref) in cmd
        assert "--output" in cmd
        assert str(tmp_path) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_auth_failure(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError with auth failure message."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed for quay.io"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_auth_required(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for authentication required."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: authentication required",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed for quay.io"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_not_found(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError with not found message."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: manifest unknown",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_not_found_404(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for 404 Not Found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 404 Not Found",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_network_error_connection(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for connection errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: connection refused",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error pulling"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_network_error_timeout(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for timeout errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: timeout waiting for response",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error pulling"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_generic_error(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for unrecognized errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: something went wrong",
            stdout="",
        )
        with pytest.raises(OrasError, match="oras pull failed"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_with_auth_file(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull includes --registry-config when auth_file provided."""
        mock_run.return_value = Mock(returncode=0, stderr="", stdout="")
        auth_file = Path("/path/to/auth.json")
        pull(image_ref, tmp_path, auth_file=auth_file)

        cmd = mock_run.call_args[0][0]
        assert "--registry-config" in cmd
        assert str(auth_file) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_verbose_prints_command(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Oras pull with verbose=True prints the command."""
        mock_run.return_value = Mock(returncode=0, stderr="", stdout="")
        pull(image_ref, tmp_path, verbose=True)

        captured = capsys.readouterr()
        assert "Running: oras pull" in captured.out


class TestManifestFetch:
    """Tests for the manifest_fetch() function."""

    @pytest.fixture
    def image_ref(self) -> ImageReference:
        """Create a sample image reference."""
        return ImageReference(
            registry="quay.io",
            repository="light-castle/tmp-pnc",
            tag=None,
            digest="sha256:abc123",
        )

    @pytest.fixture
    def sample_manifest(self) -> dict:
        """Create a sample OCI manifest."""
        return {
            "layers": [
                {
                    "digest": "sha256:layer1",
                    "mediaType": (
                        "application/vnd.lightwell.build-output.layer.v1+tar"
                    ),
                    "size": 1000,
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output",
                "deliverable.name": "TEST-build-output",
                "deliverable.type": "lightwell-build-output",
            },
        }

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_success(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        sample_manifest: dict,
    ) -> None:
        """Successful manifest fetch returns parsed JSON."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps(sample_manifest),
        )
        result = manifest_fetch(image_ref)

        assert result == sample_manifest
        mock_run.assert_called_once()

        # Verify command structure
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "oras"
        assert cmd[1] == "manifest"
        assert cmd[2] == "fetch"
        assert str(image_ref) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_auth_failure(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for auth failure."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed for quay.io"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_not_found(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for not found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: manifest unknown",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_network_error(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for network errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: connection timeout",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error fetching manifest"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_invalid_json(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for invalid JSON response."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout="not valid json",
        )
        with pytest.raises(OrasError, match="Invalid JSON in manifest response"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_with_auth_file(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        sample_manifest: dict,
    ) -> None:
        """manifest_fetch includes --registry-config when auth_file provided."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps(sample_manifest),
        )
        auth_file = Path("/path/to/auth.json")
        manifest_fetch(image_ref, auth_file=auth_file)

        cmd = mock_run.call_args[0][0]
        assert "--registry-config" in cmd
        assert str(auth_file) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_verbose_prints_command(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        sample_manifest: dict,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """manifest_fetch with verbose=True prints the command."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps(sample_manifest),
        )
        manifest_fetch(image_ref, verbose=True)

        captured = capsys.readouterr()
        assert "Running: oras manifest fetch" in captured.out


class TestOrasError:
    """Tests for the OrasError exception class."""

    def test_oras_error_attributes(self) -> None:
        """OrasError preserves message, stderr, and returncode."""
        error = OrasError(
            message="Test error",
            stderr="stderr content",
            returncode=1,
        )
        assert error.message == "Test error"
        assert error.stderr == "stderr content"
        assert error.returncode == 1
        assert str(error) == "Test error"
