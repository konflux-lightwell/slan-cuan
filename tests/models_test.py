"""Tests for data models (ImageReference, LayerInfo, ExtractResult)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slan_cuan.models import ExtractResult, ImageReference, LayerInfo


class TestImageReference:
    """Tests for ImageReference parsing and serialization."""

    @pytest.mark.parametrize(
        ("ref", "registry", "repository", "tag", "digest"),
        [
            (
                "quay.io/light-castle/tmp-pnc@sha256:abc123",
                "quay.io",
                "light-castle/tmp-pnc",
                None,
                "sha256:abc123",
            ),
            (
                "quay.io/light-castle/tmp-pnc:latest",
                "quay.io",
                "light-castle/tmp-pnc",
                "latest",
                None,
            ),
            (
                "quay.io/light-castle/tmp-pnc:v1.0@sha256:abc123",
                "quay.io",
                "light-castle/tmp-pnc",
                "v1.0",
                "sha256:abc123",
            ),
            (
                "registry.example.com/namespace/image:tag",
                "registry.example.com",
                "namespace/image",
                "tag",
                None,
            ),
            (
                "docker.io/library/alpine@sha256:def456",
                "docker.io",
                "library/alpine",
                None,
                "sha256:def456",
            ),
        ],
    )
    def test_parse_valid_reference(
        self,
        ref: str,
        registry: str,
        repository: str,
        tag: str | None,
        digest: str | None,
    ) -> None:
        """Parse valid image references."""
        img = ImageReference.parse(ref)
        assert img.registry == registry
        assert img.repository == repository
        assert img.tag == tag
        assert img.digest == digest

    @pytest.mark.parametrize(
        ("ref", "expected_error"),
        [
            ("invalid", "Image reference must have tag or digest"),
            ("no-registry:tag", "Invalid image reference"),
            ("registry.io/repo", "Image reference must have tag or digest"),
            ("", "Image reference must have tag or digest"),
            ("registry.io/repo@notsha256:abc", "Invalid digest format"),
        ],
    )
    def test_parse_invalid_reference(self, ref: str, expected_error: str) -> None:
        """Reject invalid image references."""
        with pytest.raises(ValueError, match=expected_error):
            ImageReference.parse(ref)

    def test_str_digest_only(self) -> None:
        """String representation for digest-only reference."""
        img = ImageReference(
            registry="quay.io",
            repository="light-castle/image",
            tag=None,
            digest="sha256:abc123",
        )
        assert str(img) == "quay.io/light-castle/image@sha256:abc123"

    def test_str_tag_only(self) -> None:
        """String representation for tag-only reference."""
        img = ImageReference(
            registry="quay.io",
            repository="light-castle/image",
            tag="latest",
            digest=None,
        )
        assert str(img) == "quay.io/light-castle/image:latest"

    def test_str_tag_and_digest(self) -> None:
        """String representation for reference with both tag and digest."""
        img = ImageReference(
            registry="quay.io",
            repository="light-castle/image",
            tag="v1.0",
            digest="sha256:abc123",
        )
        assert str(img) == "quay.io/light-castle/image:v1.0@sha256:abc123"

    def test_roundtrip_parse_and_str(self) -> None:
        """Parse and __str__ round-trip for valid references."""
        refs = [
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "quay.io/light-castle/tmp-pnc:latest",
            "quay.io/light-castle/tmp-pnc:v1.0@sha256:abc123",
        ]
        for ref in refs:
            img = ImageReference.parse(ref)
            assert str(img) == ref


class TestExtractResult:
    """Tests for ExtractResult serialization and deserialization."""

    @pytest.fixture
    def sample_result(self) -> ExtractResult:
        """Create a sample ExtractResult for testing."""
        return ExtractResult(
            image=ImageReference(
                registry="quay.io",
                repository="light-castle/tmp-pnc",
                tag=None,
                digest="sha256:abc123",
            ),
            manifest_digest="sha256:manifest123",
            layers=[
                LayerInfo(
                    digest="sha256:layer1",
                    media_type="application/vnd.lightwell.build-output.layer.v1+tar",
                    size=1000,
                ),
                LayerInfo(
                    digest="sha256:layer2",
                    media_type="application/vnd.oci.image.layer.v1.tar+gzip",
                    size=2000,
                ),
            ],
            annotations={
                "org.opencontainers.image.title": "TEST-build-output",
                "deliverable.name": "TEST-build-output",
                "deliverable.type": "lightwell-build-output",
            },
            deliverable_dir="TEST-build-output",
            files=[
                "TEST-build-output/cyclonedx.json",
                "TEST-build-output/provenance.json",
                "TEST-build-output/repository/test.jar",
            ],
            extracted_at="2026-06-19T12:00:00Z",
        )

    def test_to_json_returns_valid_json(
        self, sample_result: ExtractResult
    ) -> None:
        """to_json() produces valid JSON with expected structure."""
        json_str = sample_result.to_json()
        data = json.loads(json_str)

        assert data["manifest_digest"] == "sha256:manifest123"
        assert data["deliverable_dir"] == "TEST-build-output"
        assert data["extracted_at"] == "2026-06-19T12:00:00Z"
        assert len(data["layers"]) == 2
        assert len(data["files"]) == 3
        assert data["image"]["registry"] == "quay.io"
        assert data["image"]["digest"] == "sha256:abc123"
        assert data["annotations"]["deliverable.name"] == "TEST-build-output"

    def test_to_json_preserves_all_fields(
        self, sample_result: ExtractResult
    ) -> None:
        """to_json() preserves all fields including nested objects."""
        json_str = sample_result.to_json()
        data = json.loads(json_str)

        # Check LayerInfo fields
        assert data["layers"][0]["digest"] == "sha256:layer1"
        assert (
            data["layers"][0]["media_type"]
            == "application/vnd.lightwell.build-output.layer.v1+tar"
        )
        assert data["layers"][0]["size"] == 1000

        # Check ImageReference fields
        assert data["image"]["repository"] == "light-castle/tmp-pnc"
        assert data["image"]["tag"] is None

    def test_save_and_from_file_roundtrip(
        self, sample_result: ExtractResult, tmp_path: Path
    ) -> None:
        """save() and from_file() round-trip correctly."""
        file_path = tmp_path / "extract-result.json"
        sample_result.save(file_path)

        loaded = ExtractResult.from_file(file_path)

        assert loaded.image.registry == sample_result.image.registry
        assert loaded.image.digest == sample_result.image.digest
        assert loaded.manifest_digest == sample_result.manifest_digest
        assert len(loaded.layers) == len(sample_result.layers)
        assert loaded.layers[0].digest == sample_result.layers[0].digest
        assert loaded.deliverable_dir == sample_result.deliverable_dir
        assert loaded.files == sample_result.files
        assert loaded.extracted_at == sample_result.extracted_at
        assert loaded.annotations == sample_result.annotations

    def test_from_file_missing_file(self, tmp_path: Path) -> None:
        """from_file() raises FileNotFoundError for missing file."""
        nonexistent = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            ExtractResult.from_file(nonexistent)

    def test_from_file_invalid_json(self, tmp_path: Path) -> None:
        """from_file() raises JSONDecodeError for invalid JSON."""
        invalid_json = tmp_path / "invalid.json"
        invalid_json.write_text("not valid json")
        with pytest.raises(json.JSONDecodeError):
            ExtractResult.from_file(invalid_json)

    def test_from_file_missing_required_fields(self, tmp_path: Path) -> None:
        """from_file() raises KeyError for missing required fields."""
        incomplete = tmp_path / "incomplete.json"
        incomplete.write_text('{"image": {}}')
        with pytest.raises(KeyError):
            ExtractResult.from_file(incomplete)
