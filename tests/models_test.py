"""Tests for data models (ImageReference, LayerInfo, ExtractResult)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slan_cuan.models import (
    BuildOutput,
    ExtractResult,
    ImageReference,
    LayerInfo,
    MavenArtifact,
    MavenCoordinate,
    OCIManifest,
)


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


class TestOCIManifest:
    """Tests for OCIManifest parsing and serialization."""

    def test_from_dict_valid_manifest(self) -> None:
        """Parse a full manifest dict with all fields."""
        manifest_data = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.lightwell.build-output.v1+tar",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:44136fa",
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": ("application/vnd.oci.image.layer.v1.tar+gzip"),
                    "digest": "sha256:layer1abc",
                    "size": 1024,
                    "annotations": {
                        "io.deis.oras.content.unpack": "true",
                    },
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output",
            },
        }

        manifest = OCIManifest.from_dict(manifest_data)

        assert manifest.deliverable_name == "TEST-build-output"
        assert len(manifest.layers) == 1
        assert manifest.layers[0].digest == "sha256:layer1abc"
        assert manifest.layers[0].size == 1024
        assert (
            manifest.layers[0].media_type
            == "application/vnd.oci.image.layer.v1.tar+gzip"
        )
        assert manifest.artifact_type == (
            "application/vnd.lightwell.build-output.v1+tar"
        )
        assert manifest.annotations == {
            "org.opencontainers.image.title": "TEST-build-output"
        }
        assert manifest.raw == manifest_data

    def test_from_dict_fallback_deliverable_name(self) -> None:
        """Manifest uses deliverable.name when title is missing."""
        manifest_data = {
            "layers": [],
            "annotations": {
                "deliverable.name": "FALLBACK-build-output",
            },
        }

        manifest = OCIManifest.from_dict(manifest_data)

        assert manifest.deliverable_name == "FALLBACK-build-output"

    def test_from_dict_missing_deliverable_name(self) -> None:
        """Manifest with empty annotations raises ValueError."""
        manifest_data = {
            "layers": [],
            "annotations": {},
        }

        with pytest.raises(
            ValueError, match="Could not determine deliverable name"
        ):
            OCIManifest.from_dict(manifest_data)

    def test_from_dict_empty_layers(self) -> None:
        """Manifest with empty layers array."""
        manifest_data = {
            "layers": [],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output",
            },
        }

        manifest = OCIManifest.from_dict(manifest_data)

        assert manifest.layers == ()

    def test_to_dict_returns_raw(self) -> None:
        """to_dict() returns the exact dict passed to from_dict."""
        manifest_data = {
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:layer1",
                    "size": 500,
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output",
            },
        }

        manifest = OCIManifest.from_dict(manifest_data)

        assert manifest.to_dict() is manifest_data

    def test_direct_construction(self) -> None:
        """Construct OCIManifest directly with all fields."""
        raw_data = {"test": "data"}
        layer = LayerInfo(
            digest="sha256:abc123",
            media_type="application/vnd.oci.image.layer.v1.tar",
            size=1000,
            annotations={},
        )

        manifest = OCIManifest(
            deliverable_name="DIRECT-build-output",
            layers=(layer,),
            annotations={"key": "value"},
            artifact_type="application/vnd.lightwell.build-output.v1+tar",
            raw=raw_data,
        )

        assert manifest.deliverable_name == "DIRECT-build-output"
        assert len(manifest.layers) == 1
        assert manifest.layers[0].digest == "sha256:abc123"
        assert manifest.annotations == {"key": "value"}
        assert manifest.artifact_type == (
            "application/vnd.lightwell.build-output.v1+tar"
        )
        assert manifest.raw is raw_data

    def test_layer_annotations_preserved(self) -> None:
        """Parse manifest with layer-level annotations."""
        manifest_data = {
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:layer1",
                    "size": 1024,
                    "annotations": {
                        "io.deis.oras.content.unpack": "true",
                        "custom.annotation": "value",
                    },
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output",
            },
        }

        manifest = OCIManifest.from_dict(manifest_data)

        assert len(manifest.layers) == 1
        assert "io.deis.oras.content.unpack" in manifest.layers[0].annotations
        assert (
            manifest.layers[0].annotations["io.deis.oras.content.unpack"]
            == "true"
        )
        assert "custom.annotation" in manifest.layers[0].annotations
        assert manifest.layers[0].annotations["custom.annotation"] == "value"


class TestMavenArtifact:
    """Tests for MavenArtifact properties and methods."""

    def test_coordinate_property(self, tmp_path: Path) -> None:
        """Coordinate property returns MavenCoordinate with GAV."""
        artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
            file_path=tmp_path / "artifact-1.0.0.jar",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="jar",
            md5=None,
            sha1=None,
            sha256=None,
        )

        coord = artifact.coordinate

        assert isinstance(coord, MavenCoordinate)
        assert coord.group_id == "org.example"
        assert coord.artifact_id == "artifact"
        assert coord.version == "1.0.0"

    def test_is_signable_jar(self, tmp_path: Path) -> None:
        """JAR artifacts are signable."""
        artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
            file_path=tmp_path / "artifact-1.0.0.jar",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="jar",
            md5=None,
            sha1=None,
            sha256=None,
        )

        assert artifact.is_signable is True

    def test_is_signable_pom(self, tmp_path: Path) -> None:
        """POM artifacts are signable."""
        artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
            file_path=tmp_path / "artifact-1.0.0.pom",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="pom",
            md5=None,
            sha1=None,
            sha256=None,
        )

        assert artifact.is_signable is True

    def test_is_not_signable_md5(self, tmp_path: Path) -> None:
        """Checksum sidecar files are not signable."""
        artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar.md5",
            file_path=tmp_path / "artifact-1.0.0.jar.md5",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="md5",
            md5=None,
            sha1=None,
            sha256=None,
        )

        assert artifact.is_signable is False


class TestBuildOutput:
    """Tests for BuildOutput parsing and properties."""

    def test_from_extract_result(self, tmp_path: Path) -> None:
        """Parse deliverable directory using ExtractResult."""
        # Create filesystem layout
        deliverable_dir = tmp_path / "TEST-build-output"
        repo_dir = deliverable_dir / "repository" / "org" / "example"
        version_dir = repo_dir / "artifact" / "1.0.0"
        version_dir.mkdir(parents=True)

        # Create artifacts
        (version_dir / "artifact-1.0.0.jar").write_text("jar content")
        (version_dir / "artifact-1.0.0.pom").write_text("<project/>")
        (version_dir / "artifact-1.0.0-sources.jar").write_text("sources")

        # Create checksum sidecars
        (version_dir / "artifact-1.0.0.jar.md5").write_text("abc123")
        (version_dir / "artifact-1.0.0.jar.sha1").write_text("def456")
        (version_dir / "artifact-1.0.0.jar.sha256").write_text("789ghi")

        # Create well-known files
        (deliverable_dir / "cyclonedx.json").write_text("{}")
        (deliverable_dir / "provenance.json").write_text("{}")

        # Create ExtractResult
        result = ExtractResult(
            image=ImageReference(
                registry="quay.io",
                repository="test/image",
                tag=None,
                digest="sha256:abc123",
            ),
            manifest_digest="sha256:manifest123",
            layers=[],
            annotations={},
            deliverable_dir="TEST-build-output",
            files=[],
            extracted_at="2026-06-19T12:00:00Z",
        )

        build = BuildOutput.from_extract_result(result, tmp_path)

        # Verify build_id extraction
        assert build.build_id == "TEST"

        # Verify artifacts count (jar, pom, sources.jar — no checksums)
        assert len(build.artifacts) == 3

        # Verify at least one artifact has correct GAV
        jar_artifact = next(
            a
            for a in build.artifacts
            if a.extension == "jar" and not a.classifier
        )
        assert jar_artifact.group_id == "org.example"
        assert jar_artifact.artifact_id == "artifact"
        assert jar_artifact.version == "1.0.0"

        # Verify checksums read from sidecars
        assert jar_artifact.md5 == "abc123"
        assert jar_artifact.sha1 == "def456"
        assert jar_artifact.sha256 == "789ghi"

        # Verify sources jar has classifier
        sources_artifact = next(
            a for a in build.artifacts if a.classifier == "sources"
        )
        assert sources_artifact.extension == "jar"

        # Verify well-known files
        assert build.sbom_path is not None
        assert build.sbom_path.exists()
        assert build.provenance_path is not None
        assert build.provenance_path.exists()
        assert build.source_archive_path is None

    def test_coordinates_dedup(self, tmp_path: Path) -> None:
        """Coordinates property deduplicates GAVs."""
        artifact1 = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
            file_path=tmp_path / "artifact-1.0.0.jar",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="jar",
            md5=None,
            sha1=None,
            sha256=None,
        )
        artifact2 = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
            file_path=tmp_path / "artifact-1.0.0.pom",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="pom",
            md5=None,
            sha1=None,
            sha256=None,
        )

        build = BuildOutput(
            build_id="TEST",
            deliverable_dir=tmp_path,
            artifacts=(artifact1, artifact2),
            sbom_path=None,
            provenance_path=None,
            source_archive_path=None,
        )

        # Two artifacts with same GAV should result in one coordinate
        assert len(build.coordinates) == 1
        coord = next(iter(build.coordinates))
        assert coord.group_id == "org.example"
        assert coord.artifact_id == "artifact"
        assert coord.version == "1.0.0"

    def test_signable_filter(self, tmp_path: Path) -> None:
        """Signable property filters JARs and POMs."""
        jar_artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
            file_path=tmp_path / "artifact-1.0.0.jar",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="jar",
            md5=None,
            sha1=None,
            sha256=None,
        )
        pom_artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
            file_path=tmp_path / "artifact-1.0.0.pom",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="pom",
            md5=None,
            sha1=None,
            sha256=None,
        )
        md5_artifact = MavenArtifact(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar.md5",
            file_path=tmp_path / "artifact-1.0.0.jar.md5",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="md5",
            md5=None,
            sha1=None,
            sha256=None,
        )

        build = BuildOutput(
            build_id="TEST",
            deliverable_dir=tmp_path,
            artifacts=(jar_artifact, pom_artifact, md5_artifact),
            sbom_path=None,
            provenance_path=None,
            source_archive_path=None,
        )

        # Only jar and pom should be signable
        assert len(build.signable) == 2
        assert jar_artifact in build.signable
        assert pom_artifact in build.signable
        assert md5_artifact not in build.signable

    def test_classifier_detection(self, tmp_path: Path) -> None:
        """Classifier is correctly extracted from filename."""
        # Create filesystem layout
        deliverable_dir = tmp_path / "TEST-build-output"
        repo_dir = deliverable_dir / "repository" / "org" / "example"
        version_dir = repo_dir / "artifact" / "1.0.0"
        version_dir.mkdir(parents=True)

        # Create artifacts with and without classifier
        (version_dir / "artifact-1.0.0.jar").write_text("primary jar")
        (version_dir / "artifact-1.0.0-javadoc.jar").write_text("javadoc")

        result = ExtractResult(
            image=ImageReference(
                registry="quay.io",
                repository="test/image",
                tag=None,
                digest="sha256:abc123",
            ),
            manifest_digest="sha256:manifest123",
            layers=[],
            annotations={},
            deliverable_dir="TEST-build-output",
            files=[],
            extracted_at="2026-06-19T12:00:00Z",
        )

        build = BuildOutput.from_extract_result(result, tmp_path)

        # Find javadoc jar
        javadoc_jar = next(
            a for a in build.artifacts if a.classifier == "javadoc"
        )
        assert javadoc_jar.extension == "jar"

        # Find primary jar
        primary_jar = next(a for a in build.artifacts if a.classifier is None)
        assert primary_jar.extension == "jar"


class TestPublishResult:
    """Tests for PublishResult serialization."""

    def test_to_json_returns_valid_json(self) -> None:
        """to_json() produces valid JSON."""
        from slan_cuan.models import MavenCoordinate, PublishResult

        result = PublishResult(
            pulp_url="https://pulp.example.com",
            distribution="test-repo",
            artifacts_uploaded=5,
            artifacts_skipped=1,
            coordinates=(
                MavenCoordinate(
                    group_id="org.example",
                    artifact_id="test",
                    version="1.0.0",
                ),
            ),
            published_at="2026-06-22T12:00:00Z",
        )

        json_str = result.to_json()
        data = json.loads(json_str)

        assert data["pulp_url"] == "https://pulp.example.com"
        assert data["distribution"] == "test-repo"
        assert data["artifacts_uploaded"] == 5
        assert data["artifacts_skipped"] == 1
        assert len(data["coordinates"]) == 1
        assert data["coordinates"][0]["group_id"] == "org.example"
        assert data["published_at"] == "2026-06-22T12:00:00Z"

    def test_save_and_from_file_roundtrip(self, tmp_path: Path) -> None:
        """save() and from_file() round-trip correctly."""
        from slan_cuan.models import MavenCoordinate, PublishResult

        original = PublishResult(
            pulp_url="https://pulp.example.com",
            distribution="production",
            artifacts_uploaded=10,
            artifacts_skipped=2,
            coordinates=(
                MavenCoordinate(
                    group_id="org.example",
                    artifact_id="artifact1",
                    version="1.0.0",
                ),
                MavenCoordinate(
                    group_id="org.example",
                    artifact_id="artifact2",
                    version="2.0.0",
                ),
            ),
            published_at="2026-06-22T12:30:00Z",
        )

        file_path = tmp_path / "publish-result.json"
        original.save(file_path)

        loaded = PublishResult.from_file(file_path)

        assert loaded.pulp_url == original.pulp_url
        assert loaded.distribution == original.distribution
        assert loaded.artifacts_uploaded == original.artifacts_uploaded
        assert loaded.artifacts_skipped == original.artifacts_skipped
        assert len(loaded.coordinates) == len(original.coordinates)
        assert loaded.coordinates[0].group_id == "org.example"
        assert loaded.coordinates[0].artifact_id == "artifact1"
        assert loaded.coordinates[1].artifact_id == "artifact2"
        assert loaded.published_at == original.published_at
