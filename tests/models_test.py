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
        raw_data: dict[str, object] = {"test": "data"}
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

    def test_is_metadata_checksum_sidecars(self, tmp_path: Path) -> None:
        """Metadata checksum sidecars are classified as metadata."""
        for suffix in (".md5", ".sha1", ".sha256"):
            artifact = MavenArtifact(
                relative_path=f"com/example/artifact/maven-metadata.xml{suffix}",
                file_path=tmp_path / f"maven-metadata.xml{suffix}",
                group_id="com.example",
                artifact_id="artifact",
                version="",
                classifier=None,
                extension=suffix.lstrip("."),
                md5=None,
                sha1=None,
                sha256=None,
            )
            assert artifact.is_metadata is True, (
                f"maven-metadata.xml{suffix} should be metadata"
            )

    def test_artifact_checksum_not_metadata(self, tmp_path: Path) -> None:
        """Artifact checksum sidecars are NOT metadata."""
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
        assert artifact.is_metadata is False

    @pytest.mark.parametrize(
        (
            "extension",
            "is_cyclonedx",
            "is_provenance",
            "is_spdx",
            "is_vsa",
            "is_sbom",
        ),
        [
            ("cyclonedx", True, False, False, False, True),
            ("provenance", False, True, False, False, True),
            ("spdx", False, False, True, False, True),
            ("vsa", False, False, False, True, True),
            ("jar", False, False, False, False, False),
            ("pom", False, False, False, False, False),
            ("md5", False, False, False, False, False),
        ],
    )
    def test_sbom_properties(
        self,
        tmp_path: Path,
        extension: str,
        is_cyclonedx: bool,
        is_provenance: bool,
        is_spdx: bool,
        is_vsa: bool,
        is_sbom: bool,
    ) -> None:
        """SBOM properties return correct values per extension."""
        artifact = MavenArtifact(
            relative_path=f"org/example/artifact/1.0.0/artifact-1.0.0.{extension}",
            file_path=tmp_path / f"artifact-1.0.0.{extension}",
            group_id="org.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension=extension,
            md5=None,
            sha1=None,
            sha256=None,
        )
        assert artifact.is_cyclonedx is is_cyclonedx
        assert artifact.is_provenance is is_provenance
        assert artifact.is_spdx is is_spdx
        assert artifact.is_vsa is is_vsa
        assert artifact.is_sbom is is_sbom


class TestParseExtension:
    """Tests for _parse_extension with SBOM suffixes."""

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("artifact-1.0.0.jar", "jar"),
            ("artifact-1.0.0.pom", "pom"),
            ("artifact-1.0.0.jar.md5", "md5"),
            ("artifact-1.0.0.tar.gz", "tar.gz"),
            ("artifact-1.0.0.cyclonedx.json", "cyclonedx"),
            ("artifact-1.0.0.spdx.json", "spdx"),
            ("artifact-1.0.0.vsa.json", "vsa"),
            ("artifact-1.0.0.provenance.sigstore.json", "provenance"),
        ],
    )
    def test_parse_extension(self, filename: str, expected: str) -> None:
        """Extension is correctly extracted for various file types."""
        from slan_cuan.models import _parse_extension

        assert _parse_extension(filename) == expected


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

        # Create SBOM/provenance files alongside JARs
        (version_dir / "artifact-1.0.0.cyclonedx.json").write_text("{}")
        (version_dir / "artifact-1.0.0.cyclonedx.json.md5").write_text("cdxmd5")
        (version_dir / "artifact-1.0.0.provenance.sigstore.json").write_text("{}")
        (version_dir / "artifact-1.0.0.provenance.sigstore.json.md5").write_text(
            "provmd5"
        )

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

        # 3 primary + 3 checksums + 2 SBOM + 2 SBOM checksums = 10 total
        assert len(build.artifacts) == 10

        # Verify primary jar artifact has correct GAV
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

        # Verify checksum sidecar artifacts (3 for jar + 2 for SBOMs)
        checksum_artifacts = [
            a for a in build.artifacts if a.extension in ("md5", "sha1", "sha256")
        ]
        assert len(checksum_artifacts) == 5

        # Verify MD5 checksum artifact properties
        md5_artifact = next(a for a in checksum_artifacts if a.extension == "md5")
        assert md5_artifact.group_id == "org.example"
        assert md5_artifact.artifact_id == "artifact"
        assert md5_artifact.version == "1.0.0"
        assert md5_artifact.classifier is None
        assert md5_artifact.is_metadata is False
        assert md5_artifact.is_signable is False

        # Verify SHA1 checksum artifact properties
        sha1_artifact = next(
            a for a in checksum_artifacts if a.extension == "sha1"
        )
        assert sha1_artifact.extension == "sha1"
        assert sha1_artifact.is_metadata is False
        assert sha1_artifact.is_signable is False

        # Verify SHA256 checksum artifact properties
        sha256_artifact = next(
            a for a in checksum_artifacts if a.extension == "sha256"
        )
        assert sha256_artifact.extension == "sha256"
        assert sha256_artifact.is_metadata is False
        assert sha256_artifact.is_signable is False

        # Verify SBOM artifacts
        cyclonedx_artifact = next(a for a in build.artifacts if a.is_cyclonedx)
        assert cyclonedx_artifact.extension == "cyclonedx"
        assert cyclonedx_artifact.is_sbom is True
        assert cyclonedx_artifact.is_signable is False
        assert cyclonedx_artifact.md5 == "cdxmd5"

        provenance_artifact = next(a for a in build.artifacts if a.is_provenance)
        assert provenance_artifact.extension == "provenance"
        assert provenance_artifact.is_sbom is True
        assert provenance_artifact.is_signable is False
        assert provenance_artifact.md5 == "provmd5"

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

    def test_metadata_xml_parsing(self, tmp_path: Path) -> None:
        """maven-metadata.xml parsed with correct GAV (no version dir)."""
        deliverable_dir = tmp_path / "TEST-build-output"
        repo_dir = (
            deliverable_dir
            / "repository"
            / "com"
            / "fasterxml"
            / "jackson"
            / "module"
        )

        # Versioned artifact
        version_dir = repo_dir / "jackson-module-parameter-names" / "2.8.11"
        version_dir.mkdir(parents=True)
        (version_dir / "jackson-module-parameter-names-2.8.11.jar").write_text(
            "jar"
        )

        # Metadata XML (sits at artifact_id level, no version dir)
        metadata_dir = repo_dir / "jackson-module-parameter-names"
        (metadata_dir / "maven-metadata.xml").write_text("<metadata/>")

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
            extracted_at="2026-06-27T12:00:00Z",
        )

        build = BuildOutput.from_extract_result(result, tmp_path)

        metadata = [a for a in build.artifacts if a.is_metadata]
        assert len(metadata) == 1
        m = metadata[0]
        assert m.group_id == "com.fasterxml.jackson.module"
        assert m.artifact_id == "jackson-module-parameter-names"
        assert m.version == ""
        assert m.extension == "xml"

        jars = [a for a in build.artifacts if a.extension == "jar"]
        assert len(jars) == 1
        assert jars[0].group_id == "com.fasterxml.jackson.module"
        assert jars[0].artifact_id == "jackson-module-parameter-names"
        assert jars[0].version == "2.8.11"

    def test_metadata_xml_version_level(self, tmp_path: Path) -> None:
        """Version-level maven-metadata.xml parsed with correct GAV."""
        deliverable_dir = tmp_path / "TEST-build-output"
        repo_dir = deliverable_dir / "repository" / "com" / "example"

        # Version-level metadata (SNAPSHOT case)
        snapshot_dir = repo_dir / "artifact" / "1.0.0-SNAPSHOT"
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "maven-metadata.xml").write_text("<metadata/>")

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
            extracted_at="2026-06-27T12:00:00Z",
        )

        build = BuildOutput.from_extract_result(result, tmp_path)

        metadata = [a for a in build.artifacts if a.is_metadata]
        assert len(metadata) == 1
        m = metadata[0]
        assert m.group_id == "com.example"
        assert m.artifact_id == "artifact"
        assert m.version == "1.0.0-SNAPSHOT"

    def test_is_metadata_property(self, tmp_path: Path) -> None:
        """is_metadata returns True for XML, False for others."""
        xml_artifact = MavenArtifact(
            relative_path="com/example/artifact/maven-metadata.xml",
            file_path=tmp_path / "maven-metadata.xml",
            group_id="com.example",
            artifact_id="artifact",
            version="",
            classifier=None,
            extension="xml",
            md5=None,
            sha1=None,
            sha256=None,
        )
        jar_artifact = MavenArtifact(
            relative_path="com/example/artifact/1.0.0/artifact-1.0.0.jar",
            file_path=tmp_path / "artifact-1.0.0.jar",
            group_id="com.example",
            artifact_id="artifact",
            version="1.0.0",
            classifier=None,
            extension="jar",
            md5=None,
            sha1=None,
            sha256=None,
        )

        assert xml_artifact.is_metadata is True
        assert jar_artifact.is_metadata is False

    def test_metadata_checksum_sidecars_parsing(self, tmp_path: Path) -> None:
        """Parse metadata checksum sidecars with is_metadata == True."""
        deliverable_dir = tmp_path / "TEST-build-output"
        metadata_dir = (
            deliverable_dir / "repository" / "org" / "example" / "artifact"
        )
        metadata_dir.mkdir(parents=True)

        # Create maven-metadata.xml and its checksum sidecars
        (metadata_dir / "maven-metadata.xml").write_text("<metadata/>")
        (metadata_dir / "maven-metadata.xml.md5").write_text("md5checksum")
        (metadata_dir / "maven-metadata.xml.sha1").write_text("sha1checksum")

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
            extracted_at="2026-06-29T12:00:00Z",
        )

        build = BuildOutput.from_extract_result(result, tmp_path)

        # Verify all metadata artifacts
        metadata = [a for a in build.artifacts if a.is_metadata]
        assert len(metadata) == 3  # xml + md5 + sha1

        # Verify XML metadata
        xml_metadata = next(a for a in metadata if a.extension == "xml")
        assert xml_metadata.group_id == "org.example"
        assert xml_metadata.artifact_id == "artifact"
        assert xml_metadata.version == ""
        assert xml_metadata.file_path.name == "maven-metadata.xml"

        # Verify MD5 checksum metadata
        md5_metadata = next(a for a in metadata if a.extension == "md5")
        assert md5_metadata.group_id == "org.example"
        assert md5_metadata.artifact_id == "artifact"
        assert md5_metadata.version == ""
        assert md5_metadata.file_path.name == "maven-metadata.xml.md5"
        assert md5_metadata.is_metadata is True

        # Verify SHA1 checksum metadata
        sha1_metadata = next(a for a in metadata if a.extension == "sha1")
        assert sha1_metadata.group_id == "org.example"
        assert sha1_metadata.artifact_id == "artifact"
        assert sha1_metadata.version == ""
        assert sha1_metadata.file_path.name == "maven-metadata.xml.sha1"
        assert sha1_metadata.is_metadata is True


class TestRequireSbom:
    """Tests for require_sbom validation in BuildOutput.from_extract_result."""

    @pytest.fixture
    def extract_result(self) -> ExtractResult:
        """Create a minimal ExtractResult for SBOM validation tests."""
        return ExtractResult(
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

    def _make_repo(self, tmp_path: Path) -> Path:
        version_dir = (
            tmp_path
            / "TEST-build-output"
            / "repository"
            / "org"
            / "example"
            / "artifact"
            / "1.0.0"
        )
        version_dir.mkdir(parents=True)
        return version_dir

    def test_passes_when_sbom_present(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """require_sbom=True succeeds when SBOMs accompany JARs/POMs."""
        version_dir = self._make_repo(tmp_path)
        (version_dir / "artifact-1.0.0.jar").write_text("jar")
        (version_dir / "artifact-1.0.0.pom").write_text("<project/>")
        (version_dir / "artifact-1.0.0.cyclonedx.json").write_text("{}")

        build = BuildOutput.from_extract_result(
            extract_result, tmp_path, require_sbom=True
        )
        assert len(build.artifacts) == 3

    def test_raises_when_sbom_missing(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """require_sbom=True raises ValueError when no SBOMs exist."""
        version_dir = self._make_repo(tmp_path)
        (version_dir / "artifact-1.0.0.jar").write_text("jar")
        (version_dir / "artifact-1.0.0.pom").write_text("<project/>")

        with pytest.raises(ValueError, match="Missing SBOM artifacts for"):
            BuildOutput.from_extract_result(
                extract_result, tmp_path, require_sbom=True
            )

    def test_error_message_includes_gav(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """Error message includes the GAV coordinate that is missing SBOMs."""
        version_dir = self._make_repo(tmp_path)
        (version_dir / "artifact-1.0.0.jar").write_text("jar")

        with pytest.raises(ValueError, match="org.example:artifact:1.0.0"):
            BuildOutput.from_extract_result(
                extract_result, tmp_path, require_sbom=True
            )

    def test_default_false_allows_missing_sbom(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """Default require_sbom=False skips validation entirely."""
        version_dir = self._make_repo(tmp_path)
        (version_dir / "artifact-1.0.0.jar").write_text("jar")
        (version_dir / "artifact-1.0.0.pom").write_text("<project/>")

        build = BuildOutput.from_extract_result(extract_result, tmp_path)
        assert len(build.artifacts) == 2

    def test_multiple_gavs_partial_coverage(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """Raises when only some GAVs have SBOMs."""
        repo_base = (
            tmp_path / "TEST-build-output" / "repository" / "org" / "example"
        )

        # First artifact has SBOM
        v1 = repo_base / "artifact-a" / "1.0.0"
        v1.mkdir(parents=True)
        (v1 / "artifact-a-1.0.0.jar").write_text("jar")
        (v1 / "artifact-a-1.0.0.cyclonedx.json").write_text("{}")

        # Second artifact is missing SBOM
        v2 = repo_base / "artifact-b" / "2.0.0"
        v2.mkdir(parents=True)
        (v2 / "artifact-b-2.0.0.jar").write_text("jar")

        with pytest.raises(ValueError, match="artifact-b"):
            BuildOutput.from_extract_result(
                extract_result, tmp_path, require_sbom=True
            )

    def test_non_signable_files_ignored(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """Checksum sidecars without SBOMs do not trigger the check."""
        version_dir = self._make_repo(tmp_path)
        (version_dir / "artifact-1.0.0.jar").write_text("jar")
        (version_dir / "artifact-1.0.0.jar.md5").write_text("md5")
        (version_dir / "artifact-1.0.0.cyclonedx.json").write_text("{}")

        build = BuildOutput.from_extract_result(
            extract_result, tmp_path, require_sbom=True
        )
        assert any(a.extension == "jar" for a in build.artifacts)

    def test_empty_repo_passes(
        self, tmp_path: Path, extract_result: ExtractResult
    ) -> None:
        """No artifacts at all passes (nothing to validate)."""
        (tmp_path / "TEST-build-output" / "repository").mkdir(parents=True)

        build = BuildOutput.from_extract_result(
            extract_result, tmp_path, require_sbom=True
        )
        assert len(build.artifacts) == 0


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

    def test_from_file_without_pulp_labels(self, tmp_path: Path) -> None:
        """from_file() handles old JSON without pulp_labels field."""
        from slan_cuan.models import PublishResult

        old_json = {
            "pulp_url": "https://pulp.example.com",
            "distribution": "test-repo",
            "artifacts_uploaded": 5,
            "artifacts_skipped": 0,
            "coordinates": [
                {
                    "group_id": "org.example",
                    "artifact_id": "test",
                    "version": "1.0.0",
                }
            ],
            "published_at": "2026-06-22T12:00:00Z",
            "repository_version": (
                "/api/v3/repositories/maven/maven/abc/versions/1/"
            ),
            "content_unit_hrefs": ["/api/v3/content/abc/"],
        }

        file_path = tmp_path / "old-publish-result.json"
        file_path.write_text(json.dumps(old_json))

        loaded = PublishResult.from_file(file_path)

        assert loaded.pulp_labels is None
        assert loaded.pulp_url == "https://pulp.example.com"
        assert loaded.artifacts_uploaded == 5
