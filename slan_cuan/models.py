"""Data models for the slan-cuan release pipeline."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImageReference:
    """Parsed OCI image reference."""

    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @classmethod
    def parse(cls, ref: str) -> ImageReference:
        """Parse an OCI image reference string.

        Supports:
        - registry/repo@sha256:digest (digest form)
        - registry/repo:tag (tag form)
        - registry/repo:tag@sha256:digest (both, tag ignored for pull)

        Args:
            ref: Image reference string to parse

        Returns:
            Parsed ImageReference object

        Raises:
            ValueError: If reference is invalid or has neither tag nor digest

        """
        if "@" in ref:
            # Has digest
            base_ref, digest = ref.rsplit("@", 1)
            if not digest.startswith("sha256:"):
                raise ValueError(f"Invalid digest format: {digest}")

            # Check for tag before digest
            if ":" in base_ref:
                registry_repo, tag = base_ref.rsplit(":", 1)
            else:
                registry_repo = base_ref
                tag = None
        elif ":" in ref:
            # Has tag, no digest
            # Need to distinguish registry:port from repo:tag
            parts = ref.split("/")
            if len(parts) < 2:
                raise ValueError(f"Invalid image reference: {ref}")

            # Last part contains :tag
            last_part = parts[-1]
            if ":" not in last_part:
                raise ValueError(f"Invalid image reference: {ref}")

            registry_repo, tag = ref.rsplit(":", 1)
            digest = None
        else:
            raise ValueError(f"Image reference must have tag or digest: {ref}")

        # Split registry from repository
        if "/" not in registry_repo:
            raise ValueError(f"Invalid image reference: {ref}")

        registry, repository = registry_repo.split("/", 1)

        # Validate we have tag or digest
        if tag is None and digest is None:
            raise ValueError(f"Image reference must have tag or digest: {ref}")

        return cls(
            registry=registry,
            repository=repository,
            tag=tag,
            digest=digest,
        )

    def __str__(self) -> str:
        """Return canonical reference string."""
        ref = f"{self.registry}/{self.repository}"
        if self.tag:
            ref = f"{ref}:{self.tag}"
        if self.digest:
            ref = f"{ref}@{self.digest}"
        return ref


@dataclass(frozen=True)
class LayerInfo:
    """Metadata for a single OCI artifact layer."""

    digest: str
    media_type: str
    size: int


@dataclass(frozen=True)
class ExtractResult:
    """Result manifest for the extract stage."""

    image: ImageReference
    manifest_digest: str
    layers: list[LayerInfo]
    annotations: dict[str, str]
    deliverable_dir: str
    files: list[str]
    extracted_at: str

    def to_json(self) -> str:
        """Serialize to JSON string.

        Returns:
            JSON string with 2-space indentation

        """
        data = asdict(self)
        # Convert ImageReference to dict manually for clean serialization
        data["image"] = {
            "registry": self.image.registry,
            "repository": self.image.repository,
            "tag": self.image.tag,
            "digest": self.image.digest,
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_file(cls, path: Path) -> ExtractResult:
        """Deserialize from a JSON file.

        Args:
            path: Path to the extract-result.json file

        Returns:
            Deserialized ExtractResult object

        Raises:
            FileNotFoundError: If file does not exist
            json.JSONDecodeError: If file contains invalid JSON
            KeyError: If required fields are missing

        """
        with path.open("r") as f:
            data = json.load(f)

        # Reconstruct ImageReference
        image_data = data["image"]
        image = ImageReference(
            registry=image_data["registry"],
            repository=image_data["repository"],
            tag=image_data.get("tag"),
            digest=image_data.get("digest"),
        )

        # Reconstruct LayerInfo list
        layers = [
            LayerInfo(
                digest=layer["digest"],
                media_type=layer["media_type"],
                size=layer["size"],
            )
            for layer in data["layers"]
        ]

        return cls(
            image=image,
            manifest_digest=data["manifest_digest"],
            layers=layers,
            annotations=data["annotations"],
            deliverable_dir=data["deliverable_dir"],
            files=data["files"],
            extracted_at=data["extracted_at"],
        )

    def save(self, path: Path) -> None:
        """Write JSON to file.

        Args:
            path: Path to write the JSON file

        """
        with path.open("w") as f:
            f.write(self.to_json())
