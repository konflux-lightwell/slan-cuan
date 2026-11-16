"""OCI registry operations using the oras CLI."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import click

from slan_cuan.models import ImageReference
from slan_cuan.utils import safe_json_load


class OrasError(Exception):
    """Exception raised when an oras command fails."""

    def __init__(self, message: str, stderr: str, returncode: int) -> None:
        """Initialize OrasError.

        Args:
            message: Human-readable error message
            stderr: Raw stderr from oras command
            returncode: Exit code from oras command

        """
        super().__init__(message)
        self.message = message
        self.stderr = stderr
        self.returncode = returncode


def pull(
    image: ImageReference,
    output_dir: Path,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> None:
    """Pull an OCI artifact using oras and extract to output directory.

    Args:
        image: OCI image reference to pull
        output_dir: Directory to extract artifacts to
        auth_file: Optional path to registry auth file
        verbose: Whether to log the oras command

    Raises:
        OrasError: If oras command fails

    """
    cmd = ["oras", "pull", str(image), "--output", str(output_dir)]
    if auth_file:
        cmd.extend(["--registry-config", str(auth_file)])

    if verbose:
        print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()

        # Parse stderr for specific error conditions
        if "401 Unauthorized" in stderr or "authentication required" in stderr:
            raise OrasError(
                f"Authentication failed for {image}",
                stderr,
                result.returncode,
            )
        elif "404 Not Found" in stderr or "manifest unknown" in stderr:
            raise OrasError(
                f"Image not found: {image}",
                stderr,
                result.returncode,
            )
        elif (
            "network" in stderr.lower()
            or "connection" in stderr.lower()
            or "timeout" in stderr.lower()
        ):
            raise OrasError(
                f"Network error pulling {image}",
                stderr,
                result.returncode,
            )
        else:
            raise OrasError(
                f"oras pull failed: {stderr}",
                stderr,
                result.returncode,
            )


def blob_fetch(
    reference: str,
    output_file: Path,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> None:
    """Fetch a single blob from an OCI registry.

    Runs ``oras blob fetch <reference> --output <output_file>``.

    Args:
        reference: Registry reference including digest
                   (e.g. ``registry/repo@sha256:abc...``)
        output_file: Local path to write the blob to
        auth_file: Optional path to registry auth file
        verbose: Whether to log the oras command

    Raises:
        OrasError: If oras command fails

    """
    cmd = ["oras", "blob", "fetch", reference, "--output", str(output_file)]
    if auth_file:
        cmd.extend(["--registry-config", str(auth_file)])

    if verbose:
        print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()

        if "401 Unauthorized" in stderr or "authentication required" in stderr:
            raise OrasError(
                f"Authentication failed for {reference}",
                stderr,
                result.returncode,
            )
        elif "404 Not Found" in stderr or "manifest unknown" in stderr:
            raise OrasError(
                f"Blob not found: {reference}",
                stderr,
                result.returncode,
            )
        elif (
            "network" in stderr.lower()
            or "connection" in stderr.lower()
            or "timeout" in stderr.lower()
        ):
            raise OrasError(
                f"Network error fetching blob {reference}",
                stderr,
                result.returncode,
            )
        else:
            raise OrasError(
                f"oras blob fetch failed: {stderr}",
                stderr,
                result.returncode,
            )


def manifest_fetch(
    image: ImageReference,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> dict:
    """Fetch the OCI manifest for an image.

    Args:
        image: OCI image reference
        auth_file: Optional path to registry auth file
        verbose: Whether to log the oras command

    Returns:
        Parsed OCI manifest as a dictionary

    Raises:
        OrasError: If oras command fails

    """
    cmd = ["oras", "manifest", "fetch", str(image)]
    if auth_file:
        cmd.extend(["--registry-config", str(auth_file)])

    if verbose:
        print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()

        # Parse stderr for specific error conditions
        if "401 Unauthorized" in stderr or "authentication required" in stderr:
            raise OrasError(
                f"Authentication failed for {image}",
                stderr,
                result.returncode,
            )
        elif "404 Not Found" in stderr or "manifest unknown" in stderr:
            raise OrasError(
                f"Image not found: {image}",
                stderr,
                result.returncode,
            )
        elif (
            "network" in stderr.lower()
            or "connection" in stderr.lower()
            or "timeout" in stderr.lower()
        ):
            raise OrasError(
                f"Network error fetching manifest for {image}",
                stderr,
                result.returncode,
            )
        else:
            raise OrasError(
                f"oras manifest fetch failed: {stderr}",
                stderr,
                result.returncode,
            )

    return safe_json_load(
        result.stdout,
        parse_err_msg="Invalid JSON in manifest response",
        raise_type=OrasError,
        stderr=result.stderr,
        returncode=1,
    )


def discover(
    image: ImageReference,
    artifact_type: str,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> list[dict]:
    """Discover referrers of an OCI artifact by artifact type.

    Args:
        image: OCI image reference to discover referrers for
        artifact_type: OCI artifact type to filter by
        auth_file: Optional path to registry auth file
        verbose: Whether to log the oras command

    Returns:
        List of referrer descriptors (each with digest, artifactType, etc.)

    Raises:
        OrasError: If oras command fails

    """
    cmd = [
        "oras",
        "discover",
        str(image),
        "--artifact-type",
        artifact_type,
        "--format",
        "json",
    ]
    if auth_file:
        cmd.extend(["--registry-config", str(auth_file)])

    if verbose:
        print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()

        if "401 Unauthorized" in stderr or "authentication required" in stderr:
            raise OrasError(
                f"Authentication failed for {image}",
                stderr,
                result.returncode,
            )
        elif "404 Not Found" in stderr or "manifest unknown" in stderr:
            raise OrasError(
                f"Image not found: {image}",
                stderr,
                result.returncode,
            )
        elif (
            "network" in stderr.lower()
            or "connection" in stderr.lower()
            or "timeout" in stderr.lower()
        ):
            raise OrasError(
                f"Network error discovering referrers for {image}",
                stderr,
                result.returncode,
            )
        else:
            raise OrasError(
                f"oras discover failed: {stderr}",
                stderr,
                result.returncode,
            )

    data = safe_json_load(
        result.stdout,
        parse_err_msg="Invalid JSON in discover response",
        raise_type=OrasError,
        stderr=result.stderr,
        returncode=1,
    )

    referrers = data.get("referrers", [])
    if not isinstance(referrers, list):
        return []
    return referrers


def push(
    path: Path,
    target_ref: str,
    *,
    artifact_type: str | None = None,
    annotations: dict[str, str],
    auth_file: Path | None = None,
    verbose: bool = False,
) -> str:
    """Push an artifact to an OCI registry using oras.

    Args:
        path: Local path to the artifact file to push
        target_ref: OCI registry reference (e.g.,
                    registry/repo:tag or registry/repo@sha256:...)
        artifact_type: Optional artifact type for the OCI artifact
        annotations: Dictionary of key=value annotations for the artifact
                     (required, can be empty)
        auth_file: Optional path to registry auth file
        verbose: Whether to log the oras command

    Returns:
        The normalized sha256:... digest of the pushed artifact

    Raises:
        OrasError: If oras command fails or digest cannot be extracted

    """
    # Build the command: oras push <target_ref> [--artifact-type <t>]
    # --annotation k=v ... <path.name>
    cmd = ["oras", "push", target_ref]

    if artifact_type:
        cmd.extend(["--artifact-type", artifact_type])

    # Add annotations
    for key, value in annotations.items():
        cmd.extend(["--annotation", f"{key}={value}"])

    if auth_file:
        cmd.extend(["--registry-config", str(auth_file)])

    # Add bare filename, not full path
    cmd.append(path.name)

    if verbose:
        print(f"Running: {' '.join(cmd)}")

    # Run with cwd set to parent directory
    result = subprocess.run(
        cmd,
        cwd=path.parent,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()

        # Parse stderr for specific error conditions
        if "401 Unauthorized" in stderr or "authentication required" in stderr:
            raise OrasError(
                f"Authentication failed for {target_ref}",
                stderr,
                result.returncode,
            )
        elif "404 Not Found" in stderr or "manifest unknown" in stderr:
            raise OrasError(
                f"Image not found: {target_ref}",
                stderr,
                result.returncode,
            )
        elif (
            "network" in stderr.lower()
            or "connection" in stderr.lower()
            or "timeout" in stderr.lower()
        ):
            raise OrasError(
                f"Network error pushing {target_ref}",
                stderr,
                result.returncode,
            )
        else:
            raise OrasError(
                f"oras push failed: {stderr}",
                stderr,
                result.returncode,
            )

    # Extract digest from stdout+stderr via regex
    # Looking for "Digest: sha256:..." pattern
    combined_output = result.stdout + result.stderr
    digest_match = re.search(
        r"^Digest:\s*(sha256:[a-f0-9]{64})\s*$",
        combined_output,
        re.IGNORECASE | re.MULTILINE,
    )

    if digest_match:
        return digest_match.group(1)

    # Fallback: oras resolve to get the digest from the ref
    resolve_cmd = ["oras", "resolve", target_ref]
    if auth_file:
        resolve_cmd.extend(["--registry-config", str(auth_file)])

    if verbose:
        print(f"Running: {' '.join(resolve_cmd)}")

    resolve_result = subprocess.run(
        resolve_cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if resolve_result.returncode == 0:
        # Extract digest from output like "registry/repo@sha256:..."
        resolve_match = re.search(
            r"(sha256:[a-f0-9]{64})",
            resolve_result.stdout,
            re.IGNORECASE,
        )
        if resolve_match:
            return resolve_match.group(1)

    # Could not extract digest from either push or resolve
    raise OrasError(
        "Could not extract digest from push or resolve",
        result.stderr,
        1,
    )


def deduplicate_referrers(
    referrers: list[dict],
    art_type: str,
    img_ref: ImageReference,
    registry_auth_file: Path | None = None,
    verbose: bool = False,
    manifest_fetch_fn: Callable[..., dict] = manifest_fetch,
) -> dict | None:
    """Resolve referrers to a single one if layer blobs are identical.

    Returns the selected referrer descriptor, or None if no valid referrers
    exist. Raises click.ClickException if distinct artifact blob sets exist.
    """
    valid_referrers = [r for r in referrers if r.get("digest")]
    if not valid_referrers:
        return None

    # Fast path 1: Only 1 referrer
    if len(valid_referrers) == 1:
        return valid_referrers[0]

    # Fast path 2: All referrers point to the exact same manifest digest
    unique_manifest_digests = {r["digest"]: r for r in valid_referrers}
    if len(unique_manifest_digests) == 1:
        if verbose:
            click.echo(
                f"  Found {len(valid_referrers)} referrers for '{art_type}' "
                f"with identical manifest digest; deduplicating."
            )
        return next(iter(unique_manifest_digests.values()))

    # Slow path: Fetch raw manifests and compare layer/config digests
    blob_digests_seen: dict[tuple[str, ...], dict] = {}
    for ref_digest, ref_desc in unique_manifest_digests.items():
        ref_img = ImageReference(
            registry=img_ref.registry,
            repository=img_ref.repository,
            tag=None,
            digest=ref_digest,
        )
        ref_manifest_raw = manifest_fetch_fn(
            ref_img,
            auth_file=registry_auth_file,
            verbose=verbose,
        )

        layers_raw = ref_manifest_raw.get("layers", [])
        if isinstance(layers_raw, list) and layers_raw:
            layer_digests = tuple(
                str(layer["digest"])
                for layer in layers_raw
                if isinstance(layer, dict) and "digest" in layer
            )
        else:
            # For 0-layer artifacts or index manifests, fall back to
            # config digest or raw manifest digest
            config_digest = (
                ref_manifest_raw.get("config", {}).get("digest")
                if isinstance(ref_manifest_raw.get("config"), dict)
                else None
            )
            layer_digests = (config_digest or ref_digest,)

        if layer_digests not in blob_digests_seen:
            blob_digests_seen[layer_digests] = ref_desc

    if len(blob_digests_seen) > 1:
        raise click.ClickException(
            f"Expected at most 1 unique artifact for type '{art_type}', "
            f"found {len(blob_digests_seen)} distinct blob sets across "
            f"{len(valid_referrers)} referrers."
        )

    if verbose:
        click.echo(
            f"  Found {len(valid_referrers)} referrers for '{art_type}' "
            f"with identical layer blobs; deduplicating."
        )
    return next(iter(blob_digests_seen.values()))
