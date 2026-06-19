"""OCI registry operations using the oras CLI."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from slan_cuan.models import ImageReference


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

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise OrasError(
            f"Invalid JSON in manifest response: {e}",
            result.stderr,
            1,  # Use returncode=1 for JSON parse errors
        ) from e
