"""npm release upload command.

Uploads npm package tarballs to a Pulp npm repository via the synchronous
content upload API, applying the same idempotent exists/skip/replace/upload
decision tree as the bash originals it replaces: ``scripts/npm/npm-pulp-upload``
(the per-tarball loop) and ``scripts/npm/npm-release-upload`` (the thin
release-pipeline wrapper that decides whether to sign attestations first).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import click

from slan_cuan.http import parse_custom_headers
from slan_cuan.models import GlobalContext
from slan_cuan.npm.attestation import publish_attestation, sign_package
from slan_cuan.npm.metadata import read_package_metadata
from slan_cuan.oci import OrasError
from slan_cuan.pulp import FILE_REPO_API_PATH_TEMPLATE, PulpConfig, PulpError
from slan_cuan.pulp.clients.npm import PulpNpmClient
from slan_cuan.pulp.constants import (
    NPM_REPO_API_PATH_TEMPLATE,
    TASK_POLL_TIMEOUT_SECONDS,
)
from slan_cuan.utils import compute_checksum

#: SLSA predicate URI port of npm-common.sh's DEFAULT_ATTESTATION_PREDICATE_TYPE.
DEFAULT_ATTESTATION_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
#: Port of generate-and-sign-npm-attestations' BUILD_TYPE default.
DEFAULT_BUILD_TYPE = "https://konflux-ci.dev/NpmPackageBuild@v1"
#: Port of generate-and-sign-npm-attestations' BUILDER_ID default.
DEFAULT_BUILDER_ID = "https://konflux-ci.dev/calunga"
#: Port of generate-and-sign-npm-attestations' COSIGN_SECRET_DIR default.
DEFAULT_COSIGN_SECRET_DIR = Path("/etc/cosign-secret")

#: Pulp label key npm-pulp-upload sets from a *.tl-compliance.json sidecar.
COMPLIANCE_LABEL_KEY = "tl.compliance_level"
_COMPLIANCE_LEVEL_RE = re.compile(r"^L[123]$")
_MAX_COMPLIANCE_SIDECAR_BYTES = 1_048_576  # 1 MiB
_UNSAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9._@+-]+")


def _safe_segment(value: str) -> str:
    r"""Collapse a package-controlled string into one safe path segment.

    Port of npm-pulp-upload's ``safe_segment`` — strips anything outside
    the allowed charset so '/', '\\', '..' etc. in a package name/version
    cannot manipulate the Pulp relative_path.
    """
    out = _UNSAFE_SEGMENT_RE.sub("_", value).strip()
    if not out or out in (".", ".."):
        return "unknown"
    return out


def _sidecar_path(tgz_path: Path) -> Path:
    """Return the *.tl-compliance.json sidecar path for a .tgz file."""
    return tgz_path.with_suffix(".tl-compliance.json")


def _validate_compliance_sidecar(sidecar: Path) -> str | None:
    """Validate a compliance sidecar and return its compliance_level.

    Returns None when the sidecar does not exist.

    Raises:
        click.ClickException: If the sidecar is oversized, malformed, or its
            compliance_level is not one of L1/L2/L3.

    """
    if not sidecar.is_file():
        return None

    size = sidecar.stat().st_size
    if size > _MAX_COMPLIANCE_SIDECAR_BYTES:
        raise click.ClickException(
            f"compliance sidecar {sidecar} is {size} bytes "
            f"(max {_MAX_COMPLIANCE_SIDECAR_BYTES})"
        )

    try:
        data = json.loads(sidecar.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise click.ClickException(
            f"invalid compliance sidecar {sidecar}: {e}"
        ) from e

    if not isinstance(data, dict):
        raise click.ClickException(
            f"invalid compliance sidecar {sidecar}: sidecar root must be a "
            "JSON object"
        )

    level = data.get("compliance_level")
    if not isinstance(level, str) or not _COMPLIANCE_LEVEL_RE.match(level):
        raise click.ClickException(
            f"invalid compliance sidecar {sidecar}: compliance_level must "
            "be L1, L2, or L3"
        )
    return level


def _resolve_repository(
    client: PulpNpmClient, config: PulpConfig, name: str
) -> tuple[str, str]:
    """Resolve an npm repository's href and latest_version_href by name.

    Called fresh before each existence check (mirrors npm-pulp-upload's
    ``refresh_repository_version``) so uploads made earlier in the same run
    are visible to subsequent existence checks.

    Raises:
        click.ClickException: If the repository, its href, or its
            latest_version_href cannot be found.

    """
    url = NPM_REPO_API_PATH_TEMPLATE.format(domain=config.domain)
    rows = client.list_content(url, name=name)
    matches = [row for row in rows if row.get("name") == name]
    if not matches:
        raise click.ClickException(
            f"npm repository '{name}' not found. Check --pulp-repository."
        )
    row = matches[0]
    repo_href = row.get("pulp_href")
    version_href = row.get("latest_version_href")
    if not repo_href:
        raise click.ClickException(f"npm repository '{name}' has no pulp_href.")
    if not version_href:
        raise click.ClickException(
            f"npm repository '{name}' has no latest_version_href."
        )
    return str(repo_href), str(version_href)


def _resolve_file_repository_href(
    client: PulpNpmClient, config: PulpConfig, name: str
) -> str:
    """Resolve a Pulp File repository's href by name.

    Raises:
        click.ClickException: If the repository or its href cannot be found.

    """
    url = FILE_REPO_API_PATH_TEMPLATE.format(domain=config.domain)
    rows = client.list_content(url, name=name)
    matches = [row for row in rows if row.get("name") == name]
    if not matches:
        raise click.ClickException(
            f"file repository '{name}' not found. Check --pulp-file-repository."
        )
    href = matches[0].get("pulp_href")
    if not href:
        raise click.ClickException(f"file repository '{name}' has no pulp_href.")
    return str(href)


def _replace_existing_content(
    client: PulpNpmClient, repo_href: str, content_href: str
) -> None:
    """Remove mismatched content, destroy its version history, orphan-clean.

    Port of npm-pulp-upload's ``replace_existing_package``: the explicit
    remove-via-modify step creates a new repository version with
    content_href excluded (but everything else preserved); only then can
    the old versions still referencing content_href be safely destroyed and
    the artifact orphan-cleaned.
    """
    client.modify_repository(
        repo_href, [], remove_content_unit_hrefs=[content_href]
    )
    for version_href in client.list_repository_versions_holding(
        repo_href, content_href
    ):
        client.destroy_repository_version(version_href)
    client.orphan_cleanup([content_href])


def _upload_sidecar_best_effort(
    client: PulpNpmClient,
    file_repo_href: str | None,
    sidecar: Path,
    name: str,
    version: str,
) -> None:
    """Best-effort sidecar upload: warn and continue on PulpError.

    Matches npm-pulp-upload's ``upload_compliance_sidecar`` (bash
    ``|| echo "WARNING..."``) — never fails the enclosing package.
    """
    if file_repo_href is None or not sidecar.is_file():
        return
    digest = compute_checksum(sidecar, "sha256")
    relative_path = (
        f"npm-tl-compliance/{_safe_segment(name)}/{_safe_segment(version)}/"
        f"{digest}/{sidecar.name}"
    )
    try:
        client.upload_file_content(sidecar, file_repo_href, relative_path)
        click.echo(f"Uploaded compliance sidecar {sidecar} -> {relative_path}")
    except PulpError:
        click.echo(f"WARNING: could not upload compliance sidecar {sidecar}")


def _publish_attestation_if_present(
    client: PulpNpmClient,
    tgz_path: Path,
    content_href: str,
    name: str,
    version: str,
    *,
    attestation_prefix: str,
    require_attestations: bool,
    oras_options: str | None,
    verbose: bool,
) -> bool:
    """Publish a package's attestation OCI artifact if its .att exists.

    Returns False (caller fails the file) when REQUIRE_ATTESTATIONS is set
    and the .att is missing, or when the publish itself fails. Returns True
    on an unenforced skip or a successful publish.
    """
    att_path = tgz_path.with_name(tgz_path.name + ".att")
    if not att_path.is_file():
        if require_attestations:
            click.echo(
                f"ERROR: --require-attestations is set but missing {att_path}"
            )
            return False
        click.echo(f"  No {att_path}; skipping attestation OCI publish")
        return True

    try:
        publish_attestation(
            client,
            tgz_path,
            content_href,
            attestation_image_prefix=attestation_prefix,
            predicate_type=DEFAULT_ATTESTATION_PREDICATE_TYPE,
            name=name,
            version=version,
            oras_options=oras_options,
            verbose=verbose,
        )
    except (PulpError, OrasError) as e:
        click.echo(f"ERROR: failed to publish attestation for {tgz_path}: {e}")
        return False
    return True


def _process_one(
    client: PulpNpmClient,
    config: PulpConfig,
    tgz_path: Path,
    *,
    pulp_repository: str,
    file_repo_href: str | None,
    allow_content_replace: bool,
    attestation_prefix: str | None,
    require_attestations: bool,
    oras_options: str | None,
    verbose: bool,
) -> str:
    """Process one .tgz: exists-check, skip/replace/upload, attestation, sidecar.

    Returns "uploaded", "skipped", or "failed". Never raises — every error
    path is caught here so one bad file never aborts the batch. The catch
    is intentionally broad (not just PulpError/click.ClickException):
    reading a corrupt/truncated/non-gzip .tgz can raise tarfile.TarError
    (or other unexpected errors from a malformed Pulp response), and the
    bash original never aborts its loop for a single bad file either
    (``tar -xOf ... || true``-style per-file guards throughout).
    """
    try:
        return _process_one_inner(
            client,
            config,
            tgz_path,
            pulp_repository=pulp_repository,
            file_repo_href=file_repo_href,
            allow_content_replace=allow_content_replace,
            attestation_prefix=attestation_prefix,
            require_attestations=require_attestations,
            oras_options=oras_options,
            verbose=verbose,
        )
    except click.ClickException as e:
        click.echo(f"ERROR: {tgz_path}: {e.message}")
        return "failed"
    except Exception as e:
        # Intentionally broad: see docstring — one bad file must never
        # abort the batch, whatever kind of error it raises.
        click.echo(f"ERROR: {tgz_path}: {e}")
        return "failed"


def _process_one_inner(
    client: PulpNpmClient,
    config: PulpConfig,
    tgz_path: Path,
    *,
    pulp_repository: str,
    file_repo_href: str | None,
    allow_content_replace: bool,
    attestation_prefix: str | None,
    require_attestations: bool,
    oras_options: str | None,
    verbose: bool,
) -> str:
    name, version = read_package_metadata(tgz_path)
    compliance_level = _validate_compliance_sidecar(_sidecar_path(tgz_path))

    click.echo(f"Checking if {name}@{version} ({tgz_path}) exists in Pulp...")
    repo_href, version_href = _resolve_repository(client, config, pulp_repository)
    existing = client.find_by_name_version(name, version, version_href)

    if existing is not None:
        content_href = existing.get("pulp_href")
        if not content_href:
            click.echo(f"ERROR: no pulp_href for existing {name}@{version}")
            return "failed"
        content_href = str(content_href)
        # Port of the bash original's fallback: the Pulp npm list response
        # has been observed omitting `artifact`, so fetch the content
        # detail record by href when (and only when) it's missing.
        artifact_href = existing.get("artifact")
        if not artifact_href:
            artifact_href = client.get_content(content_href).get("artifact")
        if not artifact_href:
            click.echo(f"ERROR: no artifact href for existing {name}@{version}")
            return "failed"

        local_sha = compute_checksum(tgz_path, "sha256")
        remote_sha = client.get_artifact_sha256(str(artifact_href))

        if remote_sha == local_sha:
            click.echo(
                f"Skipping upload of {tgz_path} - identical content already "
                "in Pulp"
            )
            if compliance_level:
                client.set_label(
                    content_href, COMPLIANCE_LABEL_KEY, compliance_level
                )
            if not _publish_attestation_if_present(
                client,
                tgz_path,
                content_href,
                name,
                version,
                attestation_prefix=attestation_prefix or "",
                require_attestations=require_attestations,
                oras_options=oras_options,
                verbose=verbose,
            ):
                return "failed"
            _upload_sidecar_best_effort(
                client, file_repo_href, _sidecar_path(tgz_path), name, version
            )
            return "skipped"

        if not allow_content_replace:
            click.echo(
                f"ERROR: {name}@{version} digest mismatch and "
                "--allow-content-replace is not set"
            )
            return "failed"
        _replace_existing_content(client, repo_href, content_href)

    labels = (
        {COMPLIANCE_LABEL_KEY: compliance_level} if compliance_level else None
    )
    content_unit = client.upload_content(tgz_path, name, version, labels=labels)
    client.modify_repository(repo_href, [content_unit.pulp_href])
    click.echo(f"Uploaded {tgz_path} -> {content_unit.pulp_href}")

    if not _publish_attestation_if_present(
        client,
        tgz_path,
        content_unit.pulp_href,
        name,
        version,
        attestation_prefix=attestation_prefix or "",
        require_attestations=require_attestations,
        oras_options=oras_options,
        verbose=verbose,
    ):
        return "failed"

    _upload_sidecar_best_effort(
        client, file_repo_href, _sidecar_path(tgz_path), name, version
    )
    return "uploaded"


def _print_dry_run(
    tgz_files: list[Path],
    *,
    pulp_url: str,
    pulp_repository: str,
    pulp_file_repository: str | None,
    attestation_prefix: str | None,
    allow_content_replace: bool,
) -> None:
    """Describe what ``upload`` would do, without signing or any I/O."""
    for tgz_path in tgz_files:
        click.echo(
            f"Would upload {tgz_path} to Pulp npm repository "
            f"{pulp_repository} at {pulp_url}"
        )
        sidecar = _sidecar_path(tgz_path)
        if sidecar.exists():
            target = (
                f"and upload it to Pulp file repository {pulp_file_repository}"
                if pulp_file_repository
                else "(no --pulp-file-repository; sidecar upload skipped)"
            )
            click.echo(f"Would apply compliance label from {sidecar} {target}")
        if attestation_prefix:
            click.echo(
                f"Would sign {tgz_path} and publish its attestation under "
                f"{attestation_prefix}"
            )
    if allow_content_replace:
        click.echo(
            "Would replace existing same name@version content on digest "
            "mismatch (--allow-content-replace)"
        )


def _print_summary(
    uploaded: list[Path], skipped: list[Path], failed: list[Path]
) -> None:
    """Print the three-section Uploaded/Skipped/Failed summary."""
    click.echo("")
    click.echo("==============================")
    click.echo("  npm Pulp Upload Summary")
    click.echo("==============================")
    click.echo(f"Uploaded ({len(uploaded)}):")
    for f in uploaded:
        click.echo(f"  - {f}")
    click.echo(f"Skipped - already in Pulp ({len(skipped)}):")
    for f in skipped:
        click.echo(f"  - {f}")
    click.echo(f"Failed ({len(failed)}):")
    for f in failed:
        click.echo(f"  - {f}")


@click.command("upload")
@click.option(
    "--pulp-url",
    required=True,
    type=str,
    help="Pulp instance base URL (e.g. https://pulp.example.com).",
)
@click.option(
    "--pulp-repository",
    required=True,
    type=str,
    help="Pulp npm repository name to upload to.",
)
@click.option(
    "--pulp-file-repository",
    type=str,
    default=None,
    help=(
        "Optional Pulp File repository name for *.tl-compliance.json "
        "sidecar uploads. When unset, sidecar uploads are skipped "
        "(compliance labels still apply)."
    ),
)
@click.option(
    "--pulp-domain",
    required=True,
    type=str,
    help="Pulp domain for hosted content API (e.g. 'lightwell').",
)
@click.option(
    "--pulp-auth-type",
    type=click.Choice(["tbr", "cert"], case_sensitive=False),
    default="tbr",
    help="Pulp authentication method.",
)
@click.option(
    "--pulp-username",
    type=str,
    default=None,
    help="Username for TBR basic auth.",
)
@click.option(
    "--pulp-password",
    type=str,
    default=None,
    help="Password for TBR basic auth.",
)
@click.option(
    "--pulp-client-cert",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Client certificate path for entitlement cert auth.",
)
@click.option(
    "--pulp-client-key",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Client key path for entitlement cert auth.",
)
@click.option(
    "--pulp-task-timeout",
    type=click.FloatRange(min=1.0),
    default=TASK_POLL_TIMEOUT_SECONDS,
    show_default=True,
    help="Maximum time in seconds to wait for asynchronous Pulp tasks.",
)
@click.option(
    "--pulp-max-total-task-timeout",
    type=click.FloatRange(min=1.0),
    default=None,
    help=(
        "Absolute maximum time in seconds across all Pulp task state and "
        "blocker timeout resets. Defaults to twice the task timeout."
    ),
)
@click.option(
    "--pulp-custom-headers",
    default="",
    help=(
        "Custom HTTP headers to send on repository modify "
        "(CRLF/newline-delimited 'Key: Value' or JSON)."
    ),
)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification.",
)
@click.option(
    "--files-dir",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Directory tree containing *.tgz npm package tarballs.",
)
@click.option(
    "--allow-content-replace",
    is_flag=True,
    default=False,
    help=(
        "Replace same name@version content in Pulp when the local tarball "
        "sha256 differs (targeted orphan cleanup of that content unit "
        "only). Default: fail on digest mismatch."
    ),
)
@click.option(
    "--attestation-image-prefix",
    type=str,
    default=None,
    help=(
        "OCI repo prefix for attestation publish. Falls back to "
        "--compliance-image-prefix when unset. Empty skips sign + publish."
    ),
)
@click.option(
    "--compliance-image-prefix",
    type=str,
    default=None,
    help="Fallback OCI repo prefix for attestation publish (see above).",
)
@click.option(
    "--require-attestations",
    is_flag=True,
    default=False,
    help="Fail when signing material or .att files are missing.",
)
@click.option(
    "--cosign-key-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Local cosign keyfile override (default: <cosign-secret-dir>/cosign.key)."
    ),
)
@click.option(
    "--cosign-secret-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_COSIGN_SECRET_DIR,
    show_default=True,
    help=(
        "Directory holding cosign signing secrets (cosign.key, SIGN_KEY, "
        "REKOR_URL)."
    ),
)
@click.option(
    "--build-type",
    type=str,
    default=DEFAULT_BUILD_TYPE,
    show_default=True,
    help="SLSA buildDefinition.buildType URI.",
)
@click.option(
    "--builder-id",
    type=str,
    default=DEFAULT_BUILDER_ID,
    show_default=True,
    help="SLSA runDetails.builder.id URI.",
)
@click.option(
    "--release-time",
    type=str,
    default=None,
    help="Optional RFC3339 timestamp for runDetails.metadata.finishedOn.",
)
@click.option(
    "--oras-options",
    type=str,
    default=None,
    help="Extra oras options for attestation OCI publish.",
)
@click.pass_obj
def upload(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
    pulp_file_repository: str | None,
    pulp_domain: str,
    pulp_auth_type: str,
    pulp_username: str | None,
    pulp_password: str | None,
    pulp_client_cert: Path | None,
    pulp_client_key: Path | None,
    pulp_task_timeout: float,
    pulp_max_total_task_timeout: float | None,
    pulp_custom_headers: str,
    insecure: bool,
    files_dir: Path,
    allow_content_replace: bool,
    attestation_image_prefix: str | None,
    compliance_image_prefix: str | None,
    require_attestations: bool,
    cosign_key_path: Path | None,
    cosign_secret_dir: Path,
    build_type: str,
    builder_id: str,
    release_time: str | None,
    oras_options: str | None,
) -> None:
    """Upload npm package tarballs to a Pulp npm repository."""
    pulp_file_repository = (
        pulp_file_repository.strip() or None if pulp_file_repository else None
    )
    attestation_prefix = (
        attestation_image_prefix or compliance_image_prefix or ""
    ).strip() or None

    if not attestation_prefix and require_attestations:
        raise click.ClickException(
            "--require-attestations is set but neither "
            "--attestation-image-prefix nor --compliance-image-prefix was "
            "provided"
        )

    tgz_files = sorted(files_dir.rglob("*.tgz"))
    if not tgz_files:
        raise click.ClickException(f"No .tgz packages under {files_dir}")

    if ctx.dry_run:
        # Side-effect-free preview, matching extract's dry-run convention:
        # exit before any signing, Pulp, or OCI call.
        _print_dry_run(
            tgz_files,
            pulp_url=pulp_url,
            pulp_repository=pulp_repository,
            pulp_file_repository=pulp_file_repository,
            attestation_prefix=attestation_prefix,
            allow_content_replace=allow_content_replace,
        )
        return

    if attestation_prefix:
        click.echo(
            f"Generating npm package attestations (prefix={attestation_prefix})"
        )
        for tgz_path in tgz_files:
            sign_package(
                tgz_path,
                predicate_type=DEFAULT_ATTESTATION_PREDICATE_TYPE,
                build_type=build_type,
                builder_id=builder_id,
                cosign_key_path=cosign_key_path,
                cosign_secret_dir=cosign_secret_dir,
                release_time=release_time,
                require_attestations=require_attestations,
            )

    ca_cert = ctx.ca_cert if ctx.ca_cert and ctx.ca_cert.exists() else None
    config = PulpConfig(
        base_url=pulp_url,
        verify_ssl=not insecure,
        ca_cert=ca_cert,
        domain=pulp_domain,
        auth_type=pulp_auth_type,
        username=pulp_username,
        password=pulp_password,
        client_cert=pulp_client_cert,
        client_key=pulp_client_key,
        task_timeout=pulp_task_timeout,
        max_total_task_timeout=pulp_max_total_task_timeout,
        custom_headers=parse_custom_headers(pulp_custom_headers),
        verbose=ctx.verbose,
    )

    uploaded: list[Path] = []
    skipped: list[Path] = []
    failed: list[Path] = []

    with PulpNpmClient(config, pulp_repository) as client:
        file_repo_href = (
            _resolve_file_repository_href(client, config, pulp_file_repository)
            if pulp_file_repository
            else None
        )

        for tgz_path in tgz_files:
            status = _process_one(
                client,
                config,
                tgz_path,
                pulp_repository=pulp_repository,
                file_repo_href=file_repo_href,
                allow_content_replace=allow_content_replace,
                attestation_prefix=attestation_prefix,
                require_attestations=require_attestations,
                oras_options=oras_options,
                verbose=ctx.verbose,
            )
            {"uploaded": uploaded, "skipped": skipped, "failed": failed}[
                status
            ].append(tgz_path)

    _print_summary(uploaded, skipped, failed)

    if failed:
        raise click.ClickException(f"{len(failed)} upload(s) failed")
