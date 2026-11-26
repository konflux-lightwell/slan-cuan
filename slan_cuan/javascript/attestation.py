"""npm package attestation signing and publishing.

Generates a SLSA provenance predicate for an npm package tarball, signs it
with cosign as a DSSE envelope (``<tgz>.att``), then publishes that
envelope to an OCI registry via ``oras`` and records the resulting digest
as Pulp labels on the package's content unit.

Direct port of ``scripts/npm/generate-and-sign-npm-attestations`` (signing)
and ``scripts/npm/npm-attestation-publish`` (publishing), including the
shared helpers from ``scripts/npm/npm-common.sh``
(``normalize_oci_registry_base``, ``attestation_oci_tag``).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import click

from slan_cuan import oci
from slan_cuan.javascript.metadata import read_package_metadata
from slan_cuan.pulp.clients.npm import PulpNpmClient
from slan_cuan.pulp.exceptions import PulpError

#: Cosign DSSE envelope content type (not a Sigstore Bundle).
DEFAULT_ATTESTATION_ARTIFACT_TYPE = "application/vnd.in-toto.dsse+json"

_OCI_TAG_MAX_LENGTH = 128
_OCI_TAG_INVALID_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")
_OCI_TAG_FIRST_CHAR_RE = re.compile(r"^[A-Za-z0-9_]")

_LABEL_OCI_REGISTRY_BASE = "lw.oci_registry_base"
_LABEL_ATTESTATION_OCI_DIGEST = "lw.attestation_oci_digest"
_LABEL_ATTESTATION_PREDICATE_TYPE = "lw.attestation_predicate_type"

_AWS_ENV_FILES = (
    "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
)


def normalize_oci_registry_base(prefix: str) -> str:
    """Strip a trailing ``:tag`` / ``@digest`` from an OCI image prefix.

    Port of ``npm-common.sh``'s ``normalize_oci_registry_base``. A
    trailing ``@...`` is stripped unless the prefix ends in a bare ``@``
    (nothing to strip), and a trailing ``:tag`` on the last path segment
    is stripped.

    Args:
        prefix: An OCI image reference, with or without a tag/digest.

    Returns:
        The bare ``registry/repo`` base.

    """
    base = prefix
    if "@" in prefix and not prefix.endswith("@"):
        base = prefix.rsplit("@", 1)[0]
    last_segment = base.rsplit("/", 1)[-1]
    if ":" in last_segment:
        base = base.rsplit(":", 1)[0]
    return base


def attestation_oci_tag(name: str, version: str) -> str:
    """Build the mutable OCI tag used for a package's attestation artifact.

    Port of ``npm-common.sh``'s ``attestation_oci_tag``. Scoped names
    (``@scope/pkg``) have their leading ``@`` stripped and ``/`` replaced
    with ``--`` so a scoped and unscoped name can never collide (e.g.
    ``@a/b`` and ``a-b`` tag differently). The result is sanitized to the
    OCI tag charset (``[A-Za-z0-9._-]``, first character
    ``[A-Za-z0-9_]``) and capped at 128 characters.

    Args:
        name: npm package name, scoped or unscoped.
        version: npm package version (may include semver build metadata).

    Returns:
        A sanitized, length-capped OCI tag.

    """
    if name.startswith("@"):
        raw = f"{name[1:].replace('/', '--')}-{version}-att"
    else:
        raw = f"{name}-{version}-att"

    sanitized = _OCI_TAG_INVALID_CHARS_RE.sub("-", raw)
    if not _OCI_TAG_FIRST_CHAR_RE.match(sanitized):
        sanitized = f"_{sanitized}"
    return sanitized[:_OCI_TAG_MAX_LENGTH]


def _build_predicate(
    *, build_type: str, builder_id: str, release_time: str | None
) -> dict:
    """Build the in-toto SLSA provenance predicate dict for signing.

    ``metadata.finishedOn`` is omitted (not set to an empty value) when
    ``release_time`` is unset, so re-signing an unchanged tarball produces
    a content-stable predicate.
    """
    metadata: dict[str, str] = {}
    if release_time:
        metadata["finishedOn"] = release_time
    return {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": {},
            "resolvedDependencies": [],
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": metadata,
        },
    }


def _resolve_sign_mode(
    *,
    cosign_key_path: Path,
    cosign_secret_dir: Path,
    require_attestations: bool,
) -> tuple[list[str], list[str], dict[str, str]] | None:
    """Determine cosign key/rekor args and env overrides for signing.

    Sign-mode precedence (first match wins):
      1. A local keyfile at ``cosign_key_path`` — Rekor upload only when
         ``{cosign_secret_dir}/REKOR_URL`` is present/non-empty, else a
         warning is printed to stderr and ``--tlog-upload=false`` is used
         (dev/offline only).
      2. ``{cosign_secret_dir}/SIGN_KEY`` (AWS KMS ARN/URI) — AWS_* env
         vars exported from sibling files when present; REKOR_URL is
         REQUIRED here (KMS signing must upload to Rekor).
      3. Neither present — a warning is printed to stderr and ``None`` is
         returned, unless ``require_attestations`` is ``True``.

    Returns:
        ``(key_args, rekor_args, env_overrides)`` or ``None`` if no
        signing material is found.

    Raises:
        click.ClickException: If ``require_attestations`` is ``True`` and
            no signing material is found, or KMS mode is selected without
            a non-empty ``REKOR_URL``.

    """
    rekor_url_path = cosign_secret_dir / "REKOR_URL"

    if cosign_key_path.is_file():
        key_args = ["--key", str(cosign_key_path)]
        rekor_url = (
            rekor_url_path.read_text().strip() if rekor_url_path.is_file() else ""
        )
        if rekor_url:
            rekor_args = [f"--rekor-url={rekor_url}"]
        else:
            click.echo(
                f"WARNING: keyfile signing without {rekor_url_path}; "
                "using --tlog-upload=false (dev/offline only)",
                err=True,
            )
            rekor_args = ["--tlog-upload=false"]
        return key_args, rekor_args, {}

    sign_key_path = cosign_secret_dir / "SIGN_KEY"
    if sign_key_path.is_file():
        env_overrides: dict[str, str] = {}
        for env_key in _AWS_ENV_FILES:
            env_file = cosign_secret_dir / env_key
            if env_file.is_file():
                env_overrides[env_key] = env_file.read_text().strip()

        rekor_url = (
            rekor_url_path.read_text().strip() if rekor_url_path.is_file() else ""
        )
        if not rekor_url:
            raise click.ClickException(
                "KMS signing requires non-empty "
                f"{rekor_url_path} for transparency-log upload "
                "(found SIGN_KEY but no Rekor URL)"
            )

        sign_key = sign_key_path.read_text().strip()
        return ["--key", sign_key], [f"--rekor-url={rekor_url}"], env_overrides

    msg = f"No cosign signing material at {cosign_key_path} or {sign_key_path}"
    if require_attestations:
        raise click.ClickException(msg)
    click.echo(
        f"WARNING: {msg} — skipping attestation "
        f"(require_attestations={require_attestations})",
        err=True,
    )
    return None


def _cosign_supports_use_signing_config() -> bool:
    """Probe whether the installed cosign understands ``--use-signing-config``.

    Port of the bash original's defensive probe:
    ``cosign attest-blob --help 2>&1 | grep -q -- '--use-signing-config'``.
    Newer cosign versions default to a "signing config" mode that then
    requires ``--bundle``, which would silently break the classic
    DSSE-via-``--output-signature`` output this module relies on (a prior
    incident this probe exists to prevent). When the flag exists,
    ``sign_package`` adds ``--use-signing-config=false`` to keep writing
    classic DSSE envelopes.
    """
    result = subprocess.run(
        ["cosign", "attest-blob", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    combined_output = (result.stdout or "") + (result.stderr or "")
    return "--use-signing-config" in combined_output


def sign_package(
    tgz_path: Path,
    *,
    predicate_type: str,
    build_type: str,
    builder_id: str,
    cosign_key_path: Path | None,
    cosign_secret_dir: Path,
    release_time: str | None,
    require_attestations: bool,
) -> Path | None:
    """Generate and sign a SLSA provenance attestation for one tarball.

    Builds the in-toto predicate, signs it with ``cosign attest-blob``
    using whichever signing material is available (see
    ``_resolve_sign_mode`` for precedence), validates the resulting DSSE
    envelope shape, and writes it to ``<tgz_path>.att``.

    Args:
        tgz_path: Path to the npm ``.tgz`` tarball being attested.
        predicate_type: SLSA predicate URI (cosign ``--type=``).
        build_type: SLSA ``buildDefinition.buildType`` URI.
        builder_id: SLSA ``runDetails.builder.id`` URI.
        cosign_key_path: Local cosign keyfile path override. Defaults to
            ``{cosign_secret_dir}/cosign.key`` when ``None``.
        cosign_secret_dir: Directory holding cosign signing secrets
            (``cosign.key``, ``SIGN_KEY``, ``REKOR_URL``, AWS_* files).
        release_time: Optional RFC3339 timestamp for
            ``runDetails.metadata.finishedOn``. Omitted when unset.
        require_attestations: If ``True``, raise when no signing material
            is found instead of skipping.

    Returns:
        Path to the written ``<tgz_path>.att`` DSSE envelope, or ``None``
        if no signing material was found and ``require_attestations`` is
        ``False``.

    Raises:
        click.ClickException: If signing material requirements aren't
            met (see ``_resolve_sign_mode``), ``cosign`` fails, or its
            output isn't a valid DSSE envelope.

    """
    resolved_key_path = cosign_key_path or (cosign_secret_dir / "cosign.key")
    sign_mode = _resolve_sign_mode(
        cosign_key_path=resolved_key_path,
        cosign_secret_dir=cosign_secret_dir,
        require_attestations=require_attestations,
    )
    if sign_mode is None:
        return None
    key_args, rekor_args, env_overrides = sign_mode

    predicate = _build_predicate(
        build_type=build_type, builder_id=builder_id, release_time=release_time
    )

    env = os.environ.copy()
    env.update(env_overrides)

    att_path = tgz_path.with_name(tgz_path.name + ".att")

    with tempfile.TemporaryDirectory(prefix="slan-cuan-npm-attest-") as tmp_dir:
        predicate_file = Path(tmp_dir) / "predicate.json"
        predicate_file.write_text(json.dumps(predicate))
        dsse_file = Path(tmp_dir) / "dsse.json"

        cosign_bundle_args = (
            ["--use-signing-config=false"]
            if _cosign_supports_use_signing_config()
            else []
        )

        cmd = [
            "cosign",
            "attest-blob",
            str(tgz_path),
            f"--predicate={predicate_file}",
            f"--type={predicate_type}",
            *key_args,
            "--yes",
            *rekor_args,
            *cosign_bundle_args,
            f"--output-signature={dsse_file}",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, env=env
        )
        if result.returncode != 0:
            raise click.ClickException(
                f"Failed to sign attestation for {tgz_path}: "
                f"{result.stderr.strip()}"
            )

        try:
            dsse_content = dsse_file.read_text()
            dsse_data = json.loads(dsse_content)
        except (OSError, json.JSONDecodeError) as e:
            raise click.ClickException(
                f"cosign wrote non-DSSE attestation output for {tgz_path}: {e}"
            ) from e

        payload = (
            dsse_data.get("payload") if isinstance(dsse_data, dict) else None
        )
        signatures = (
            dsse_data.get("signatures") if isinstance(dsse_data, dict) else None
        )
        if not (isinstance(payload, str) and payload) or not (
            isinstance(signatures, list) and signatures
        ):
            raise click.ClickException(
                f"cosign wrote non-DSSE attestation output for {tgz_path} "
                "(expected payload+signatures via --output-signature)"
            )

        att_path.write_text(dsse_content)

    return att_path


def publish_attestation(
    client: PulpNpmClient,
    tgz_path: Path,
    content_href: str,
    *,
    attestation_image_prefix: str,
    predicate_type: str,
    artifact_type: str = DEFAULT_ATTESTATION_ARTIFACT_TYPE,
    name: str | None = None,
    version: str | None = None,
    oras_options: str | None = None,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> str:
    """Push a signed attestation to an OCI registry and label the package.

    Port of ``npm-attestation-publish``: resolves the package name and
    version when not already known, pushes ``<tgz_path>.att`` to a
    content-addressed tag under ``attestation_image_prefix``, then
    records the pushed digest and metadata as labels on the Pulp content
    unit at ``content_href``.

    Args:
        client: Pulp npm client used for the label writes.
        tgz_path: Path to the npm ``.tgz`` tarball (its ``.att`` sibling
            is what actually gets pushed).
        content_href: Pulp content unit href to label.
        attestation_image_prefix: OCI repo (optionally with a tag/digest,
            which is stripped) to push the attestation under.
        predicate_type: SLSA predicate URI recorded as a label. Must
            match what was passed to ``sign_package`` as ``--type=`` at
            sign time.
        artifact_type: oras ``--artifact-type`` for the push.
        name: npm package name. Read from the tarball when omitted.
        version: npm package version. Read from the tarball when omitted.
        oras_options: Accepted for interface parity with the legacy
            ``ORAS_OPTIONS`` escape hatch; ``slan_cuan.oci.push`` has no
            equivalent extra-flags mechanism, so this is currently unused.
        auth_file: Optional path to a registry auth file.
        verbose: Whether to log the oras command.

    Returns:
        The normalized ``sha256:...`` digest of the pushed attestation.

    Raises:
        click.ClickException: If the package name/version can't be read
            from the tarball, or if the content unit at ``content_href``
            vanishes (HTTP 404) between the OCI push and a label write
            (concurrent deletion race).
        slan_cuan.oci.OrasError: If the oras push fails.
        slan_cuan.pulp.exceptions.PulpError: If a label write fails for
            any reason other than a 404.

    """
    del oras_options  # unused: see docstring

    if name is None or version is None:
        name, version = read_package_metadata(tgz_path)

    registry_base = normalize_oci_registry_base(attestation_image_prefix)
    image_ref = f"{registry_base}:{attestation_oci_tag(name, version)}"

    att_path = tgz_path.with_name(tgz_path.name + ".att")

    digest = oci.push(
        att_path,
        image_ref,
        artifact_type=artifact_type,
        annotations={
            "org.opencontainers.image.title": "npm-package-attestation",
            "dev.lightwell.npm.name": name,
            "dev.lightwell.npm.version": version,
        },
        auth_file=auth_file,
        verbose=verbose,
    )

    try:
        client.set_labels(
            content_href,
            {
                _LABEL_OCI_REGISTRY_BASE: registry_base,
                _LABEL_ATTESTATION_OCI_DIGEST: digest,
                _LABEL_ATTESTATION_PREDICATE_TYPE: predicate_type,
            },
        )
    except PulpError as exc:
        if exc.status_code == 404:
            raise click.ClickException(
                f"content unit {content_href} vanished before attestation "
                f"labels (digest {digest}) could be written"
            ) from exc
        raise

    return digest
