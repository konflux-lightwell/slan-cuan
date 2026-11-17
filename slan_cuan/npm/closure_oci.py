"""OCI artifact I/O for npm "Trusted Libraries" compliance closure.

Reads and writes the two OCI artifacts the closure system uses as its
durable store: a per-package compliance document (schema in
``closure_model.py``) and a single global closure index. Builds on
``slan_cuan.oci.pull``/``push`` (Task 4) for the actual registry I/O,
``slan_cuan.npm.closure_model`` (Task 13) for the pure data shapes, and
``slan_cuan.npm.closure_pulp`` (Task 14) for the Pulp-label side of
publishing a compliance document.

Direct port of ``scripts/npm/update-npm-closure``'s OCI-facing functions
(lines 683-865), with two deliberate signature changes carried over from
this plan's pre-flight review:

* Every function that needs the compliance-image prefix takes it as an
  explicit parameter instead of reading ``COMPLIANCE_IMAGE_PREFIX`` (or
  ``CLOSURE_INDEX_IMAGE``) from the environment directly. ``closure.py``
  (Task 16, the CLI layer) is the single place those env vars get read.
  In particular, ``registry_url`` is accepted exactly as the caller
  passes it and forwarded as-is to
  ``closure_model.doc_to_compliance_json`` -- this module does **not**
  re-apply the original script's ``.rstrip("/")`` on it. That stripping
  is the CLI layer's job (see Task 16 / ``closure_model.doc_to_compliance_json``'s
  own docstring for the same note).
* Every ``SystemExit`` the original raised is now a ``click.ClickException``,
  since this module backs CLI commands.

``slan_cuan.oci`` has no ``resolve`` primitive (adding one is out of scope
for this plan, and ``oci.pull`` does not return a digest), so
``_resolve_oras_digest`` below shells out to ``oras resolve`` directly --
a private stopgap, not a shared primitive, mirroring the original script's
``oras_resolve_digest`` (lines 706-711).
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import click

from slan_cuan import oci
from slan_cuan.models import parse_image_ref
from slan_cuan.npm import closure_model, closure_pulp
from slan_cuan.npm.closure_pulp import normalize_digest
from slan_cuan.pulp.clients.npm import PulpNpmClient

#: oras ``--artifact-type`` for a package's compliance-document artifact.
COMPLIANCE_ARTIFACT_TYPE = "application/vnd.npm.tl-compliance+json"

#: Sidecar filename the global closure index is pushed/pulled under.
INDEX_FILENAME = "npm-closure-index.json"

#: oras ``--artifact-type`` for the global closure-index artifact. Not an
#: env-var override like the original script's ``CLOSURE_INDEX_ARTIFACT_TYPE``
#: -- env reads belong to the CLI layer (Task 16), not here.
_CLOSURE_INDEX_ARTIFACT_TYPE = "application/vnd.npm.closure-index+json"

#: Annotation stamped on every compliance/index artifact pushed here.
_ARTIFACT_TITLE_ANNOTATION = {
    "org.opencontainers.image.title": "npm-closure-artifact"
}


def _strip_oci_tag_and_digest(prefix: str) -> str:
    """Strip a trailing ``:tag``/``@digest`` from an OCI image reference.

    Factors out the stripping logic the original script duplicated
    inline in both ``compliance_image_ref`` and ``closure_index_image_ref``
    (lines 127-149).
    """
    base = prefix
    if "@" in prefix and not prefix.endswith("@"):
        base = prefix.split("@", 1)[0]
    if ":" in base.rsplit("/", 1)[-1]:
        base = base.rsplit(":", 1)[0]
    return base


def compliance_image_ref(
    name: str, version: str, compliance_image_prefix: str
) -> str:
    """Build the OCI reference for a package's compliance-document artifact.

    Any trailing ``:tag``/``@digest`` on ``compliance_image_prefix`` is
    stripped before the package-specific tag is appended.
    """
    base = _strip_oci_tag_and_digest(compliance_image_prefix)
    return f"{base}:{closure_model.compliance_oci_tag(name, version)}"


def closure_index_image_ref(
    compliance_image_prefix: str, closure_index_image: str = ""
) -> str:
    """Build the OCI reference for the global closure-index artifact.

    ``closure_index_image``, when set, is returned verbatim (an explicit
    override). Otherwise the reference is derived from
    ``compliance_image_prefix`` with its trailing ``:tag``/``@digest``
    stripped, plus a fixed ``/npm-closure-index:latest`` suffix.
    """
    if closure_index_image:
        return closure_index_image
    base = _strip_oci_tag_and_digest(compliance_image_prefix)
    return f"{base}/npm-closure-index:latest"


def _resolve_oras_digest(image_ref: str) -> str:
    """Shell out to ``oras resolve`` to get an image reference's digest.

    Stopgap for the fact that ``slan_cuan.oci`` has no ``resolve``
    primitive and ``oci.pull`` does not return a digest -- private to
    this module, not a shared primitive (see module docstring).

    Raises:
        click.ClickException: If ``oras resolve`` exits non-zero.

    """
    proc = subprocess.run(
        ["oras", "resolve", image_ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise click.ClickException(
            f"oras resolve failed for {image_ref}: "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    resolved = proc.stdout.strip()
    if "@" in resolved:
        return normalize_digest(resolved.rsplit("@", 1)[-1])
    return normalize_digest(resolved)


#: Markers (in ``OrasError.stderr``) of a registry "does not exist" reply:
#: a missing tag/manifest, or (registry ``NAME_UNKNOWN``) a missing repo.
_ORAS_NOT_FOUND_MARKERS = (
    "404 Not Found",
    "manifest unknown",
    "name unknown",
    "NAME_UNKNOWN",
    "MANIFEST_UNKNOWN",
)

#: What real oras (1.3.0, against Quay) actually prints for a missing tag:
#: ``Error response from registry: <ref>: not found``. Anchored to the end
#: of stderr so an unrelated "not found" mid-message can't match.
_ORAS_TRAILING_NOT_FOUND = re.compile(r":\s*not found\s*$")


def _is_oras_not_found(exc: oci.OrasError) -> bool:
    """Return True only when an ``oras pull`` failure means "not found".

    ``oci.pull`` classifies a 404/manifest-unknown reply as an
    ``"Image not found: ..."`` message; auth (401) is classified first, so
    an auth failure never counts as not-found here. A missing repository
    (``NAME_UNKNOWN``), which ``oci.pull`` lumps into its generic message,
    is also treated as not-found.

    Real oras output for a missing tag (``"...: <ref>: not found"``)
    matches none of those, so it is also recognized by its trailing
    ``: not found``. That check runs before the network-error short-circuit
    because ``oci.pull`` labels any stderr containing "network"/
    "connection"/"timeout" a network error -- and the echoed ref embeds the
    npm package name (e.g. ``timeout-signal``).
    """
    stderr = exc.stderr or ""
    if exc.message.startswith("Authentication failed"):
        return False
    if _ORAS_TRAILING_NOT_FOUND.search(stderr):
        return True
    if exc.message.startswith("Network error"):
        return False
    if exc.message.startswith("Image not found"):
        return True
    return any(marker in stderr for marker in _ORAS_NOT_FOUND_MARKERS)


def pull_json_artifact(
    image_ref: str,
    filename_suffix: str,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> tuple[dict | None, str | None]:
    """Pull an OCI artifact and parse its one JSON sidecar file.

    Pulls ``image_ref`` to a temporary directory via ``oci.pull``, finds
    the single file in it whose name ends with ``filename_suffix``,
    parses it as JSON, and resolves the image's digest.

    Returns:
        ``(parsed_json, digest)``, or ``(None, None)`` when the image/
        manifest does not exist (a legitimate "not seeded yet" state) or
        no matching file is found in the pulled artifact.

    Raises:
        click.ClickException: The pull failed for any reason other than
            "not found" (auth, network, unclassified). Treating those as
            "not seeded" would let ``cas_push_index`` overwrite a real,
            populated index with an empty-plus-one-mutation one.

    """
    with tempfile.TemporaryDirectory(prefix="npm-oras-pull.") as tmp:
        tmp_path = Path(tmp)
        try:
            oci.pull(
                parse_image_ref(image_ref),
                tmp_path,
                auth_file=auth_file,
                verbose=verbose,
            )
        except oci.OrasError as exc:
            if _is_oras_not_found(exc):
                return None, None
            raise click.ClickException(
                f"Failed to pull {image_ref}: {exc.message}"
            ) from exc
        match = next(
            (
                entry
                for entry in sorted(tmp_path.iterdir())
                if entry.name.endswith(filename_suffix) and entry.is_file()
            ),
            None,
        )
        if match is None:
            return None, None
        data = json.loads(match.read_text(encoding="utf-8"))
        digest = _resolve_oras_digest(image_ref)
        return data, digest


def pull_compliance_doc(
    name: str,
    version: str,
    compliance_image_prefix: str,
    pulp_href_fallback: str = "",
) -> tuple[dict | None, str | None]:
    """Pull and normalize a package's compliance document, if one exists."""
    raw, digest = pull_json_artifact(
        compliance_image_ref(name, version, compliance_image_prefix),
        ".tl-compliance.json",
    )
    if raw is None:
        return None, None
    doc = closure_model.normalize_doc(raw)
    if pulp_href_fallback and not doc.get("pulp_href"):
        doc["pulp_href"] = pulp_href_fallback
    return doc, digest


def pull_index(
    compliance_image_prefix: str, closure_index_image: str = ""
) -> tuple[dict, str | None]:
    """Pull and normalize the global closure index.

    Returns ``closure_model.empty_index()`` (with digest ``None``) when
    the index artifact has not been seeded yet.
    """
    raw, digest = pull_json_artifact(
        closure_index_image_ref(compliance_image_prefix, closure_index_image),
        INDEX_FILENAME,
    )
    if raw is None:
        return closure_model.empty_index(), None
    return closure_model.normalize_index(raw), digest


def push_json_artifact(
    image_ref: str,
    filename: str,
    payload: dict,
    *,
    artifact_type: str,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> str:
    """Write ``payload`` to a temp file and push it as an OCI artifact.

    Returns:
        The normalized ``sha256:...`` digest of the pushed artifact.

    """
    with tempfile.TemporaryDirectory(prefix="npm-oras-push.") as tmp:
        path = Path(tmp) / filename
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return oci.push(
            path,
            image_ref,
            artifact_type=artifact_type,
            annotations=_ARTIFACT_TITLE_ANNOTATION,
            auth_file=auth_file,
            verbose=verbose,
        )


def publish_compliance_doc(
    client: PulpNpmClient,
    doc: dict,
    repo: dict,
    *,
    compliance_image_prefix: str,
    registry_url: str,
) -> str:
    """Push a compliance document and sync its Pulp CAS labels.

    Resolves ``doc["pulp_href"]`` via ``closure_pulp.find_content_in_repo``
    when it is not already set (and stamps it onto ``doc`` when found), then
    calls ``closure_pulp.sync_content_pulp_labels`` with the pushed digest
    when an href is known.

    Returns:
        The normalized ``sha256:...`` digest of the pushed compliance
        document.

    """
    image_ref = compliance_image_ref(
        doc["name"], doc["version"], compliance_image_prefix
    )
    payload = closure_model.doc_to_compliance_json(
        doc, registry_url=registry_url, compliance_oci=image_ref
    )
    digest = push_json_artifact(
        image_ref,
        closure_model.compliance_filename(doc["name"], doc["version"]),
        payload,
        artifact_type=COMPLIANCE_ARTIFACT_TYPE,
    )
    href = doc.get("pulp_href")
    if not href:
        content = closure_pulp.find_content_in_repo(
            client, doc["name"], doc["version"], repo["latest_version_href"]
        )
        if content:
            href = content.get("pulp_href") or ""
            doc["pulp_href"] = href
    if href:
        closure_pulp.sync_content_pulp_labels(
            client,
            href,
            repo["latest_version_href"],
            doc["name"],
            doc["version"],
            doc.get("compliance_level"),
            digest,
        )
    return digest


def publish_index(
    index: dict,
    *,
    compliance_image_prefix: str,
    closure_index_image: str = "",
    expected_revision: int | None = None,
) -> tuple[dict, str]:
    """Normalize, revision-bump, and push the global closure index.

    When ``expected_revision`` is given and doesn't match the index's
    current revision, the index's revision is forced to
    ``expected_revision`` before bumping -- the single-writer-per-round
    half of ``cas_push_index``'s CAS protocol.

    Returns:
        ``(pushed_index, digest)`` -- the index as pushed (including its
        bumped revision and refreshed ``updated_at``) and its digest.

    """
    index = closure_model.normalize_index(index)
    if expected_revision is not None and index["revision"] != expected_revision:
        index["revision"] = expected_revision
    index["revision"] = int(index["revision"]) + 1
    index["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    digest = push_json_artifact(
        closure_index_image_ref(compliance_image_prefix, closure_index_image),
        INDEX_FILENAME,
        index,
        artifact_type=_CLOSURE_INDEX_ARTIFACT_TYPE,
    )
    return index, digest


def _resolve_max_retries(max_retries: int | None) -> int:
    """Return ``max_retries``, or the shared env-sourced default if None.

    Reuses ``closure_pulp.DEFAULT_CAS_MAX_RETRIES`` (read once from
    ``CLOSURE_CAS_MAX_RETRIES``) rather than re-reading the env var here,
    so the label CAS and both OCI CAS loops always agree.
    """
    if max_retries is None:
        return closure_pulp.DEFAULT_CAS_MAX_RETRIES
    return max_retries


def cas_push_index(
    mutator: Callable[[dict], dict],
    *,
    compliance_image_prefix: str,
    closure_index_image: str = "",
    max_retries: int | None = None,
) -> tuple[dict, str]:
    """Pull-mutate-push the closure index with optimistic-concurrency retry.

    Each round: pull the current index, run ``mutator`` on a deep copy of
    it, pin the mutated copy's revision back to what was just pulled, and
    push via ``publish_index`` with that pulled revision as
    ``expected_revision``. A push failure (e.g. a concurrent writer's push
    landed first) is retried, up to ``max_retries`` rounds, with linear
    backoff between rounds.

    Raises:
        click.ClickException: The push never succeeded within
            ``max_retries`` rounds.

    ``max_retries`` defaults (when ``None``) to
    ``closure_pulp.DEFAULT_CAS_MAX_RETRIES`` -- the single
    ``CLOSURE_CAS_MAX_RETRIES``-sourced ceiling shared by every closure CAS
    loop -- resolved at call time.

    """
    max_retries = _resolve_max_retries(max_retries)
    for attempt in range(max_retries):
        index, _digest = pull_index(compliance_image_prefix, closure_index_image)
        expected = index["revision"]
        updated = mutator(copy.deepcopy(index))
        updated["revision"] = expected
        try:
            return publish_index(
                updated,
                compliance_image_prefix=compliance_image_prefix,
                closure_index_image=closure_index_image,
                expected_revision=expected,
            )
        except oci.OrasError as exc:
            if attempt + 1 >= max_retries:
                raise click.ClickException(
                    f"Index CAS failed after {max_retries} retries: {exc}"
                ) from exc
            click.echo(
                f"Index CAS retry {attempt + 1}/{max_retries}: {exc}",
                err=True,
            )
            time.sleep(0.2 * (attempt + 1))
    raise click.ClickException(f"Index CAS failed after {max_retries} retries")


def cas_publish_compliance(
    client: PulpNpmClient,
    doc: dict,
    repo: dict,
    *,
    compliance_image_prefix: str,
    registry_url: str,
    max_retries: int | None = None,
) -> str:
    """Publish a compliance document with revision-conflict retry.

    Each round: pull whatever compliance document currently exists for
    ``doc["name"]``/``doc["version"]``; if one does, bump ``doc``'s
    ``compliance_revision`` strictly past it (never regressing it
    downward), carry over its ``direct_dependencies``/``assessed_at``
    when ``doc`` doesn't already have its own, then publish and re-pull to
    verify the published revision actually landed (``>=`` the one we
    meant to publish) before returning.

    Mutates ``doc`` in place across rounds (the original script's
    behavior), so the caller's dict reflects the final published
    ``compliance_revision``/``pulp_href``/etc. on return.

    Returns:
        The normalized ``sha256:...`` digest of the published compliance
        document.

    Raises:
        click.ClickException: The published revision never verified as
            landed within ``max_retries`` rounds.

    ``max_retries`` defaults (when ``None``) to
    ``closure_pulp.DEFAULT_CAS_MAX_RETRIES``, as for ``cas_push_index``.

    """
    max_retries = _resolve_max_retries(max_retries)
    name, version = doc["name"], doc["version"]
    for attempt in range(max_retries):
        existing, _ = pull_compliance_doc(
            name, version, compliance_image_prefix, doc.get("pulp_href") or ""
        )
        if existing:
            expected_rev = int(existing.get("compliance_revision") or 1)
            if int(doc.get("compliance_revision") or 1) <= expected_rev:
                doc["compliance_revision"] = expected_rev + 1
            doc["direct_dependencies"] = (
                existing.get("direct_dependencies")
                or doc.get("direct_dependencies")
                or []
            )
            if not doc.get("assessed_at"):
                doc["assessed_at"] = existing.get("assessed_at")
        digest = publish_compliance_doc(
            client,
            doc,
            repo,
            compliance_image_prefix=compliance_image_prefix,
            registry_url=registry_url,
        )
        verify, _ = pull_compliance_doc(
            name, version, compliance_image_prefix, doc.get("pulp_href") or ""
        )
        if verify and int(verify.get("compliance_revision") or 0) >= int(
            doc.get("compliance_revision") or 0
        ):
            return digest
        if attempt + 1 >= max_retries:
            raise click.ClickException(
                f"Compliance CAS failed for {name}@{version}"
            )
        click.echo(
            f"Compliance CAS retry {attempt + 1}/{max_retries} "
            f"for {name}@{version}",
            err=True,
        )
        time.sleep(0.2 * (attempt + 1))
    raise click.ClickException(f"Compliance CAS failed for {name}@{version}")
