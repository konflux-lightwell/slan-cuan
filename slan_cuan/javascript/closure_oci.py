"""OCI artifact I/O for npm "Trusted Libraries" compliance closure.

Reads and writes the two OCI artifacts the closure system uses as its
durable store: a per-package compliance document (schema in
``closure_model.py``) and a single global closure index. Builds on
``slan_cuan.oci.pull``/``push`` (Task 4) for the actual registry I/O,
``slan_cuan.javascript.closure_model`` (Task 13) for the pure data shapes, and
``slan_cuan.javascript.closure_pulp`` (Task 14) for the Pulp-label side of
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
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import click

from slan_cuan import oci
from slan_cuan.javascript import closure_model, closure_pulp
from slan_cuan.javascript.closure_pulp import normalize_digest
from slan_cuan.models import parse_image_ref
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


def legacy_compliance_image_ref(
    name: str, version: str, compliance_image_prefix: str
) -> str | None:
    """Build the OCI reference the pre-port bash tool used, if it differs.

    Returns None when there is no distinct legacy tag (see
    ``closure_model.legacy_compliance_oci_tag``).
    """
    legacy_tag = closure_model.legacy_compliance_oci_tag(name, version)
    if legacy_tag is None:
        return None
    base = _strip_oci_tag_and_digest(compliance_image_prefix)
    return f"{base}:{legacy_tag}"


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
        oci.OrasError: If ``oras resolve`` exits non-zero. Classified via
            ``oci._classify_oras_error`` -- the same auth/not-found/
            network/generic classification ``oci.pull`` uses -- so
            ``_is_oras_not_found`` can tell a not-found resolve apart
            from a hard failure the same way it already does for pulls.

    """
    proc = subprocess.run(
        ["oras", "resolve", image_ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        raise oci._classify_oras_error(
            stderr or proc.stdout.strip(),
            proc.returncode,
            ref=image_ref,
            command="resolve",
            not_found_message=f"Image not found: {image_ref}",
            network_message=f"Network error resolving {image_ref}",
        )
    resolved = proc.stdout.strip()
    if "@" in resolved:
        return normalize_digest(resolved.rsplit("@", 1)[-1])
    return normalize_digest(resolved)


#: Registry ``NAME_UNKNOWN`` (a missing *repository*, not tag), which
#: ``oci.pull``/``_resolve_oras_digest`` deliberately leave in their generic
#: "oras <command> failed" bucket. For the closure index/sidecars a
#: never-created repo is the same "not seeded yet" state as a missing tag.
_ORAS_REPO_UNKNOWN_MARKERS = ("name unknown", "NAME_UNKNOWN")

#: Generic-failure message prefixes ``_classify_oras_error`` can produce for
#: the two oras subcommands this module drives directly (pull, resolve) --
#: used by ``_is_oras_not_found`` to spot the ``NAME_UNKNOWN`` case, which
#: ``_classify_oras_error`` doesn't itself label not-found.
_ORAS_GENERIC_FAILURE_PREFIXES = ("oras pull failed", "oras resolve failed")


def _is_oras_not_found(exc: oci.OrasError) -> bool:
    """Return True only when an oras pull/resolve failure means "not found".

    Relies on ``oci.pull``/``_resolve_oras_digest``'s own classification
    (``exc.message``): both label a 404/manifest-unknown reply, or real
    oras's trailing ``"<ref>: not found"``, as ``"Image not found: ..."``
    -- after auth, and before network, so an auth failure never counts as
    not-found and a ref embedding "timeout"/"connection" can't be
    mislabelled. The one local extension is a missing repository
    (``NAME_UNKNOWN``), which only ever appears in their generic
    ``"oras pull failed"``/``"oras resolve failed"`` message.
    """
    if exc.message.startswith("Image not found"):
        return True
    if not any(
        exc.message.startswith(prefix)
        for prefix in _ORAS_GENERIC_FAILURE_PREFIXES
    ):
        return False
    return any(m in (exc.stderr or "") for m in _ORAS_REPO_UNKNOWN_MARKERS)


def pull_json_artifact(
    image_ref: str,
    filename_suffix: str,
    auth_file: Path | None = None,
    verbose: bool = False,
) -> tuple[dict | None, str | None]:
    """Resolve, then pull-by-digest, an OCI artifact; parse its JSON sidecar.

    Resolves ``image_ref`` to its current digest FIRST, then pulls that
    exact immutable ``repo@digest`` reference (never the mutable tag) to a
    temporary directory via ``oci.pull``, finds the single file in it whose
    name ends with ``filename_suffix``, and parses it as JSON. Resolving
    before pulling, and pulling the resolved digest rather than the
    mutable tag, guarantees the returned ``(data, digest)`` pair describes
    the same immutable content regardless of any writer racing a new
    revision in between -- a concurrent writer can still win the race (our
    resolve loses to theirs, or vice versa), but whichever digest we
    resolve is the one we pull, so the pair is always self-consistent.

    Returns:
        ``(parsed_json, digest)``, or ``(None, None)`` when the image/
        manifest does not exist (a legitimate "not seeded yet" state) or
        no matching file is found in the pulled artifact.

    Raises:
        click.ClickException: The resolve or the pull failed for any
            reason other than "not found" (auth, network, unclassified).
            Treating those as "not seeded" would let ``cas_push_index``
            overwrite a real, populated index with an empty-plus-one-
            mutation one.

    """
    try:
        digest = _resolve_oras_digest(image_ref)
    except oci.OrasError as exc:
        if _is_oras_not_found(exc):
            return None, None
        raise click.ClickException(
            f"Failed to resolve {image_ref}: {exc.message}"
        ) from exc
    pinned_ref = f"{_strip_oci_tag_and_digest(image_ref)}@{digest}"
    with tempfile.TemporaryDirectory(prefix="npm-oras-pull.") as tmp:
        tmp_path = Path(tmp)
        try:
            oci.pull(
                parse_image_ref(pinned_ref),
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
        return data, digest


def _pull_legacy_compliance_json(
    name: str, version: str, compliance_image_prefix: str
) -> tuple[dict | None, str | None]:
    """Pull a compliance document from the legacy bash-tool tag, if valid.

    The legacy tag scheme was lossy (``@scope/pkg`` and ``scope-pkg`` shared
    one tag), so a document found there is only accepted when its own
    ``name``/``version`` match; otherwise it belongs to another package and
    is treated as absent.
    """
    legacy_ref = legacy_compliance_image_ref(
        name, version, compliance_image_prefix
    )
    if legacy_ref is None:
        return None, None
    raw, digest = pull_json_artifact(legacy_ref, ".tl-compliance.json")
    if raw is None:
        return None, None
    if raw.get("name") != name or raw.get("version") != version:
        return None, None
    return raw, digest


def pull_compliance_doc(
    name: str,
    version: str,
    compliance_image_prefix: str,
    pulp_href_fallback: str = "",
) -> tuple[dict | None, str | None]:
    """Pull and normalize a package's compliance document, if one exists.

    Reads the current (collision-free) tag first. If absent, falls back to
    the tag the pre-port bash tool published under (they differ for scoped
    names), so documents published before the cutover are not mistaken for
    unseeded packages -- their ``compliance_revision`` and gap history carry
    forward, and the next publish re-seeds them under the current tag.
    """
    raw, digest = pull_json_artifact(
        compliance_image_ref(name, version, compliance_image_prefix),
        ".tl-compliance.json",
    )
    if raw is None:
        raw, digest = _pull_legacy_compliance_json(
            name, version, compliance_image_prefix
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
    ``expected_revision``, then re-pull to verify the write actually landed
    (see ``_index_push_verified``). A push failure, or a push that a
    concurrent writer overwrote, is retried -- re-pull, re-mutate, re-push
    -- up to ``max_retries`` rounds, with linear backoff between rounds.

    ``oras push`` to a mutable tag never fails on a conflicting concurrent
    write, so without the verify step two writers that both pulled
    revision N would both "succeed" at pushing N+1 and the loser's
    mutation would silently vanish. This is detection, not true atomic
    compare-and-swap (that needs a server-side lock): a writer that lands
    between our verify re-pull and return is not caught.

    Raises:
        click.ClickException: The push never succeeded and verified within
            ``max_retries`` rounds.

    ``max_retries`` defaults (when ``None``) to
    ``closure_pulp.DEFAULT_CAS_MAX_RETRIES`` -- the single
    ``CLOSURE_CAS_MAX_RETRIES``-sourced ceiling shared by every closure CAS
    loop -- resolved at call time.

    """
    max_retries = _resolve_max_retries(max_retries)
    result: dict[str, tuple[dict, str]] = {}

    def _round(_attempt: int) -> tuple[bool, str]:
        index, _digest = pull_index(compliance_image_prefix, closure_index_image)
        expected = index["revision"]
        updated = mutator(copy.deepcopy(index))
        updated["revision"] = expected
        try:
            pushed, digest = publish_index(
                updated,
                compliance_image_prefix=compliance_image_prefix,
                closure_index_image=closure_index_image,
                expected_revision=expected,
            )
        except oci.OrasError as exc:
            return False, str(exc)
        current, current_digest = pull_index(
            compliance_image_prefix, closure_index_image
        )
        if _index_push_verified(pushed, digest, current, current_digest):
            result["value"] = (pushed, digest)
            return True, ""
        reason = (
            f"pushed revision {pushed['revision']} ({digest}) was not "
            f"live on re-pull (found revision {current['revision']}, "
            f"{current_digest}); a concurrent writer likely overwrote it"
        )
        return False, reason

    closure_pulp.run_cas_rounds(max_retries, _round, retry_label="Index CAS")
    return result["value"]


def _index_push_verified(
    pushed: dict,
    pushed_digest: str,
    current: dict,
    current_digest: str | None,
) -> bool:
    """Return True if a re-pulled index confirms our push landed.

    Confirmed when the live artifact is exactly the one we pushed (same
    digest), or when its revision is strictly past ours -- some writer has
    since pushed a higher revision, so ours is no longer the latest either
    way. Note this is a heuristic, not a guarantee the later revision was
    built on top of ours: with three or more racing writers, a later
    revision can be built on a different writer's overwrite of ours,
    which this check cannot distinguish from a revision built on ours.

    A revision-only ``>=`` check is NOT enough here: two writers that both
    pulled revision N both push N+1, so the loser re-pulls N+1 and would
    wrongly "verify". At equal revision only a digest match proves the
    live index is ours. A missing index (no ``current_digest``) or a
    lower revision never verifies.
    """
    if not current_digest:
        return False
    # oci.push's digest regex is case-insensitive; oras resolve is lower.
    if normalize_digest(current_digest).lower() == (
        normalize_digest(pushed_digest).lower()
    ):
        return True
    return int(current["revision"]) > int(pushed["revision"])


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
    result: dict[str, str] = {}

    def _round(_attempt: int) -> tuple[bool, str]:
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
            result["digest"] = digest
            return True, ""
        return False, f"{name}@{version}"

    closure_pulp.run_cas_rounds(max_retries, _round, retry_label="Compliance CAS")
    return result["digest"]
