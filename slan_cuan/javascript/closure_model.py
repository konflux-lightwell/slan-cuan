"""Pure data model for npm "Trusted Libraries" compliance closure.

Schema v3 (an upstream ``assess`` step writes the initial doc; a closure
updater mutates gap lists + level only):

  direct_dependencies  immutable [{name, requested}] from package.json
  missing_gaps         mutable [name@version, ...] not on TL yet
  pending_l3_gaps      mutable [name@version, ...] on TL but not L3
  compliance_level     L1 if missing_gaps; L2 if pending_l3_gaps; else L3

The global closure index (a separate OCI artifact) maps a blocker
``name@version`` key to the set of parent ``name@version`` keys waiting on
it: ``{"entries": {blocker_key: {"parents": [...]}}}``.

This module is intentionally side-effect-free: every function takes plain
dicts/strings/lists and returns the same, with no I/O, subprocess, HTTP, or
environment reads. That is what keeps it cheaply, independently testable,
and is the reason it is split out from ``closure_pulp.py``/``closure_oci.py``
(Pulp- and OCI/env-touching siblings). In particular, ``compliance_oci`` is
always accepted as a parameter rather than computed here — computing it
requires reading a compliance-image-prefix value, which belongs to
``closure_oci.py``.

Direct port of ``scripts/npm/update-npm-closure``'s same-named functions
(lines 68-354 and 930-1014), with every ``SystemExit`` converted to
``click.ClickException`` since this module backs CLI commands.
"""

from __future__ import annotations

import copy
import hashlib
import re
import time

import click

from slan_cuan.javascript.semver import max_satisfying

#: Internal compliance-document schema version this module reads/writes.
SCHEMA_VERSION = 3

#: Closure index schema version.
INDEX_SCHEMA_VERSION = 1

#: Pulp label recording a package's sticky compliance level (L1/L2/L3).
COMPLIANCE_LABEL = "lw.compliance_level"

#: OCI distribution-spec tag constraints used by ``compliance_oci_tag``.
_OCI_TAG_MAX_LENGTH = 128
_OCI_TAG_VALID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")
_OCI_TAG_INVALID_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")
_OCI_TAG_FIRST_CHAR_RE = re.compile(r"^[A-Za-z0-9_]")

#: Name of the python-wheels Pulp repository. javascript commands refuse to
#: operate against it (port of the original script's
#: ``npm_repository_name`` guard against a misconfigured PULP_REPOSITORY).
PYTHON_WHEELS_REPOSITORY = "main"


def assert_not_python_wheels_repository(repository: str) -> None:
    """Fail closed if a javascript command targets the python-wheels repository.

    Port of ``scripts/npm/update-npm-closure``'s ``npm_repository_name``
    guard, shared by ``javascript upload`` and the ``javascript closure``
    write commands. Callers run it before any Pulp/OCI I/O (and before the
    ``--dry-run`` early exit).

    Raises:
        click.ClickException: ``repository`` is the python-wheels repo.

    """
    if repository.strip().lower() == PYTHON_WHEELS_REPOSITORY:
        raise click.ClickException(
            "Refusing to operate against the python-wheels Pulp repository "
            f"(PULP_REPOSITORY={PYTHON_WHEELS_REPOSITORY}) - this is almost "
            "certainly a misconfiguration for a javascript release. Check "
            "--pulp-repository."
        )


def is_npm_alias_spec(spec: str) -> bool:
    """Return True if ``spec`` is an npm alias spec (``npm:name@range``).

    A package.json dependency value like ``"npm:real-pkg@^1.2.0"`` means
    "install ``real-pkg`` at this range, but refer to it locally under a
    different key name." Its real registry identity (name + version) is
    different from the dependency's own key name, so closure/compliance
    gap tracking -- which keys everything by ``name@version`` of the
    actual registry package -- must not build a node key directly from
    an alias dependency's own name and this raw spec string: doing so
    would both corrupt ``node_key``/``parse_node_key`` round-tripping
    (the spec itself contains an ``@``) and mix an alias's local name
    with a different package's real identity.

    Callers record such a dependency as a missing gap keyed by
    ``node_key(dep_name, UNVERIFIABLE_ALIAS_VERSION)`` instead, so the
    parent fails closed (stays below L3) rather than skipping it.
    """
    return spec.startswith("npm:")


#: Sentinel "version" for the missing-gap entry recorded for an npm alias
#: dependency. Its real target is never verified, so the gap must never
#: clear: the sentinel contains no ``@`` (``node_key``/``parse_node_key``
#: round-trip cleanly), is not a parseable semver version or range (so
#: ``npm_version_satisfies`` never matches a real release against it),
#: and ``find_index_blocker_keys_for_release`` refuses to match it at all.
UNVERIFIABLE_ALIAS_VERSION = "unverifiable-npm-alias"


def alias_gap_key(dep_name: str) -> str:
    """Return the permanently-unresolvable gap key for an alias dependency.

    Keyed by the dependency's LOCAL name (its ``package.json`` key), not
    the alias's real target package, so ``validate_gap_subset``'s
    "gap names are direct dependencies" invariant still holds.
    """
    return node_key(dep_name, UNVERIFIABLE_ALIAS_VERSION)


def node_key(name: str, version: str) -> str:
    """Build a closure graph key from a package name and version."""
    return f"{name}@{version}"


def parse_node_key(key: str) -> tuple[str, str]:
    """Split a closure graph key back into (name, version).

    Uses ``rsplit("@", 1)`` so a scoped package name's own leading ``@``
    (e.g. ``@scope/pkg@1.0.0``) does not get mistaken for the separator.
    """
    name, version = key.rsplit("@", 1)
    return name, version


def _gap_name(key: str) -> str:
    """Return just the package name half of a gap/blocker key."""
    return parse_node_key(key)[0]


def npm_version_satisfies(version: str, spec: str) -> bool:
    """Check whether version is the max satisfying release for spec.

    ``spec`` may be an exact version (matched by string equality) or an
    npm semver range (matched via ``slan_cuan.javascript.semver.max_satisfying``).
    """
    if version == spec:
        return True
    return max_satisfying([version], spec) == version


def compliance_oci_tag(name: str, version: str) -> str:
    """Build the OCI tag used for a package's compliance-document artifact.

    A plain unscoped ``name-version`` whose characters are all OCI-tag-safe
    (``[A-Za-z0-9._-]``, first character ``[A-Za-z0-9_]``, at most 128
    chars) is used verbatim, e.g. ``lodash-4.17.21``.

    Anything else -- a scoped name, or a name/version needing sanitization
    or truncation -- gets a readable, sanitized base (scoped ``@scope/pkg``
    becomes ``scope--pkg``, invalid characters become ``-``) plus an
    ``_<16 hex>`` suffix: the first 16 hex chars of the SHA-256 of
    ``name@version``. That keeps lossy encodings collision-free: ``@scope/
    pkg``, ``scope-pkg``, and ``scope--pkg`` all tag differently, as do
    ``1.0.0+build.1`` and ``1.0.0-build.1``. A suffixed tag can never equal
    a verbatim one, since a verbatim tag always ends in a semver version
    (which contains ``.`` and never ``_``) while the suffix is dot-free hex
    after an ``_``.

    Deliberately a separate tag namespace from
    ``slan_cuan.javascript.attestation.attestation_oci_tag`` (``-att`` suffix,
    no hash): the compliance and attestation artifacts for the same
    package@version are different OCI refs.
    """
    raw = f"{name}-{version}"
    if (
        not name.startswith("@")
        and len(raw) <= _OCI_TAG_MAX_LENGTH
        and _OCI_TAG_VALID_RE.fullmatch(raw)
    ):
        return raw

    readable = name[1:].replace("/", "--") if name.startswith("@") else name
    base = _OCI_TAG_INVALID_CHARS_RE.sub("-", f"{readable}-{version}")
    if not _OCI_TAG_FIRST_CHAR_RE.match(base):
        base = f"_{base}"
    digest = hashlib.sha256(node_key(name, version).encode()).hexdigest()
    suffix = f"_{digest[:16]}"
    return base[: _OCI_TAG_MAX_LENGTH - len(suffix)] + suffix


def compliance_filename(name: str, version: str) -> str:
    """Build the sidecar filename for a package's compliance document."""
    return f"{compliance_oci_tag(name, version)}.tl-compliance.json"


def compute_level(doc: dict) -> str:
    """Derive the sticky compliance level from a doc's gap lists.

    ``"L1"`` if any gaps are still missing from TL entirely, else
    ``"L2"`` if any gaps are on TL but not yet L3, else ``"L3"``.
    """
    if doc.get("missing_gaps"):
        return "L1"
    if doc.get("pending_l3_gaps"):
        return "L2"
    return "L3"


def normalize_gap_list(value: list | None) -> list[str]:
    """Normalize a gap list to a sorted, deduplicated list of node keys.

    Accepts either a list of ``name@version`` strings, a list of
    ``{"name": ..., "version"|"requested": ...}`` dicts, or a mix of the
    two (dropping any dict entry missing a usable name or version).
    """
    if not value or not isinstance(value, list):
        return []
    out = []
    for item in value:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or ""
            version = item.get("version") or item.get("requested") or ""
            if name and version:
                out.append(node_key(name, version))
    return sorted(set(out))


def normalize_direct_dependencies(value: list | None) -> list[dict]:
    """Normalize direct_dependencies to a list of ``{name, requested}``.

    Non-dict entries, and entries missing a usable name or requested
    spec, are dropped.
    """
    if not value:
        return []
    out = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        requested = item.get("requested") or item.get("version") or ""
        if name and requested:
            out.append({"name": name, "requested": requested})
    return out


def normalize_doc(doc: dict) -> dict:
    """Normalize a v1/v2/v3-shaped compliance doc to the internal v3 shape.

    Migrates the legacy ``closure_gaps`` field (v1 shape) into
    ``missing_gaps`` when both ``missing_gaps`` and ``pending_l3_gaps``
    are absent from the input. Does not mutate the input dict.
    """
    doc = copy.deepcopy(doc)
    missing = normalize_gap_list(doc.get("missing_gaps"))
    pending = normalize_gap_list(doc.get("pending_l3_gaps"))
    legacy_gaps = doc.get("closure_gaps") or []
    if legacy_gaps and not missing and not pending:
        for item in legacy_gaps:
            if isinstance(item, dict):
                name = item.get("name") or ""
                version = item.get("version") or item.get("requested") or ""
                if name and version:
                    missing.append(node_key(name, version))
    missing = sorted(set(missing))
    pending = sorted(set(pending))
    direct = normalize_direct_dependencies(doc.get("direct_dependencies"))
    level = (
        doc.get("compliance_level")
        or doc.get("level")
        or compute_level({"missing_gaps": missing, "pending_l3_gaps": pending})
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "name": doc.get("name") or "",
        "version": doc.get("version") or "",
        "compliance_level": level,
        "direct_dependencies": direct,
        "missing_gaps": missing,
        "pending_l3_gaps": pending,
        "assessed_at": doc.get("assessed_at"),
        "closure_updated_at": doc.get("closure_updated_at"),
        "compliance_revision": int(doc.get("compliance_revision") or 1),
        "pulp_href": doc.get("pulp_href") or "",
        "tarball_sha256": doc.get("tarball_sha256"),
        "tarball": doc.get("tarball"),
        "built_from": doc.get("built_from"),
        "registry": doc.get("registry"),
    }


def gap_keys(doc: dict) -> list[str]:
    """Return the sorted union of a doc's missing and pending gap keys."""
    return sorted(
        set(doc.get("missing_gaps") or []) | set(doc.get("pending_l3_gaps") or [])
    )


def direct_dep_names(doc: dict) -> set[str]:
    """Return the set of package names in a doc's direct_dependencies."""
    return {d["name"] for d in doc.get("direct_dependencies") or []}


def validate_gap_subset(doc: dict) -> None:
    """Raise unless every gap key's package name is a direct dependency.

    This is a real data-integrity check: a gap for a package the doc
    doesn't even depend on directly indicates a corrupt or hand-edited
    document, not a normal transient state.

    Raises:
        click.ClickException: If any gap key's package name is not among
            the doc's own direct_dependencies names.

    """
    for key in gap_keys(doc):
        if _gap_name(key) not in direct_dep_names(doc):
            raise click.ClickException(
                f"Gap {key!r} is not a direct dependency of "
                f"{doc.get('name')}@{doc.get('version')}"
            )


def refresh_parent_doc(doc: dict, blocker_key: str, blocker_level: str) -> dict:
    """Move blocker_key between gap lists per its landed level.

    Recomputes ``compliance_level``, bumps ``compliance_revision``, and
    stamps ``closure_updated_at``. ``direct_dependencies`` is left
    unchanged. Does not mutate the input dict.
    """
    doc = copy.deepcopy(doc)
    missing = list(doc.get("missing_gaps") or [])
    pending = list(doc.get("pending_l3_gaps") or [])
    if blocker_key in missing:
        missing.remove(blocker_key)
        if blocker_level != "L3" and blocker_key not in pending:
            pending.append(blocker_key)
    elif blocker_key in pending:
        if blocker_level == "L3":
            pending.remove(blocker_key)
    doc["missing_gaps"] = sorted(set(missing))
    doc["pending_l3_gaps"] = sorted(set(pending))
    doc["compliance_level"] = compute_level(doc)
    doc["compliance_revision"] = int(doc.get("compliance_revision") or 1) + 1
    doc["closure_updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return doc


def doc_to_compliance_json(
    doc: dict,
    *,
    registry_url: str,
    compliance_oci: str,
    for_update: bool = False,
) -> dict:
    """Build the external compliance-document JSON shape from a doc.

    ``compliance_oci`` is supplied by the caller rather than computed
    here — computing it requires ``compliance_image_ref``, which reads a
    compliance-image-prefix value and lives in ``closure_oci.py``.
    ``registry_url`` is likewise caller-supplied (the default/env lookup
    belongs to the CLI layer); a doc's own explicit ``registry`` field,
    when set, still wins over it.
    """
    out = {
        "schema_version": SCHEMA_VERSION,
        "name": doc["name"],
        "version": doc["version"],
        "compliance_level": doc.get("compliance_level") or compute_level(doc),
        "direct_dependencies": copy.deepcopy(
            doc.get("direct_dependencies") or []
        ),
        "missing_gaps": sorted(set(doc.get("missing_gaps") or [])),
        "pending_l3_gaps": sorted(set(doc.get("pending_l3_gaps") or [])),
        "assessed_at": doc.get("assessed_at"),
        "closure_updated_at": doc.get("closure_updated_at")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "compliance_revision": int(doc.get("compliance_revision") or 1),
        "registry": doc.get("registry") or registry_url,
        "compliance_oci": compliance_oci,
        "pulp_href": doc.get("pulp_href") or "",
    }
    if doc.get("tarball_sha256"):
        out["tarball_sha256"] = doc["tarball_sha256"]
    if doc.get("tarball"):
        out["tarball"] = doc["tarball"]
    if doc.get("built_from"):
        out["built_from"] = doc["built_from"]
    if for_update:
        out["direct_dependencies"] = copy.deepcopy(
            doc.get("direct_dependencies") or []
        )
    return out


#: Strictness order of compliance levels, lowest (least compliant) first.
_LEVEL_RANK = {"L1": 1, "L2": 2, "L3": 3}


def enforce_alias_gaps(doc: dict) -> dict:
    """Fail closed on npm alias direct dependencies in a normalized doc.

    For each direct dependency whose ``requested`` value is an alias spec
    (``is_npm_alias_spec``) and whose ``alias_gap_key`` is in neither gap
    list, adds that key to ``missing_gaps``. Only the exact sentinel key
    counts as already flagged: a local-name gap with a real version (e.g.
    ``my-dep@^1.2.0``) would be cleared by any unrelated package named
    ``my-dep`` reaching L3, so it does not fail closed.

    When the doc has any alias dependency, ``compliance_level`` is capped
    at the level its gap lists imply (never raised), so a claimed ``L3``
    cannot survive an alias gap. Docs without alias dependencies are
    returned unchanged. Does not mutate the input dict.
    """
    alias_names = [
        dep["name"]
        for dep in doc.get("direct_dependencies") or []
        if is_npm_alias_spec(dep.get("requested") or "")
    ]
    if not alias_names:
        return doc
    doc = copy.deepcopy(doc)
    missing = set(doc.get("missing_gaps") or [])
    pending = set(doc.get("pending_l3_gaps") or [])
    for name in alias_names:
        key = alias_gap_key(name)
        if key not in missing and key not in pending:
            missing.add(key)
    doc["missing_gaps"] = sorted(missing)
    doc["pending_l3_gaps"] = sorted(pending)
    # An alias gap is now always present, so computed is L1 or L2. An
    # unrecognized claimed level ranks above L3 and is always replaced.
    computed = compute_level(doc)
    claimed = doc.get("compliance_level")
    if _LEVEL_RANK[computed] < _LEVEL_RANK.get(claimed, len(_LEVEL_RANK) + 1):
        doc["compliance_level"] = computed
    return doc


def sidecar_to_doc(sidecar_json: dict, pulp_href: str = "") -> dict:
    """Normalize and validate an already-parsed sidecar compliance doc.

    Also applies ``enforce_alias_gaps``: the automated ``closure update``
    path trusts the sidecar's gap lists (produced by an external assess
    tool) and never re-scans dependencies the way ``rebalance`` does, so
    an alias dependency the assess tool failed to flag must still fail
    closed here. This deliberately lives in ``sidecar_to_doc``, not
    ``normalize_doc``: ``normalize_doc`` also backs every OCI pull, and
    ``rebalance`` detects stale stored docs by diffing its re-derived gaps
    against the pulled doc -- injecting on pull would mask a stale stored
    L3 doc (and its Pulp label) from that diff.

    Does not mutate ``sidecar_json``.

    Raises:
        click.ClickException: If the sidecar is missing name/version, or
            a gap key isn't a direct dependency (see
            ``validate_gap_subset``).

    """
    data = dict(sidecar_json)
    if pulp_href:
        data["pulp_href"] = pulp_href
    doc = enforce_alias_gaps(normalize_doc(data))
    if not doc["name"] or not doc["version"]:
        raise click.ClickException("Sidecar missing name/version")
    validate_gap_subset(doc)
    return doc


def empty_index() -> dict:
    """Build a fresh, empty closure index."""
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "revision": 0,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entries": {},
    }


def normalize_index(raw: dict | None) -> dict:
    """Normalize a raw index dict, dropping entries with no parents."""
    if not raw:
        return empty_index()
    entries = {}
    for key, val in (raw.get("entries") or {}).items():
        parents = sorted(set((val or {}).get("parents") or []))
        if parents:
            entries[key] = {"parents": parents}
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "revision": int(raw.get("revision") or 0),
        "updated_at": raw.get("updated_at")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entries": entries,
    }


def index_add_parent(index: dict, blocker_key: str, parent_key: str) -> None:
    """Record parent_key as waiting on blocker_key, in place."""
    entry = index["entries"].setdefault(blocker_key, {"parents": []})
    parents = set(entry.get("parents") or [])
    parents.add(parent_key)
    entry["parents"] = sorted(parents)


def index_remove_key(index: dict, key: str) -> None:
    """Drop a blocker key from the index, in place. No-op if absent."""
    index["entries"].pop(key, None)


def rebuild_index_from_docs(docs_by_key: dict) -> dict:
    """Rebuild a full closure index from a map of node_key -> doc."""
    index = empty_index()
    for parent_key, doc in docs_by_key.items():
        for blocker_key in gap_keys(doc):
            index_add_parent(index, blocker_key, parent_key)
    return index


def find_index_blocker_keys_for_release(
    index: dict, release_name: str, release_version: str
) -> list[str]:
    """Return index blocker keys satisfied by release_name@release_version.

    A blocker key ``name@spec`` matches when ``spec`` is either the exact
    released version string, or an npm semver range that the released
    version satisfies. An alias-dependency gap key
    (``UNVERIFIABLE_ALIAS_VERSION``) never matches any release.
    """
    matched = []
    for blocker_key in index.get("entries") or {}:
        bname, bspec = parse_node_key(blocker_key)
        if bname != release_name or bspec == UNVERIFIABLE_ALIAS_VERSION:
            continue
        if bspec == release_version or npm_version_satisfies(
            release_version, bspec
        ):
            matched.append(blocker_key)
    return sorted(set(matched))


def apply_index_release(
    index: dict, package_key: str, release_doc: dict, release_level: str
) -> dict:
    """Register a release on the index; drop satisfied blockers at L3.

    When ``release_level`` is ``"L3"``, every index entry this release
    satisfies (per ``find_index_blocker_keys_for_release``) is removed,
    along with the release's own key, before the release is registered
    as a parent of its own remaining gaps.
    """
    if release_level == "L3":
        release_name, release_version = parse_node_key(package_key)
        for blocker_key in find_index_blocker_keys_for_release(
            index, release_name, release_version
        ):
            index_remove_key(index, blocker_key)
        index_remove_key(index, package_key)
    register_package_on_index(index, package_key, release_doc)
    return index


def register_package_on_index(index: dict, package_key: str, doc: dict) -> None:
    """Add package_key as a parent of every one of its own gap keys."""
    for blocker_key in gap_keys(doc):
        index_add_parent(index, blocker_key, package_key)


def hydrate_seed_doc(row: dict) -> dict:
    """Build a normalized seed doc from a Pulp npm content row.

    Used when bootstrapping a compliance document for a package that has
    none yet: no known dependency gaps, and a compliance level taken from
    the row's existing Pulp label (defaulting to ``"L3"``, i.e. "already
    on TL, assumed fully compliant until re-assessed").
    """
    name = row.get("name") or ""
    version = row.get("version") or ""
    labels = row.get("pulp_labels") or {}
    return normalize_doc(
        {
            "name": name,
            "version": version,
            "pulp_href": row.get("pulp_href") or "",
            "compliance_level": labels.get(COMPLIANCE_LABEL) or "L3",
            "direct_dependencies": [],
            "missing_gaps": [],
            "pending_l3_gaps": [],
            "assessed_at": None,
            "compliance_revision": 1,
        }
    )
