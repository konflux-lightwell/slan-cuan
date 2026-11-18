"""npm closure graph orchestration CLI: ``slan-cuan npm closure``.

Composes the compliance-document/closure-index data model
(``closure_model``, Task 13), the Pulp label CAS protocol
(``closure_pulp``, Task 14), and the OCI artifact I/O + compliance CAS
protocol (``closure_oci``, Task 15) into the five subcommands the original
``scripts/npm/update-npm-closure`` script exposed as ``argparse``
subcommands: ``update``, ``seed``, ``rebalance``, ``show``, ``show-index``.

Direct port of ``scripts/npm/update-npm-closure`` lines 868-1203
(``tl_level_for_key``, ``promote_parent``, ``drain_blocker_parents``,
``merge_update``, ``cmd_seed``, ``cmd_rebalance``,
``find_resolved_version_for_dep``, ``cmd_show``, ``cmd_show_index``, and
``main``'s argparse wiring), with two deliberate deviations:

* This is the one place in the npm closure port that reads
  ``--npm-registry-url`` and strips a trailing ``/`` from it before
  passing it down as ``registry_url`` -- the original script's
  ``doc_to_compliance_json`` did ``os.environ.get("TL_NPM_REGISTRY_URL",
  <default>).rstrip("/")`` internally; ``closure_model``/``closure_oci``
  (Tasks 13/15) deliberately do not re-apply that stripping themselves
  (see their own docstrings), so it happens here instead.
* The original's raw ``pulp_query_base()``/``pulp_get`` fallback inside
  ``find_resolved_version_for_dep`` (checking for an exact-version content
  row a second time via a hand-rolled HTTP query) applied the identical
  ``name``/``version`` equality filter as the preceding
  ``find_content_in_repo`` call one line above it, so it could never
  resolve differently except on the already-handled "multiple matches"
  path. It is not ported: doing so would reintroduce a raw Pulp HTTP call
  this whole refactor exists to retire, for a branch that is effectively
  dead code.
"""

from __future__ import annotations

import copy
import json
import time
from collections.abc import Callable
from pathlib import Path

import click

from slan_cuan.http import parse_custom_headers
from slan_cuan.models import GlobalContext
from slan_cuan.npm import closure_model, closure_oci, closure_pulp
from slan_cuan.npm.semver import max_satisfying
from slan_cuan.pulp.clients.npm import PulpNpmClient
from slan_cuan.pulp.constants import (
    NPM_CONTENT_API_PATH_TEMPLATE,
    NPM_REPO_API_PATH_TEMPLATE,
    TASK_POLL_TIMEOUT_SECONDS,
)
from slan_cuan.pulp.models import PulpConfig

#: Default registry URL stamped into a published compliance document,
#: matching the original script's ``TL_NPM_REGISTRY_URL`` env var default.
DEFAULT_NPM_REGISTRY_URL = "https://packages.redhat.com/api/pulp-content/public-trusted-libraries/javascript"

#: The domain-agnostic path segment an npm content unit href must contain.
#: Derived from ``NPM_CONTENT_API_PATH_TEMPLATE`` (rather than duplicating
#: the original script's separate ``NPM_CONTENT_PATH`` literal) so this
#: stays in sync with however that template is defined.
_NPM_CONTENT_HREF_SEGMENT = NPM_CONTENT_API_PATH_TEMPLATE.rsplit("{domain}", 1)[1]


def _assert_npm_content_href(href: str, context: str) -> None:
    """Fail closed unless ``href`` looks like an npm content unit href.

    Port of the original script's ``assert_npm_content_href`` (lines
    421-426), guarding a caller-supplied ``--pulp-href`` before it is
    trusted and threaded into the compliance doc / Pulp label CAS
    protocol -- a wrong-content-type href would otherwise either fail
    deep inside ``sync_content_pulp_labels``'s retry loop with an unclear
    404, or worse, address a content unit of the wrong type.

    Raises:
        click.ClickException: ``href`` does not contain the npm content
            path segment.

    """
    if _NPM_CONTENT_HREF_SEGMENT not in href:
        raise click.ClickException(
            f"Refusing non-npm content href for {context} "
            f"(expected a path containing {_NPM_CONTENT_HREF_SEGMENT!r}): "
            f"{href!r}"
        )


def _resolve_repo(
    client: PulpNpmClient, config: PulpConfig, name: str
) -> dict[str, object]:
    """Resolve an npm repository to the minimal dict shape this module needs.

    The original script's ``get_repository()`` returned the full raw Pulp
    repository API object; ``PulpNpmClient`` has no equivalent single call,
    so this builds the same minimal ``{"name", "pulp_href",
    "latest_version_href"}`` shape that ``closure_pulp``/``closure_oci``
    actually read (``repo["latest_version_href"]``), the same way Task 11's
    ``upload.py::_resolve_repository`` resolves a repo by name.

    Raises:
        click.ClickException: If the repository or its
            ``latest_version_href`` cannot be found.

    """
    url = NPM_REPO_API_PATH_TEMPLATE.format(domain=config.domain)
    rows = client.list_content(url, name=name)
    matches = [row for row in rows if row.get("name") == name]
    if not matches:
        raise click.ClickException(
            f"npm repository '{name}' not found. Check --pulp-repository."
        )
    row = matches[0]
    version_href = row.get("latest_version_href")
    if not version_href:
        raise click.ClickException(
            f"npm repository '{name}' has no latest_version_href."
        )
    return {
        "name": row.get("name") or name,
        "pulp_href": row.get("pulp_href"),
        "latest_version_href": str(version_href),
    }


def _pulp_config(ctx: GlobalContext, **kwargs: object) -> PulpConfig:
    """Build a ``PulpConfig`` from the shared Pulp CLI option values."""
    ca_cert = ctx.ca_cert if ctx.ca_cert and ctx.ca_cert.exists() else None
    return PulpConfig(
        base_url=str(kwargs["pulp_url"]),
        verify_ssl=not kwargs["insecure"],
        ca_cert=ca_cert,
        domain=str(kwargs["pulp_domain"]),
        auth_type=str(kwargs["pulp_auth_type"]),
        username=kwargs["pulp_username"],
        password=kwargs["pulp_password"],
        client_cert=kwargs["pulp_client_cert"],
        client_key=kwargs["pulp_client_key"],
        task_timeout=float(kwargs["pulp_task_timeout"]),
        max_total_task_timeout=kwargs["pulp_max_total_task_timeout"],
        custom_headers=parse_custom_headers(str(kwargs["pulp_custom_headers"])),
        verbose=ctx.verbose,
    )


def _pulp_options(f: Callable) -> Callable:
    """Apply the shared Pulp connection option block (Task 11's list)."""
    options = [
        click.option(
            "--pulp-url",
            required=True,
            type=str,
            help="Pulp instance base URL (e.g. https://pulp.example.com).",
        ),
        click.option(
            "--pulp-repository",
            required=True,
            type=str,
            help="Pulp npm repository name.",
        ),
        click.option(
            "--pulp-domain",
            required=True,
            type=str,
            help="Pulp domain for hosted content API (e.g. 'lightwell').",
        ),
        click.option(
            "--pulp-auth-type",
            type=click.Choice(["tbr", "cert"], case_sensitive=False),
            default="tbr",
            help="Pulp authentication method.",
        ),
        click.option(
            "--pulp-username",
            type=str,
            default=None,
            help="Username for TBR basic auth.",
        ),
        click.option(
            "--pulp-password",
            type=str,
            default=None,
            help="Password for TBR basic auth.",
        ),
        click.option(
            "--pulp-client-cert",
            type=click.Path(dir_okay=False, path_type=Path),
            default=None,
            help="Client certificate path for entitlement cert auth.",
        ),
        click.option(
            "--pulp-client-key",
            type=click.Path(dir_okay=False, path_type=Path),
            default=None,
            help="Client key path for entitlement cert auth.",
        ),
        click.option(
            "--pulp-task-timeout",
            type=click.FloatRange(min=1.0),
            default=TASK_POLL_TIMEOUT_SECONDS,
            show_default=True,
            help="Maximum time in seconds to wait for asynchronous Pulp tasks.",
        ),
        click.option(
            "--pulp-max-total-task-timeout",
            type=click.FloatRange(min=1.0),
            default=None,
            help=(
                "Absolute maximum time in seconds across all Pulp task "
                "state and blocker timeout resets. Defaults to twice the "
                "task timeout."
            ),
        ),
        click.option(
            "--pulp-custom-headers",
            default="",
            help=(
                "Custom HTTP headers to send on Pulp requests "
                "(CRLF/newline-delimited 'Key: Value' or JSON)."
            ),
        ),
        click.option(
            "--insecure",
            is_flag=True,
            default=False,
            help="Disable TLS certificate verification.",
        ),
    ]
    for option in reversed(options):
        f = option(f)
    return f


def _oci_options(f: Callable) -> Callable:
    """Apply the shared compliance-image-prefix/index/registry options."""
    options = [
        click.option(
            "--compliance-image-prefix",
            required=True,
            type=str,
            help="OCI repo prefix for compliance-document/index artifacts.",
        ),
        click.option(
            "--closure-index-image",
            default="",
            help=(
                "Explicit OCI ref for the closure index. Defaults to "
                "<compliance-image-prefix>/npm-closure-index:latest."
            ),
        ),
        click.option(
            "--npm-registry-url",
            default=DEFAULT_NPM_REGISTRY_URL,
            show_default=True,
            help="Registry URL stamped into published compliance documents.",
        ),
    ]
    for option in reversed(options):
        f = option(f)
    return f


def tl_level_for_key(
    client: PulpNpmClient,
    name: str,
    version: str,
    repo: dict[str, object],
    *,
    compliance_image_prefix: str,
) -> str | None:
    """Return the sticky compliance level Pulp/OCI currently hold for a key.

    Port of the original script's ``tl_level_for_key`` (lines 868-879): the
    Pulp label wins when present (cheapest, most current claim); falling
    back to the compliance OCI document, then defaulting to ``"L3"`` (on TL,
    assumed compliant) when neither exists but the content unit itself does.
    Returns ``None`` only when the content unit is not found in the repo at
    all.
    """
    content = closure_pulp.find_content_in_repo(
        client, name, version, str(repo["latest_version_href"])
    )
    if not content:
        return None
    labels = content.get("pulp_labels") or {}
    level = labels.get(closure_pulp.COMPLIANCE_LABEL)
    if level:
        return str(level)
    doc, _ = closure_oci.pull_compliance_doc(
        name, version, compliance_image_prefix, content.get("pulp_href") or ""
    )
    if doc:
        return doc.get("compliance_level")
    return "L3"


def find_resolved_version_for_dep(
    client: PulpNpmClient,
    dep_name: str,
    dep_spec: str,
    doc: dict,
    repo_version_href: str,
) -> str | None:
    """Resolve a direct dependency's spec to a concrete version, if known.

    Port of the original script's ``find_resolved_version_for_dep`` (lines
    1129-1143), minus its raw-HTTP fallback query -- see the module
    docstring for why that branch is not ported.

    Checks the doc's own gap keys first (a gap already names the resolved
    version), then resolves ``dep_spec`` against every version of
    ``dep_name`` Pulp actually holds in the repo, via
    ``slan_cuan.npm.semver.max_satisfying``. ``dep_spec`` is virtually
    always an npm semver range (e.g. ``^4.17.21``), not a concrete
    version, so an exact-match lookup (``find_content_in_repo``) would
    almost never resolve it -- that bug is what this function exists to
    avoid.
    """
    for key in closure_model.gap_keys(doc):
        name, version = closure_model.parse_node_key(key)
        if name == dep_name:
            return version
    rows = closure_pulp.list_versions_in_repo(client, dep_name, repo_version_href)
    versions = [row["version"] for row in rows if row.get("version")]
    return max_satisfying(versions, dep_spec)


def promote_parent(
    client: PulpNpmClient,
    repo: dict[str, object],
    parent_key: str,
    blocker_key: str,
    blocker_level: str,
    refreshed: dict[str, str],
    queue: list[str],
    *,
    compliance_image_prefix: str,
    registry_url: str,
) -> None:
    """Refresh one waiter's compliance doc for a blocker's landed level.

    Direct port of the original script's ``promote_parent`` (lines
    882-899). Mutates ``refreshed``/``queue`` in place: ``refreshed``
    records every parent touched this drain (so it is never refreshed
    twice), and ``queue`` collects parents that themselves reached ``L3``,
    for the caller's transitive-promotion loop.
    """
    if parent_key in refreshed:
        return
    name, version = closure_model.parse_node_key(parent_key)
    doc, _ = closure_oci.pull_compliance_doc(
        name, version, compliance_image_prefix
    )
    if not doc:
        click.echo(
            f"Skip parent refresh (no compliance OCI): {parent_key}", err=True
        )
        return
    old_level = doc.get("compliance_level")
    updated = closure_model.refresh_parent_doc(doc, blocker_key, blocker_level)
    digest = closure_oci.cas_publish_compliance(
        client,
        updated,
        repo,
        compliance_image_prefix=compliance_image_prefix,
        registry_url=registry_url,
    )
    refreshed[parent_key] = digest
    click.echo(
        f"Refreshed {parent_key} level {old_level} -> "
        f"{updated['compliance_level']} (blocker {blocker_key} at "
        f"{blocker_level})",
        err=True,
    )
    if updated["compliance_level"] == "L3":
        queue.append(parent_key)


def drain_blocker_parents(
    client: PulpNpmClient,
    repo: dict[str, object],
    index: dict,
    blocker_key: str,
    blocker_level: str,
    *,
    compliance_image_prefix: str,
    registry_url: str,
) -> list[str]:
    """Refresh every waiter compliance doc for a blocker's landed level.

    Direct port of the original script's ``drain_blocker_parents`` (lines
    902-927). Does not mutate ``index`` -- only reads its ``parents``
    lists. After promoting ``blocker_key``'s direct parents, drains a
    queue of any parent that itself reached ``L3``, promoting *its* own
    parents too (transitive promotion), until the queue is empty.

    Returns:
        The sorted list of every node key whose compliance doc was
        refreshed.

    """
    entry = (index.get("entries") or {}).get(blocker_key) or {}
    parents = list(entry.get("parents") or [])
    if not parents:
        return []
    refreshed: dict[str, str] = {}
    queue: list[str] = []
    for parent_key in parents:
        promote_parent(
            client,
            repo,
            parent_key,
            blocker_key,
            blocker_level,
            refreshed,
            queue,
            compliance_image_prefix=compliance_image_prefix,
            registry_url=registry_url,
        )
    seen: set[str] = set()
    while queue:
        key = queue.pop(0)
        if key in seen:
            continue
        seen.add(key)
        name, version = closure_model.parse_node_key(key)
        level_doc, _ = closure_oci.pull_compliance_doc(
            name, version, compliance_image_prefix
        )
        if not level_doc:
            continue
        parent_level = level_doc.get("compliance_level") or "L3"
        if parent_level != "L3":
            continue
        sub = (index.get("entries") or {}).get(key) or {}
        for parent_key in sub.get("parents") or []:
            promote_parent(
                client,
                repo,
                parent_key,
                key,
                parent_level,
                refreshed,
                queue,
                compliance_image_prefix=compliance_image_prefix,
                registry_url=registry_url,
            )
    return sorted(refreshed.keys())


@click.command("update")
@click.option(
    "--sidecar",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to *.tl-compliance.json from assess.",
)
@click.option(
    "--pulp-href",
    default="",
    help="Pulp content href for the released package.",
)
@_pulp_options
@_oci_options
@click.option(
    "--oras-options",
    type=str,
    default=None,
    help=(
        "Extra oras options. Accepted for interface parity with the "
        "legacy ORAS_OPTIONS escape hatch; slan_cuan.oci has no "
        "equivalent extra-flags mechanism, so this is currently unused."
    ),
)
@click.pass_obj
def update(
    ctx: GlobalContext,
    sidecar: Path,
    pulp_href: str,
    pulp_url: str,
    pulp_repository: str,
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
    compliance_image_prefix: str,
    closure_index_image: str,
    npm_registry_url: str,
    oras_options: str | None,
) -> None:
    """Apply a release sidecar: update compliance doc, index, and waiters."""
    del oras_options  # unused: see --oras-options help text above

    closure_model.assert_not_python_wheels_repository(pulp_repository)
    if pulp_href:
        _assert_npm_content_href(pulp_href, "update --pulp-href")

    registry_url = npm_registry_url.rstrip("/")
    sidecar_json = json.loads(sidecar.read_text())
    release_doc = closure_model.sidecar_to_doc(sidecar_json, pulp_href)
    package_key = closure_model.node_key(
        release_doc["name"], release_doc["version"]
    )
    release_level = release_doc["compliance_level"]

    click.echo(f"Closure update for {package_key} (index + gap lists)", err=True)

    if ctx.dry_run:
        # Side-effect-free preview: exit before any Pulp or OCI call.
        index_ref = closure_oci.closure_index_image_ref(
            compliance_image_prefix, closure_index_image
        )
        doc_ref = closure_oci.compliance_image_ref(
            release_doc["name"], release_doc["version"], compliance_image_prefix
        )
        click.echo(
            f"Would publish {release_level} compliance document for "
            f"{package_key} from {sidecar} to {doc_ref}"
        )
        click.echo(
            f"Would set Pulp compliance labels on "
            f"{pulp_href or f'{package_key} in repository {pulp_repository}'}"
        )
        click.echo(
            f"Would refresh waiting parent compliance documents and push "
            f"the closure index to {index_ref}"
        )
        return

    config = _pulp_config(
        ctx,
        pulp_url=pulp_url,
        pulp_domain=pulp_domain,
        pulp_auth_type=pulp_auth_type,
        pulp_username=pulp_username,
        pulp_password=pulp_password,
        pulp_client_cert=pulp_client_cert,
        pulp_client_key=pulp_client_key,
        pulp_task_timeout=pulp_task_timeout,
        pulp_max_total_task_timeout=pulp_max_total_task_timeout,
        pulp_custom_headers=pulp_custom_headers,
        insecure=insecure,
    )

    with PulpNpmClient(config, pulp_repository) as client:
        repo = _resolve_repo(client, config, pulp_repository)

        index, _ = closure_oci.pull_index(
            compliance_image_prefix, closure_index_image
        )
        release_name, release_version = closure_model.parse_node_key(package_key)
        blocker_keys = closure_model.find_index_blocker_keys_for_release(
            index, release_name, release_version
        )
        if (
            package_key in (index.get("entries") or {})
            and package_key not in blocker_keys
        ):
            blocker_keys.append(package_key)

        drained: list[str] = []
        for blocker_key in blocker_keys:
            drained.extend(
                drain_blocker_parents(
                    client,
                    repo,
                    index,
                    blocker_key,
                    release_level,
                    compliance_image_prefix=compliance_image_prefix,
                    registry_url=registry_url,
                )
            )
        drained = sorted(set(drained))

        release_doc["compliance_revision"] = int(
            release_doc.get("compliance_revision") or 1
        )
        release_digest = closure_oci.cas_publish_compliance(
            client,
            release_doc,
            repo,
            compliance_image_prefix=compliance_image_prefix,
            registry_url=registry_url,
        )

        def mutate_index(idx: dict) -> dict:
            return closure_model.apply_index_release(
                idx, package_key, release_doc, release_level
            )

        new_index, index_digest = closure_oci.cas_push_index(
            mutate_index,
            compliance_image_prefix=compliance_image_prefix,
            closure_index_image=closure_index_image,
        )

    click.echo(
        json.dumps(
            {
                "package": package_key,
                "compliance_level": release_level,
                "compliance_oci_digest": release_digest,
                "parents_refreshed": drained,
                "index_revision": new_index.get("revision"),
                "index_oci_digest": index_digest,
            },
            indent=2,
            sort_keys=True,
        )
    )


@click.command("seed")
@_pulp_options
@_oci_options
@click.option(
    "--init-index",
    is_flag=True,
    default=False,
    help="Rebuild and push closure index from existing compliance docs.",
)
@click.pass_obj
def seed(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
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
    compliance_image_prefix: str,
    closure_index_image: str,
    npm_registry_url: str,
    init_index: bool,
) -> None:
    """Bootstrap compliance OCI documents for catalog packages missing one."""
    closure_model.assert_not_python_wheels_repository(pulp_repository)
    if ctx.dry_run:
        # Side-effect-free preview: exit before any Pulp or OCI call.
        click.echo(
            f"Would push a seed compliance document under "
            f"{compliance_image_prefix} (and set Pulp compliance labels) for "
            f"every package in Pulp npm repository {pulp_repository} at "
            f"{pulp_url} that has none yet"
        )
        if init_index:
            index_ref = closure_oci.closure_index_image_ref(
                compliance_image_prefix, closure_index_image
            )
            click.echo(
                f"Would rebuild the closure index from all compliance "
                f"documents and push it to {index_ref}"
            )
        return

    registry_url = npm_registry_url.rstrip("/")
    config = _pulp_config(
        ctx,
        pulp_url=pulp_url,
        pulp_domain=pulp_domain,
        pulp_auth_type=pulp_auth_type,
        pulp_username=pulp_username,
        pulp_password=pulp_password,
        pulp_client_cert=pulp_client_cert,
        pulp_client_key=pulp_client_key,
        pulp_task_timeout=pulp_task_timeout,
        pulp_max_total_task_timeout=pulp_max_total_task_timeout,
        pulp_custom_headers=pulp_custom_headers,
        insecure=insecure,
    )

    docs_by_key: dict[str, dict] = {}
    pushed: dict[str, str] = {}
    count = 0

    with PulpNpmClient(config, pulp_repository) as client:
        repo = _resolve_repo(client, config, pulp_repository)
        click.echo(
            f"Seeding compliance OCI from npm repo {repo.get('name')!r}",
            err=True,
        )
        for row in closure_pulp.list_repo_packages(client, repo):
            key = closure_model.node_key(row["name"], row["version"])
            existing, _ = closure_oci.pull_compliance_doc(
                row["name"],
                row["version"],
                compliance_image_prefix,
                row.get("pulp_href") or "",
            )
            if existing:
                docs_by_key[key] = existing
                count += 1
                continue
            doc = closure_model.hydrate_seed_doc(row)
            digest = closure_oci.publish_compliance_doc(
                client,
                doc,
                repo,
                compliance_image_prefix=compliance_image_prefix,
                registry_url=registry_url,
            )
            docs_by_key[key] = doc
            if digest:
                pushed[key] = digest
            count += 1

        index_result = None
        if init_index:
            index = closure_model.rebuild_index_from_docs(docs_by_key)
            index, index_digest = closure_oci.publish_index(
                index,
                compliance_image_prefix=compliance_image_prefix,
                closure_index_image=closure_index_image,
                expected_revision=0,
            )
            index_result = {
                "revision": index.get("revision"),
                "digest": index_digest,
            }

    click.echo(
        json.dumps(
            {
                "node_count": count,
                "compliance_oci": pushed,
                "index": index_result,
            },
            indent=2,
            sort_keys=True,
        )
    )


@click.command("rebalance")
@_pulp_options
@_oci_options
@click.option(
    "--index-only",
    is_flag=True,
    default=False,
    help="Rebuild index from current gap lists only (no gap re-derive).",
)
@click.pass_obj
def rebalance(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
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
    compliance_image_prefix: str,
    closure_index_image: str,
    npm_registry_url: str,
    index_only: bool,
) -> None:
    """Rebuild the closure index, and optionally re-derive gap lists."""
    closure_model.assert_not_python_wheels_repository(pulp_repository)
    if ctx.dry_run:
        # Side-effect-free preview: exit before any Pulp or OCI call.
        index_ref = closure_oci.closure_index_image_ref(
            compliance_image_prefix, closure_index_image
        )
        if not index_only:
            click.echo(
                f"Would re-derive gap lists for every package in Pulp npm "
                f"repository {pulp_repository} at {pulp_url} and republish "
                f"changed compliance documents under {compliance_image_prefix}"
            )
        click.echo(
            f"Would rebuild the closure index from current compliance "
            f"documents and push it to {index_ref}"
        )
        return

    registry_url = npm_registry_url.rstrip("/")
    config = _pulp_config(
        ctx,
        pulp_url=pulp_url,
        pulp_domain=pulp_domain,
        pulp_auth_type=pulp_auth_type,
        pulp_username=pulp_username,
        pulp_password=pulp_password,
        pulp_client_cert=pulp_client_cert,
        pulp_client_key=pulp_client_key,
        pulp_task_timeout=pulp_task_timeout,
        pulp_max_total_task_timeout=pulp_max_total_task_timeout,
        pulp_custom_headers=pulp_custom_headers,
        insecure=insecure,
    )

    docs_by_key: dict[str, dict] = {}
    updated: list[str] = []

    with PulpNpmClient(config, pulp_repository) as client:
        repo = _resolve_repo(client, config, pulp_repository)
        for row in closure_pulp.list_repo_packages(client, repo):
            name, version = row["name"], row["version"]
            key = closure_model.node_key(name, version)
            doc, _ = closure_oci.pull_compliance_doc(
                name, version, compliance_image_prefix, row.get("pulp_href") or ""
            )
            if not doc:
                doc = closure_model.hydrate_seed_doc(row)
            if index_only:
                docs_by_key[key] = doc
                continue
            if not doc.get("direct_dependencies"):
                docs_by_key[key] = doc
                continue

            missing: list[str] = []
            pending: list[str] = []
            repo_version = str(repo["latest_version_href"])
            for dep in doc.get("direct_dependencies") or []:
                dep_name = dep.get("name") or ""
                dep_spec = dep.get("requested") or ""
                if not dep_name or not dep_spec:
                    continue
                if closure_model.is_npm_alias_spec(dep_spec):
                    # An alias spec's real registry identity (name +
                    # version) is a different package than dep_name, and
                    # the raw spec string itself contains an "@", which
                    # would corrupt node_key/parse_node_key round-
                    # tripping -- this short-circuit exists purely to
                    # avoid that, by never resolving or building a node
                    # key from the raw spec. It does NOT record the gap
                    # itself: closure_model.enforce_alias_gaps (the same
                    # single owner the ``update`` sidecar path already
                    # uses) adds the permanently-unresolvable missing gap
                    # below, once, after this loop -- re-deriving alias
                    # dependencies directly from direct_dependencies
                    # rather than from what this loop appends to
                    # missing/pending.
                    click.echo(
                        f"Alias dependency {dep_name}@{dep_spec} cannot be "
                        "verified; recording it as an unresolvable gap",
                        err=True,
                    )
                    continue
                resolved = find_resolved_version_for_dep(
                    client, dep_name, dep_spec, doc, repo_version
                )
                if not resolved:
                    missing.append(closure_model.node_key(dep_name, dep_spec))
                    continue
                dep_key = closure_model.node_key(dep_name, resolved)
                level = tl_level_for_key(
                    client,
                    dep_name,
                    resolved,
                    repo,
                    compliance_image_prefix=compliance_image_prefix,
                )
                if level is None:
                    missing.append(dep_key)
                elif level != "L3":
                    pending.append(dep_key)

            new_doc = copy.deepcopy(doc)
            new_doc["missing_gaps"] = sorted(set(missing))
            new_doc["pending_l3_gaps"] = sorted(set(pending))
            # Single owner of "what key represents an alias gap, and how
            # it caps the level" for both the update (sidecar) and
            # rebalance paths -- re-derives alias dependencies straight
            # from direct_dependencies, independent of the loop above.
            new_doc = closure_model.enforce_alias_gaps(new_doc)
            new_doc["compliance_level"] = closure_model.compute_level(new_doc)
            if (
                new_doc["missing_gaps"] != doc.get("missing_gaps")
                or new_doc["pending_l3_gaps"] != doc.get("pending_l3_gaps")
                or new_doc["compliance_level"] != doc.get("compliance_level")
            ):
                new_doc["compliance_revision"] = (
                    int(doc.get("compliance_revision") or 1) + 1
                )
                new_doc["closure_updated_at"] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                )
                closure_oci.publish_compliance_doc(
                    client,
                    new_doc,
                    repo,
                    compliance_image_prefix=compliance_image_prefix,
                    registry_url=registry_url,
                )
                updated.append(key)
            docs_by_key[key] = new_doc

        index = closure_model.rebuild_index_from_docs(docs_by_key)
        new_index, index_digest = closure_oci.cas_push_index(
            lambda _idx: index,
            compliance_image_prefix=compliance_image_prefix,
            closure_index_image=closure_index_image,
        )

    click.echo(
        json.dumps(
            {
                "mode": "index-only" if index_only else "full",
                "packages_seen": len(docs_by_key),
                "compliance_updated": updated,
                "index_revision": new_index.get("revision"),
                "index_oci_digest": index_digest,
            },
            indent=2,
            sort_keys=True,
        )
    )


@click.command("show")
@click.option("--name", default="", help="Package name.")
@click.option("--version", default="", help="Package version.")
@click.option(
    "--compliance-path",
    default="",
    type=str,
    help="Read a local compliance JSON file instead of pulling from OCI.",
)
@click.option(
    "--compliance-image-prefix",
    default="",
    type=str,
    help=(
        "OCI repo prefix for compliance-document artifacts. Required "
        "unless --compliance-path is given."
    ),
)
@click.option(
    "--npm-registry-url",
    default=DEFAULT_NPM_REGISTRY_URL,
    show_default=True,
    help="Registry URL stamped into the printed compliance document.",
)
def show(
    name: str,
    version: str,
    compliance_path: str,
    compliance_image_prefix: str,
    npm_registry_url: str,
) -> None:
    """Print a compliance document from OCI, or a local file verbatim."""
    if compliance_path:
        click.echo(Path(compliance_path).read_text(encoding="utf-8"), nl=False)
        return
    if not name or not version:
        raise click.ClickException(
            "show requires --name and --version, or --compliance-path"
        )
    if not compliance_image_prefix:
        raise click.ClickException(
            "--compliance-image-prefix is required unless --compliance-path "
            "is given"
        )
    doc, _ = closure_oci.pull_compliance_doc(
        name, version, compliance_image_prefix
    )
    if not doc:
        raise click.ClickException(f"No compliance OCI for {name}@{version}")
    image_ref = closure_oci.compliance_image_ref(
        name, version, compliance_image_prefix
    )
    registry_url = npm_registry_url.rstrip("/")
    click.echo(
        json.dumps(
            closure_model.doc_to_compliance_json(
                doc, registry_url=registry_url, compliance_oci=image_ref
            ),
            indent=2,
            sort_keys=True,
        )
    )


@click.command("show-index")
@click.option(
    "--compliance-image-prefix",
    required=True,
    type=str,
    help="OCI repo prefix the closure index is derived from.",
)
@click.option(
    "--closure-index-image",
    default="",
    help=(
        "Explicit OCI ref for the closure index. Defaults to "
        "<compliance-image-prefix>/npm-closure-index:latest."
    ),
)
def show_index(compliance_image_prefix: str, closure_index_image: str) -> None:
    """Print the global closure index from OCI."""
    index, digest = closure_oci.pull_index(
        compliance_image_prefix, closure_index_image
    )
    click.echo(
        json.dumps({"digest": digest, "index": index}, indent=2, sort_keys=True)
    )


@click.group("closure")
def closure_cli() -> None:
    """Npm "Trusted Libraries" closure graph orchestration commands."""


closure_cli.add_command(update)
closure_cli.add_command(seed)
closure_cli.add_command(rebalance)
closure_cli.add_command(show)
closure_cli.add_command(show_index)
