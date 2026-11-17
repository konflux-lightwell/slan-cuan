"""Pulp I/O and the compliance-label CAS protocol for npm closure sync.

Direct port of ``scripts/npm/update-npm-closure``'s Pulp-label helpers and
``sync_content_pulp_labels`` (lines 439-659), rewritten against
``PulpNpmClient.get_labels``/``PulpNpmClient.set_label`` (Task 9) instead of
the original's raw ``pulp_post``/``find_content_in_repo`` HTTP calls, with
every ``SystemExit`` converted to ``click.ClickException`` since this module
backs CLI commands.

Pulp labels (``tl.compliance_level``, ``tl.compliance_oci_digest``) use the
OCI digest as an optimistic lock: write the digest first and re-read; only
then write the level (after another re-read for sticky max). If another
digest is present, fail closed so the release can be retried. Levels are
sticky (never downgraded).

``PulpClientBase.get_labels``/``set_label`` (Task 1) are single
HTTP-round-trip primitives with no retry/backoff/sticky-max logic of their
own -- all of that multi-step orchestration (claim, re-verify, sticky-max
raise, re-verify, retry loop) lives here, built from repeated calls to those
two primitives.

Foreign-digest handling matches the original script's
``_assert_digest_or_race``: once this writer has claimed (or observed itself
holding) the digest lock, seeing any other digest -- or an emptied digest --
at a later re-read raises ``click.ClickException`` immediately ("refusing
overwrite; retry the release"). It is never retried, because a retry round
would re-claim and silently clobber the concurrent writer's digest. The only
retried condition is "our digest is held but the level has not yet reached
the desired level" in the final verify.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator

import click

from slan_cuan.npm.closure_model import node_key
from slan_cuan.pulp.clients.npm import PulpNpmClient
from slan_cuan.pulp.constants import NPM_CONTENT_API_PATH_TEMPLATE
from slan_cuan.pulp.exceptions import PulpError

#: Pulp label recording a package's sticky compliance level (L1/L2/L3).
COMPLIANCE_LABEL = "tl.compliance_level"

#: Pulp label recording the OCI digest a compliance-level claim is pinned
#: to -- the optimistic-lock value for the CAS protocol below.
COMPLIANCE_DIGEST_LABEL = "tl.compliance_oci_digest"

_LEVEL_RANKS = {"L1": 1, "L2": 2, "L3": 3}

#: Backoff base (seconds) between CAS retry rounds; round N sleeps
#: ``_RETRY_BACKOFF_SECONDS * N``.
_RETRY_BACKOFF_SECONDS = 0.2

#: Default CAS retry-round ceiling, matching the original script's
#: module-level ``CAS_MAX_RETRIES = int(os.environ.get(
#: "CLOSURE_CAS_MAX_RETRIES", "8"))``. Read once at import time and shared
#: by every closure CAS loop (this module's label CAS and
#: ``closure_oci``'s index/compliance CAS), each resolving it at call time
#: when ``max_retries`` is None; callers may still override per-call.
DEFAULT_CAS_MAX_RETRIES = int(os.environ.get("CLOSURE_CAS_MAX_RETRIES", "8"))


class _ContentGone(Exception):
    """Internal signal: the content unit no longer resolves by href."""


def normalize_digest(digest: str) -> str:
    """Normalize a digest to ``sha256:<hex>`` form where recognizable.

    A bare 64-char hex string is prefixed with ``sha256:`` (lowercased).
    An already-prefixed digest, or anything else (empty, malformed), is
    passed through unchanged -- a direct port of the original script's
    ``normalize_digest``.
    """
    if not digest:
        return ""
    digest = digest.strip()
    if digest.startswith("sha256:"):
        return digest
    if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest.lower()):
        return "sha256:" + digest.lower()
    return digest


def level_rank(level: str) -> int:
    """Rank sticky compliance levels; unknown/empty sorts lowest."""
    return _LEVEL_RANKS.get(level or "", 0)


def monotone_target_level(current: str, desired: str) -> str:
    """Prefer the higher sticky level so concurrent writers never downgrade."""
    if not desired:
        return current or ""
    if level_rank(current) > level_rank(desired):
        return current
    return desired


def find_content_in_repo(
    client: PulpNpmClient, name: str, version: str, repo_version_href: str
) -> dict[str, object] | None:
    """Find a Pulp content row for name@version within a repo version.

    Thin wrapper over ``PulpNpmClient.find_by_name_version`` (Task 9 already
    does the pagination/ambiguity-check work) kept under this name so other
    callers (e.g. ``closure_oci.py``) use the same vocabulary as the
    original ``update-npm-closure`` script.
    """
    return client.find_by_name_version(name, version, repo_version_href)


def list_repo_packages(
    client: PulpNpmClient, repo: dict[str, object]
) -> Iterator[dict[str, object]]:
    """Yield a repo's latest-version content rows that have name + version.

    Port of the original script's ``list_repo_packages``, using
    ``PulpNpmClient.list_content`` for pagination instead of hand-rolled
    offset/limit looping.
    """
    list_url = NPM_CONTENT_API_PATH_TEMPLATE.format(domain=client._config.domain)
    rows = client.list_content(
        list_url, repository_version=str(repo["latest_version_href"])
    )
    for row in rows:
        name = row.get("name") or ""
        version = row.get("version") or ""
        if name and version:
            yield row


def _read_pulp_labels(client: PulpNpmClient, content_href: str) -> dict[str, str]:
    """Fetch current labels for a content unit.

    Raises:
        _ContentGone: The content unit no longer resolves (HTTP 404).

    """
    try:
        return client.get_labels(content_href)
    except PulpError as exc:
        if exc.status_code == 404:
            raise _ContentGone from exc
        raise


def _labels_already_satisfied(
    cur_digest: str, cur_level: str, desired_digest: str, desired_level: str
) -> bool:
    """Return True when digest matches and level is already >= desired."""
    if cur_digest != desired_digest:
        return False
    if not desired_level:
        return True
    return level_rank(cur_level) >= level_rank(desired_level)


def _assert_digest_or_race(
    labels: dict[str, str], desired_digest: str, key: str, context: str
) -> None:
    """Require the digest label to equal ``desired_digest``; fail closed.

    Called only after this writer has claimed (or observed itself holding)
    the digest lock, so any other value means a concurrent writer has taken
    the lock (or it was cleared). Never retried: a retry round would
    re-claim and overwrite the other writer's digest.

    Raises:
        click.ClickException: A foreign or empty digest is present.

    """
    cur_digest = normalize_digest(labels.get(COMPLIANCE_DIGEST_LABEL, ""))
    if cur_digest == desired_digest:
        return
    if cur_digest:
        raise click.ClickException(
            f"Pulp label digest race for {key} ({context}): wanted "
            f"{desired_digest}, found {cur_digest} "
            "(refusing overwrite; retry the release)"
        )
    raise click.ClickException(
        f"Pulp label digest race for {key} ({context}): wanted "
        f"{desired_digest}, found empty "
        "(refusing to continue; retry the release)"
    )


def _claim_compliance_digest(
    client: PulpNpmClient, content_href: str, desired_digest: str, key: str
) -> None:
    """Write the digest label and verify the claim stuck.

    Raises:
        _ContentGone: Content vanished before the claim could be verified.
        click.ClickException: Another writer's digest won the race.

    """
    client.set_label(content_href, COMPLIANCE_DIGEST_LABEL, desired_digest)
    click.echo(
        f"Updated {key} Pulp label {COMPLIANCE_DIGEST_LABEL} -> {desired_digest}",
        err=True,
    )
    labels = _read_pulp_labels(client, content_href)
    _assert_digest_or_race(labels, desired_digest, key, "after digest write")


def _reread_holding_digest(
    client: PulpNpmClient,
    content_href: str,
    desired_digest: str,
    key: str,
    context: str,
) -> str:
    """Re-read labels, requiring our digest is still held; return the level.

    Raises:
        _ContentGone: Content vanished.
        click.ClickException: Another writer's digest has replaced ours.

    """
    labels = _read_pulp_labels(client, content_href)
    _assert_digest_or_race(labels, desired_digest, key, context)
    return labels.get(COMPLIANCE_LABEL) or ""


def _maybe_raise_compliance_level(
    client: PulpNpmClient,
    content_href: str,
    cur_level: str,
    desired_level: str,
    key: str,
) -> None:
    """Write the level label only when the sticky target is strictly higher.

    Skips the write when a concurrent release already set a higher level
    (e.g. L3 while we wanted L2) -- levels are never written downward.
    """
    target_level = monotone_target_level(cur_level, desired_level)
    if level_rank(cur_level) < level_rank(target_level):
        client.set_label(content_href, COMPLIANCE_LABEL, target_level)
        click.echo(
            f"Updated {key} Pulp label {COMPLIANCE_LABEL} -> {target_level} "
            f"(was {cur_level or '<unset>'})",
            err=True,
        )


def _final_labels_ok(
    client: PulpNpmClient,
    content_href: str,
    desired_digest: str,
    desired_level: str,
    key: str,
) -> bool:
    """Return True when digest is still ours and level is at least desired.

    Raises:
        _ContentGone: Content vanished.
        click.ClickException: Another writer's digest has replaced ours.

    """
    cur_level = _reread_holding_digest(
        client, content_href, desired_digest, key, "final verify"
    )
    if not desired_level:
        return True
    return level_rank(cur_level) >= level_rank(desired_level)


def sync_content_pulp_labels(
    client: PulpNpmClient,
    content_href: str,
    repo_version_href: str,
    name: str,
    version: str,
    level: str,
    compliance_digest: str,
    *,
    max_retries: int | None = None,
) -> None:
    """Set Pulp compliance labels using the OCI digest as an optimistic lock.

    Pulp ``set_label`` is not atomic CAS. High-level protocol per round:

    1. Read current labels; return if already satisfied or if the content
       unit no longer exists. On a retry round (after this writer has
       already claimed/held the digest), a foreign or empty digest here
       fails closed instead of being re-claimed.
    2. Claim ``tl.compliance_oci_digest`` (if not already ours) and verify
       it stuck.
    3. Re-read under that digest; raise the level only if the sticky max
       needs it (never downgrades).
    4. Final verify digest + level; return on success. If the digest is
       still ours but the level has not yet reached ``desired_level``, back
       off and retry the whole round, up to ``max_retries`` times.

    Any foreign/empty digest seen after this writer's claim (steps 2-4, or
    step 1 of a later round) raises immediately -- never retried, since a
    retry would re-claim and silently overwrite the concurrent writer.

    ``repo_version_href`` is accepted for interface symmetry with
    ``find_content_in_repo`` (which callers use to resolve ``content_href``
    before calling this function) -- once resolved, this protocol re-reads
    directly by ``content_href`` via ``client.get_labels``, so it is not
    used in the body here.

    Raises:
        click.ClickException: A concurrent writer's digest was seen after
            our claim (fail closed, no retry), or the level verify never
            caught up within ``max_retries`` rounds.

    """
    if max_retries is None:
        max_retries = DEFAULT_CAS_MAX_RETRIES
    desired_digest = normalize_digest(compliance_digest)
    if not desired_digest:
        return
    key = node_key(name, version)
    desired_level = level or ""
    # Set once we have claimed (or observed ourselves holding) the digest
    # lock. From then on, a foreign/empty digest is a lost race, not a
    # stale value to overwrite.
    holding = False

    for attempt in range(max_retries):
        try:
            labels = _read_pulp_labels(client, content_href)
            if holding:
                _assert_digest_or_race(
                    labels, desired_digest, key, f"retry round {attempt + 1}"
                )
            cur_digest = normalize_digest(labels.get(COMPLIANCE_DIGEST_LABEL, ""))
            cur_level = labels.get(COMPLIANCE_LABEL) or ""

            if _labels_already_satisfied(
                cur_digest, cur_level, desired_digest, desired_level
            ):
                return

            if cur_digest != desired_digest:
                _claim_compliance_digest(
                    client, content_href, desired_digest, key
                )
            holding = True

            if not desired_level:
                return

            cur_level = _reread_holding_digest(
                client, content_href, desired_digest, key, "before level write"
            )
            _maybe_raise_compliance_level(
                client, content_href, cur_level, desired_level, key
            )

            if _final_labels_ok(
                client, content_href, desired_digest, desired_level, key
            ):
                return
        except _ContentGone:
            click.echo(
                f"Pulp label sync for {key} abandoned: content unit no "
                "longer found (likely destroyed mid-sync, e.g. by an "
                "upload replace); no labels written this round",
                err=True,
            )
            return

        if attempt + 1 >= max_retries:
            break
        click.echo(
            f"Pulp label CAS retry {attempt + 1}/{max_retries} for {key} "
            f"(level not yet >= {desired_level})",
            err=True,
        )
        time.sleep(_RETRY_BACKOFF_SECONDS * (attempt + 1))

    raise click.ClickException(
        f"Pulp label CAS failed for {key} after {max_retries} retries "
        f"(wanted digest {desired_digest} level {desired_level or '<none>'})"
    )
