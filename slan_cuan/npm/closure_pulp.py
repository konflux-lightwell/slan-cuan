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

Deliberate deviation from the original script: the original's
``_assert_digest_or_race`` raises ``SystemExit`` the first time it sees a
foreign digest, with no retry at all. Here a foreign-digest race is instead
treated as a *retryable* condition -- the caller backs off and tries the
whole claim/verify round again, only raising after ``max_retries`` rounds.
A foreign digest seen mid-race may belong to another writer converging on
the same compliance data (e.g. a retried release of the same artifact), so
giving it a bounded number of chances to settle is strictly safer than
refusing on the very first sighting, while still failing closed if the
conflict never clears.
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
#: "CLOSURE_CAS_MAX_RETRIES", "8"))``. Read once at import time; callers
#: (and tests) may still override per-call via ``max_retries``.
DEFAULT_CAS_MAX_RETRIES = int(os.environ.get("CLOSURE_CAS_MAX_RETRIES", "8"))


class _ContentGone(Exception):
    """Internal signal: the content unit no longer resolves by href."""


class _LabelRace(Exception):
    """Internal signal: a concurrent writer holds/won a label; retry."""


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


def _assert_digest_or_race(labels: dict[str, str], desired_digest: str) -> None:
    """Require the digest label to equal ``desired_digest``.

    Raises:
        _LabelRace: A different (or missing) digest is present -- another
            writer holds the lock, or we lost it. Caller retries.

    """
    cur_digest = normalize_digest(labels.get(COMPLIANCE_DIGEST_LABEL, ""))
    if cur_digest != desired_digest:
        raise _LabelRace


def _claim_compliance_digest(
    client: PulpNpmClient, content_href: str, desired_digest: str, key: str
) -> None:
    """Write the digest label and verify the claim stuck.

    Raises:
        _ContentGone: Content vanished before the claim could be verified.
        _LabelRace: Another writer's digest won the race.

    """
    client.set_label(content_href, COMPLIANCE_DIGEST_LABEL, desired_digest)
    click.echo(
        f"Updated {key} Pulp label {COMPLIANCE_DIGEST_LABEL} -> {desired_digest}",
        err=True,
    )
    labels = _read_pulp_labels(client, content_href)
    _assert_digest_or_race(labels, desired_digest)


def _reread_holding_digest(
    client: PulpNpmClient, content_href: str, desired_digest: str
) -> str:
    """Re-read labels, requiring our digest is still held; return the level.

    Raises:
        _ContentGone: Content vanished.
        _LabelRace: Another writer's digest has replaced ours.

    """
    labels = _read_pulp_labels(client, content_href)
    _assert_digest_or_race(labels, desired_digest)
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
) -> bool:
    """Return True when digest is still ours and level is at least desired.

    Raises:
        _ContentGone: Content vanished.
        _LabelRace: Another writer's digest has replaced ours.

    """
    cur_level = _reread_holding_digest(client, content_href, desired_digest)
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
    max_retries: int = DEFAULT_CAS_MAX_RETRIES,
) -> None:
    """Set Pulp compliance labels using the OCI digest as an optimistic lock.

    Pulp ``set_label`` is not atomic CAS. High-level protocol per round:

    1. Read current labels; return if already satisfied or if the content
       unit no longer exists.
    2. Claim ``tl.compliance_oci_digest`` (if not already ours) and verify
       it stuck.
    3. Re-read under that digest; raise the level only if the sticky max
       needs it (never downgrades).
    4. Final verify digest + level; return on success, else back off and
       retry the whole round, up to ``max_retries`` times.

    ``repo_version_href`` is accepted for interface symmetry with
    ``find_content_in_repo`` (which callers use to resolve ``content_href``
    before calling this function) -- once resolved, this protocol re-reads
    directly by ``content_href`` via ``client.get_labels``, so it is not
    used in the body here.

    Raises:
        click.ClickException: The digest/level could not be established
            within ``max_retries`` rounds -- a persistent foreign-digest
            race, or the level verify never catching up.

    """
    desired_digest = normalize_digest(compliance_digest)
    if not desired_digest:
        return
    key = node_key(name, version)
    desired_level = level or ""

    for attempt in range(max_retries):
        try:
            labels = _read_pulp_labels(client, content_href)
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

            if not desired_level:
                return

            cur_level = _reread_holding_digest(
                client, content_href, desired_digest
            )
            _maybe_raise_compliance_level(
                client, content_href, cur_level, desired_level, key
            )

            if _final_labels_ok(
                client, content_href, desired_digest, desired_level
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
        except _LabelRace:
            pass  # another writer currently holds/contests the lock; retry

        if attempt + 1 >= max_retries:
            break
        click.echo(
            f"Pulp label CAS retry {attempt + 1}/{max_retries} for {key} "
            f"(wanted digest {desired_digest} "
            f"level {desired_level or '<none>'})",
            err=True,
        )
        time.sleep(_RETRY_BACKOFF_SECONDS * (attempt + 1))

    raise click.ClickException(
        f"Pulp label CAS failed for {key} after {max_retries} retries "
        f"(wanted digest {desired_digest} level {desired_level or '<none>'})"
    )
