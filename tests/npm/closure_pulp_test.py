"""Tests for the npm closure Pulp I/O and label CAS protocol."""

from __future__ import annotations

import importlib
from unittest.mock import Mock, patch

import click
import pytest

from slan_cuan.npm import closure_pulp
from slan_cuan.npm.closure_pulp import (
    COMPLIANCE_DIGEST_LABEL,
    COMPLIANCE_LABEL,
    find_content_in_repo,
    level_rank,
    list_repo_packages,
    monotone_target_level,
    normalize_digest,
    sync_content_pulp_labels,
)
from slan_cuan.pulp.exceptions import PulpError

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
CONTENT_HREF = "/api/pulp/test/api/v3/content/npm/packages/abc/"
REPO_VERSION_HREF = "/api/pulp/test/api/v3/repositories/npm/npm/x/versions/1/"


class TestNormalizeDigest:
    """normalize_digest -- bare hex prefixing, passthrough otherwise."""

    def test_normalize_digest_bare_hex_gets_prefixed(self):
        """A bare 64-char hex string gets a sha256: prefix, lowercased."""
        bare = "a" * 64
        assert normalize_digest(bare) == "sha256:" + bare
        assert normalize_digest("A" * 64) == "sha256:" + "a" * 64

    def test_normalize_digest_passthrough_for_non_digest_strings(self):
        """Empty, already-prefixed, and malformed strings pass through."""
        assert normalize_digest("") == ""
        assert normalize_digest("not-a-digest") == "not-a-digest"
        already = "sha256:" + "b" * 64
        assert normalize_digest(already) == already
        assert normalize_digest("abc123") == "abc123"


class TestLevelHelpers:
    """level_rank / monotone_target_level sticky-level comparisons."""

    def test_level_rank_and_monotone_target_level(self):
        """Unknown/empty ranks lowest; monotone target never downgrades."""
        assert level_rank("") == 0
        assert level_rank("bogus") == 0
        assert level_rank("L1") == 1
        assert level_rank("L2") == 2
        assert level_rank("L3") == 3

        assert monotone_target_level("L3", "L1") == "L3"
        assert monotone_target_level("L1", "L2") == "L2"
        assert monotone_target_level("", "L2") == "L2"
        assert monotone_target_level("L2", "") == "L2"


class TestFindContentInRepo:
    """find_content_in_repo -- thin wrapper over find_by_name_version."""

    def test_find_content_in_repo_delegates_to_client(self):
        """Delegates straight through with the same args and return value."""
        client = Mock()
        client.find_by_name_version.return_value = {"pulp_href": CONTENT_HREF}
        result = find_content_in_repo(
            client, "lodash", "4.17.21", REPO_VERSION_HREF
        )
        assert result == {"pulp_href": CONTENT_HREF}
        client.find_by_name_version.assert_called_once_with(
            "lodash", "4.17.21", REPO_VERSION_HREF
        )


class TestSyncContentPulpLabels:
    """sync_content_pulp_labels -- the claim/reverify/sticky-max CAS loop."""

    def test_sync_labels_noop_when_already_satisfied(self):
        """No writes when digest matches and level is already sufficient."""
        client = Mock()
        client.get_labels.return_value = {
            COMPLIANCE_DIGEST_LABEL: DIGEST,
            COMPLIANCE_LABEL: "L2",
        }
        sync_content_pulp_labels(
            client,
            CONTENT_HREF,
            REPO_VERSION_HREF,
            "pkg",
            "1.0.0",
            "L2",
            DIGEST,
        )
        client.set_label.assert_not_called()
        assert client.get_labels.call_count == 1

    def test_sync_labels_claims_digest_then_raises_level(self):
        """Claims the digest first, then raises the level, in that order."""
        client = Mock()
        client.get_labels.side_effect = [
            {},
            {COMPLIANCE_DIGEST_LABEL: DIGEST},
            {COMPLIANCE_DIGEST_LABEL: DIGEST},
            {COMPLIANCE_DIGEST_LABEL: DIGEST, COMPLIANCE_LABEL: "L2"},
        ]
        sync_content_pulp_labels(
            client,
            CONTENT_HREF,
            REPO_VERSION_HREF,
            "pkg",
            "1.0.0",
            "L2",
            DIGEST,
        )
        assert client.set_label.call_count == 2
        keys = [c.args[1] for c in client.set_label.call_args_list]
        assert keys == [COMPLIANCE_DIGEST_LABEL, COMPLIANCE_LABEL]
        assert client.set_label.call_args_list[0].args[2] == DIGEST
        assert client.set_label.call_args_list[1].args[2] == "L2"

    def test_sync_labels_noop_when_digest_and_level_already_match(self):
        """Fast-path no-op: digest matches and level already meets desired."""
        client = Mock()
        client.get_labels.return_value = {
            COMPLIANCE_DIGEST_LABEL: DIGEST,
            COMPLIANCE_LABEL: "L2",
        }
        sync_content_pulp_labels(
            client,
            CONTENT_HREF,
            REPO_VERSION_HREF,
            "pkg",
            "1.0.0",
            "L2",
            DIGEST,
        )
        client.set_label.assert_not_called()
        assert client.get_labels.call_count == 1

    def test_sync_labels_skips_level_write_when_current_already_higher(self):
        """Sticky max: a concurrent bump to L3 blocks our in-flight L2 write.

        Digest must be claimed first (so the fast-path
        ``_labels_already_satisfied`` check does NOT short-circuit) -- a
        concurrent writer then raises the level to L3 while we hold the
        digest, so ``_maybe_raise_compliance_level`` must see cur_level=L3
        for its own skip-write branch to actually execute.
        """
        client = Mock()
        client.get_labels.side_effect = [
            {},  # initial: no digest yet -> claim required
            {COMPLIANCE_DIGEST_LABEL: DIGEST},  # post-claim verify
            # before-level-write reread: concurrent writer already at L3
            {COMPLIANCE_DIGEST_LABEL: DIGEST, COMPLIANCE_LABEL: "L3"},
            # final verify: still L3, still ours
            {COMPLIANCE_DIGEST_LABEL: DIGEST, COMPLIANCE_LABEL: "L3"},
        ]
        sync_content_pulp_labels(
            client,
            CONTENT_HREF,
            REPO_VERSION_HREF,
            "pkg",
            "1.0.0",
            "L2",
            DIGEST,
        )
        keys = [c.args[1] for c in client.set_label.call_args_list]
        assert keys == [COMPLIANCE_DIGEST_LABEL]

    def test_sync_labels_raises_on_foreign_digest_race(self):
        """A persistent foreign digest retries, then fails closed."""
        client = Mock()
        client.get_labels.return_value = {
            COMPLIANCE_DIGEST_LABEL: OTHER_DIGEST,
            COMPLIANCE_LABEL: "L1",
        }
        with (
            patch("slan_cuan.npm.closure_pulp.time.sleep") as mock_sleep,
            pytest.raises(click.ClickException, match="Pulp label CAS failed"),
        ):
            sync_content_pulp_labels(
                client,
                CONTENT_HREF,
                REPO_VERSION_HREF,
                "pkg",
                "1.0.0",
                "L2",
                DIGEST,
                max_retries=3,
            )
        assert client.set_label.called
        digest_write_keys = {c.args[1] for c in client.set_label.call_args_list}
        assert digest_write_keys == {COMPLIANCE_DIGEST_LABEL}
        assert mock_sleep.call_count == 2

    def test_sync_labels_noop_when_content_not_found(self):
        """A missing content unit is a clean no-op, not an error."""
        client = Mock()
        client.get_labels.side_effect = PulpError(
            "not found", status_code=404, response_body=""
        )
        sync_content_pulp_labels(
            client,
            CONTENT_HREF,
            REPO_VERSION_HREF,
            "pkg",
            "1.0.0",
            "L2",
            DIGEST,
        )
        client.set_label.assert_not_called()

    def test_sync_labels_retries_before_succeeding(self):
        """Round 1's final verify fails; round 2 finds it already satisfied."""
        client = Mock()
        client.get_labels.side_effect = [
            {},
            {COMPLIANCE_DIGEST_LABEL: DIGEST},
            {COMPLIANCE_DIGEST_LABEL: DIGEST},
            {COMPLIANCE_DIGEST_LABEL: DIGEST},
            {COMPLIANCE_DIGEST_LABEL: DIGEST, COMPLIANCE_LABEL: "L2"},
        ]
        with patch("slan_cuan.npm.closure_pulp.time.sleep") as mock_sleep:
            sync_content_pulp_labels(
                client,
                CONTENT_HREF,
                REPO_VERSION_HREF,
                "pkg",
                "1.0.0",
                "L2",
                DIGEST,
            )
        assert client.get_labels.call_count == 5
        assert mock_sleep.call_count == 1
        assert client.set_label.call_count == 2


class TestDefaultCasMaxRetries:
    """DEFAULT_CAS_MAX_RETRIES -- env-var override, matching the original."""

    def test_default_max_retries_reads_env_var_override(self, monkeypatch):
        """CLOSURE_CAS_MAX_RETRIES overrides the default retry ceiling."""
        monkeypatch.setenv("CLOSURE_CAS_MAX_RETRIES", "3")
        try:
            reloaded = importlib.reload(closure_pulp)
            assert reloaded.DEFAULT_CAS_MAX_RETRIES == 3
        finally:
            importlib.reload(closure_pulp)

    def test_default_max_retries_falls_back_to_eight(self, monkeypatch):
        """Without the env var set, the default retry ceiling is 8."""
        monkeypatch.delenv("CLOSURE_CAS_MAX_RETRIES", raising=False)
        reloaded = importlib.reload(closure_pulp)
        assert reloaded.DEFAULT_CAS_MAX_RETRIES == 8


class TestListRepoPackages:
    """list_repo_packages -- yields only rows with both name and version."""

    def test_list_repo_packages_yields_rows_with_name_and_version(self):
        """Rows missing a name or version are dropped; others pass through."""
        client = Mock()
        client._config.domain = "test-domain"
        client.list_content.return_value = [
            {"name": "lodash", "version": "4.17.21"},
            {"name": "", "version": "1.0.0"},
            {"name": "express", "version": ""},
            {"name": "chalk", "version": "5.0.0"},
        ]
        repo = {"latest_version_href": "/repo/versions/9/"}
        rows = list(list_repo_packages(client, repo))
        assert [r["name"] for r in rows] == ["lodash", "chalk"]
        client.list_content.assert_called_once()
        _args, kwargs = client.list_content.call_args
        assert kwargs.get("repository_version") == "/repo/versions/9/"
