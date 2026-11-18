"""Tests for the `slan-cuan npm closure` command group.

These are integration-flavored tests of orchestration -- Tasks 13-15's own
pure/Pulp/OCI logic is already unit-tested in ``closure_model_test.py``,
``closure_pulp_test.py``, and ``closure_oci_test.py``. Here, ``PulpNpmClient``
construction and every ``closure_pulp``/``closure_oci`` module function are
mocked; what's under test is that ``closure.py`` wires them together in the
right order with the right data.
"""

from __future__ import annotations

import copy
import json
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.npm import closure_model
from slan_cuan.npm.closure import (
    drain_blocker_parents,
    find_resolved_version_for_dep,
)

_REPO_HREF = "/api/v3/repositories/npm/npm/abc/"
_REPO_VERSION_HREF = "/api/v3/repositories/npm/npm/abc/versions/5/"
_REPO = {
    "name": "npm-registry",
    "pulp_href": _REPO_HREF,
    "latest_version_href": _REPO_VERSION_HREF,
}
DIGEST = "sha256:" + "a" * 64
INDEX_DIGEST = "sha256:" + "b" * 64

_PULP_ARGS = [
    "--pulp-url",
    "https://pulp.example.com",
    "--pulp-repository",
    "npm-registry",
    "--pulp-domain",
    "lightwell",
    "--pulp-username",
    "user",
    "--pulp-password",
    "pass",
]
_OCI_ARGS = ["--compliance-image-prefix", "quay.io/org/tl-compliance"]


def _write_sidecar(
    tmp_path: Path,
    *,
    name: str = "pkg",
    version: str = "1.0.0",
    compliance_level: str = "L3",
    direct_dependencies: list[dict] | None = None,
    missing_gaps: list[str] | None = None,
    pending_l3_gaps: list[str] | None = None,
) -> Path:
    """Write a *.tl-compliance.json sidecar and return its path."""
    payload = {
        "name": name,
        "version": version,
        "compliance_level": compliance_level,
        "direct_dependencies": direct_dependencies or [],
        "missing_gaps": missing_gaps or [],
        "pending_l3_gaps": pending_l3_gaps or [],
    }
    path = tmp_path / f"{name}-{version}.tl-compliance.json"
    path.write_text(json.dumps(payload))
    return path


@pytest.fixture
def runner() -> CliRunner:
    """Return a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mocks():
    """Patch every external dependency of slan_cuan.npm.closure.

    Defaults to a quiet "no blockers, nothing to do" happy path; individual
    tests override return_value/side_effect as needed.
    """
    with ExitStack() as stack:
        client = MagicMock()
        client_cls = stack.enter_context(
            patch("slan_cuan.npm.closure.PulpNpmClient")
        )
        client_cls.return_value.__enter__.return_value = client

        resolve_repo = stack.enter_context(
            patch("slan_cuan.npm.closure._resolve_repo", return_value=dict(_REPO))
        )

        pull_index = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_oci.pull_index")
        )
        pull_index.return_value = (closure_model.empty_index(), None)

        cas_publish_compliance = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_oci.cas_publish_compliance")
        )
        cas_publish_compliance.return_value = DIGEST

        cas_push_index = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_oci.cas_push_index")
        )
        cas_push_index.return_value = ({"revision": 1}, INDEX_DIGEST)

        publish_compliance_doc = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_oci.publish_compliance_doc")
        )
        publish_compliance_doc.return_value = DIGEST

        publish_index = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_oci.publish_index")
        )
        publish_index.return_value = (
            {"revision": 1, "entries": {}},
            INDEX_DIGEST,
        )

        pull_compliance_doc = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_oci.pull_compliance_doc")
        )
        pull_compliance_doc.return_value = (None, None)

        list_repo_packages = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_pulp.list_repo_packages")
        )
        list_repo_packages.return_value = iter([])

        find_content_in_repo = stack.enter_context(
            patch("slan_cuan.npm.closure.closure_pulp.find_content_in_repo")
        )
        find_content_in_repo.return_value = None

        drain = stack.enter_context(
            patch("slan_cuan.npm.closure.drain_blocker_parents")
        )
        drain.return_value = []

        find_resolved_version_for_dep = stack.enter_context(
            patch("slan_cuan.npm.closure.find_resolved_version_for_dep")
        )
        find_resolved_version_for_dep.return_value = None

        tl_level_for_key = stack.enter_context(
            patch("slan_cuan.npm.closure.tl_level_for_key")
        )
        tl_level_for_key.return_value = "L3"

        yield SimpleNamespace(
            client=client,
            client_cls=client_cls,
            resolve_repo=resolve_repo,
            pull_index=pull_index,
            cas_publish_compliance=cas_publish_compliance,
            cas_push_index=cas_push_index,
            publish_compliance_doc=publish_compliance_doc,
            publish_index=publish_index,
            pull_compliance_doc=pull_compliance_doc,
            list_repo_packages=list_repo_packages,
            find_content_in_repo=find_content_in_repo,
            drain=drain,
            find_resolved_version_for_dep=find_resolved_version_for_dep,
            tl_level_for_key=tl_level_for_key,
        )


class TestUpdateCommand:
    """CLI-level tests for `slan-cuan npm closure update`."""

    def test_update_command_prints_summary_json(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A clean no-blockers release prints the five documented keys."""
        sidecar = _write_sidecar(tmp_path)

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert set(payload.keys()) == {
            "package",
            "compliance_level",
            "compliance_oci_digest",
            "parents_refreshed",
            "index_revision",
            "index_oci_digest",
        }
        assert payload["package"] == "pkg@1.0.0"
        assert payload["compliance_level"] == "L3"
        assert payload["compliance_oci_digest"] == DIGEST
        assert payload["parents_refreshed"] == []
        assert payload["index_revision"] == 1
        assert payload["index_oci_digest"] == INDEX_DIGEST

    def test_update_command_rejects_non_npm_pulp_href(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A --pulp-href that isn't an npm content href is rejected up front."""
        sidecar = _write_sidecar(tmp_path)

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                "--pulp-href",
                "/api/pulp/lightwell/api/v3/content/python/packages/abc/",
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code != 0
        assert "Refusing non-npm content href" in result.output
        mocks.resolve_repo.assert_not_called()
        mocks.pull_index.assert_not_called()
        mocks.cas_publish_compliance.assert_not_called()
        mocks.cas_push_index.assert_not_called()

    def test_update_command_drains_blocker_parents_before_publishing(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A release that is itself an index blocker drains before publish."""
        sidecar = _write_sidecar(tmp_path)
        index = {
            "schema_version": 1,
            "revision": 3,
            "updated_at": "2026-01-01T00:00:00Z",
            "entries": {"pkg@1.0.0": {"parents": ["waiter@2.0.0"]}},
        }
        mocks.pull_index.return_value = (index, "sha256:" + "c" * 64)

        call_order: list[str] = []
        mocks.drain.side_effect = lambda *a, **k: call_order.append("drain") or []
        mocks.cas_publish_compliance.side_effect = lambda *a, **k: (
            call_order.append("publish") or DIGEST
        )

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code == 0, result.output
        mocks.drain.assert_called_once()
        assert mocks.drain.call_args[0][3] == "pkg@1.0.0"
        assert call_order == ["drain", "publish"]

    def test_update_command_registers_release_gaps_on_index_when_not_l3(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A non-L3 release registers its own gaps as index entries."""
        sidecar = _write_sidecar(
            tmp_path,
            compliance_level="L1",
            direct_dependencies=[{"name": "dep", "requested": "^1.0.0"}],
            missing_gaps=["dep@^1.0.0"],
        )

        captured: dict[str, dict] = {}

        def _fake_cas_push_index(mutator, **kwargs):
            captured["index"] = mutator(closure_model.empty_index())
            return captured["index"], INDEX_DIGEST

        mocks.cas_push_index.side_effect = _fake_cas_push_index

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code == 0, result.output
        assert captured["index"]["entries"]["dep@^1.0.0"]["parents"] == [
            "pkg@1.0.0"
        ]

    def test_update_command_clears_index_entries_on_l3_release(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """An L3 release clears the index entries it satisfies."""
        sidecar = _write_sidecar(tmp_path, compliance_level="L3")
        pre_index = {
            "schema_version": 1,
            "revision": 0,
            "updated_at": "2026-01-01T00:00:00Z",
            "entries": {"pkg@1.0.0": {"parents": ["waiter@1.0.0"]}},
        }
        mocks.pull_index.return_value = (copy.deepcopy(pre_index), None)

        captured: dict[str, dict] = {}

        def _fake_cas_push_index(mutator, **kwargs):
            captured["index"] = mutator(copy.deepcopy(pre_index))
            return captured["index"], INDEX_DIGEST

        mocks.cas_push_index.side_effect = _fake_cas_push_index

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code == 0, result.output
        assert captured["index"]["entries"] == {}

    def test_update_command_unflagged_alias_dependency_stays_below_l3(
        self, runner: CliRunner, tmp_path: Path, mocks: SimpleNamespace
    ) -> None:
        """A sidecar claiming L3 with an unflagged alias dep is not L3.

        The automated update path trusts the sidecar and never runs
        rebalance's dependency re-scan, so the alias fail-closed gap must
        be injected on the shared sidecar_to_doc path.
        """
        sidecar = _write_sidecar(
            tmp_path,
            compliance_level="L3",
            direct_dependencies=[
                {"name": "my-dep", "requested": "npm:real-pkg@^1.2.0"}
            ],
        )
        alias_key = closure_model.alias_gap_key("my-dep")
        captured: dict[str, dict] = {}

        def _fake_cas_push_index(mutator, **kwargs):
            captured["index"] = mutator(closure_model.empty_index())
            return captured["index"], INDEX_DIGEST

        mocks.cas_push_index.side_effect = _fake_cas_push_index

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["compliance_level"] == "L1"
        published = mocks.cas_publish_compliance.call_args.args[1]
        assert published["compliance_level"] == "L1"
        assert published["missing_gaps"] == [alias_key]
        assert captured["index"]["entries"][alias_key]["parents"] == ["pkg@1.0.0"]


class TestSeedCommand:
    """CLI-level tests for `slan-cuan npm closure seed`."""

    def test_seed_command_skips_packages_with_existing_compliance_doc(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """A package with an existing compliance doc is not republished."""
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        existing_doc = closure_model.normalize_doc(
            {"name": "pkg", "version": "1.0.0", "compliance_level": "L2"}
        )
        mocks.pull_compliance_doc.return_value = (existing_doc, DIGEST)

        result = runner.invoke(
            main, ["npm", "closure", "seed", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.publish_compliance_doc.assert_not_called()
        payload = json.loads(result.stdout)
        assert payload["node_count"] == 1
        assert payload["compliance_oci"] == {}
        assert payload["index"] is None

    def test_seed_command_hydrates_new_packages_as_l3(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """A package with no existing compliance doc is seeded at L3."""
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (None, None)

        result = runner.invoke(
            main, ["npm", "closure", "seed", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.publish_compliance_doc.assert_called_once()
        published_doc = mocks.publish_compliance_doc.call_args[0][1]
        assert published_doc["compliance_level"] == "L3"
        assert published_doc["name"] == "pkg"
        payload = json.loads(result.stdout)
        assert payload["node_count"] == 1
        assert payload["compliance_oci"] == {"pkg@1.0.0": DIGEST}

    def test_seed_command_init_index_rebuilds_and_pushes(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """--init-index rebuilds the index from seeded docs and pushes it."""
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (None, None)
        mocks.publish_index.return_value = (
            {"revision": 1, "entries": {}},
            INDEX_DIGEST,
        )

        result = runner.invoke(
            main,
            ["npm", "closure", "seed", "--init-index", *_PULP_ARGS, *_OCI_ARGS],
        )

        assert result.exit_code == 0, result.output
        mocks.publish_index.assert_called_once()
        assert mocks.publish_index.call_args.kwargs["expected_revision"] == 0
        payload = json.loads(result.stdout)
        assert payload["index"] == {"revision": 1, "digest": INDEX_DIGEST}


class TestRebalanceCommand:
    """CLI-level tests for `slan-cuan npm closure rebalance`."""

    def _doc(self, **overrides) -> dict:
        base = {
            "name": "pkg",
            "version": "1.0.0",
            "compliance_level": "L3",
            "direct_dependencies": [{"name": "dep", "requested": "^1.0.0"}],
            "missing_gaps": [],
            "pending_l3_gaps": [],
        }
        base.update(overrides)
        return closure_model.normalize_doc(base)

    def test_rebalance_command_index_only_skips_gap_rederivation(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """--index-only never calls the per-dependency resolution helpers."""
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (self._doc(), DIGEST)

        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "rebalance",
                "--index-only",
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )

        assert result.exit_code == 0, result.output
        mocks.find_resolved_version_for_dep.assert_not_called()
        mocks.tl_level_for_key.assert_not_called()
        mocks.publish_compliance_doc.assert_not_called()
        payload = json.loads(result.stdout)
        assert payload["mode"] == "index-only"

    def test_rebalance_command_recomputes_gaps_and_republishes_on_change(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """A resolution change from the stored doc triggers a republish."""
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (self._doc(), DIGEST)
        mocks.find_resolved_version_for_dep.return_value = None  # now unresolved

        result = runner.invoke(
            main, ["npm", "closure", "rebalance", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.publish_compliance_doc.assert_called_once()
        payload = json.loads(result.stdout)
        assert payload["compliance_updated"] == ["pkg@1.0.0"]
        assert payload["mode"] == "full"

    def test_rebalance_command_leaves_unchanged_docs_unpublished(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """A doc whose recomputed gaps/level match the stored one is skipped."""
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        # Stored doc already reflects "dep" unresolved -- recomputation
        # with the same (mocked) resolution outcome should be a no-op.
        doc = self._doc(missing_gaps=["dep@^1.0.0"], compliance_level="L1")
        mocks.pull_compliance_doc.return_value = (doc, DIGEST)
        mocks.find_resolved_version_for_dep.return_value = None

        result = runner.invoke(
            main, ["npm", "closure", "rebalance", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.publish_compliance_doc.assert_not_called()
        payload = json.loads(result.stdout)
        assert payload["compliance_updated"] == []

    def _alias_doc(self) -> dict:
        return self._doc(
            direct_dependencies=[
                {"name": "my-dep", "requested": "npm:real-pkg@^1.2.0"}
            ],
        )

    def test_rebalance_command_never_resolves_alias_dependency_spec(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """An npm: alias dependency spec is never resolved.

        A package.json dependency value like
        ``"npm:real-pkg@^1.2.0"`` is an alias spec: its real registry
        identity is a different package than the dependency's own name.
        Resolving it via ``find_resolved_version_for_dep``/building a
        node key from the alias dep's own name and raw spec would either
        crash ``parse_node_key`` (the spec itself contains an ``@``) or
        silently attribute a different package's identity to the wrong
        name, so it must never be resolved.
        """
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (self._alias_doc(), DIGEST)

        result = runner.invoke(
            main, ["npm", "closure", "rebalance", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.find_resolved_version_for_dep.assert_not_called()
        mocks.tl_level_for_key.assert_not_called()

    def test_rebalance_command_alias_dependency_keeps_package_below_l3(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """An unverifiable alias dependency fails closed as a missing gap.

        A package whose only direct dependency is an npm alias must not
        be certified L3: the alias's real target was never checked, so
        it is recorded as a permanently-unresolvable missing gap keyed
        by the LOCAL dependency name (keeping ``validate_gap_subset``'s
        invariant) and a fixed sentinel version.
        """
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (self._alias_doc(), DIGEST)

        result = runner.invoke(
            main, ["npm", "closure", "rebalance", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.publish_compliance_doc.assert_called_once()
        published = mocks.publish_compliance_doc.call_args.args[1]
        assert published["compliance_level"] == "L1"
        assert published["missing_gaps"] == [
            closure_model.node_key(
                "my-dep", closure_model.UNVERIFIABLE_ALIAS_VERSION
            )
        ]
        assert published["pending_l3_gaps"] == []
        closure_model.validate_gap_subset(published)
        payload = json.loads(result.stdout)
        assert payload["compliance_updated"] == ["pkg@1.0.0"]

    def test_rebalance_command_alias_plus_normal_dep_matches_old_end_state(
        self, runner: CliRunner, mocks: SimpleNamespace
    ) -> None:
        """Rebalance + enforce_alias_gaps match the old inline-only end-state.

        For a realistic multi-dependency doc, one alias dependency (never
        resolved, no longer appended inline)
        and one normal, fully-resolved-at-L3 dependency: the published
        doc's missing_gaps must still contain exactly the alias gap key
        (now added by ``closure_model.enforce_alias_gaps`` instead of the
        loop's own ``.append()``), with the normal dependency contributing
        no gap at all, and the level still capped at L1.
        """
        doc = self._doc(
            direct_dependencies=[
                {"name": "my-dep", "requested": "npm:real-pkg@^1.2.0"},
                {"name": "normal-dep", "requested": "^2.0.0"},
            ],
        )
        mocks.list_repo_packages.return_value = iter(
            [{"name": "pkg", "version": "1.0.0", "pulp_href": "href1"}]
        )
        mocks.pull_compliance_doc.return_value = (doc, DIGEST)
        mocks.find_resolved_version_for_dep.return_value = "2.0.0"
        mocks.tl_level_for_key.return_value = "L3"

        result = runner.invoke(
            main, ["npm", "closure", "rebalance", *_PULP_ARGS, *_OCI_ARGS]
        )

        assert result.exit_code == 0, result.output
        mocks.find_resolved_version_for_dep.assert_called_once_with(
            mocks.client,
            "normal-dep",
            "^2.0.0",
            doc,
            _REPO_VERSION_HREF,
            available_versions={"pkg": ["1.0.0"]},
        )
        published = mocks.publish_compliance_doc.call_args.args[1]
        assert published["compliance_level"] == "L1"
        assert published["missing_gaps"] == [
            closure_model.node_key(
                "my-dep", closure_model.UNVERIFIABLE_ALIAS_VERSION
            )
        ]
        assert published["pending_l3_gaps"] == []
        closure_model.validate_gap_subset(published)
        payload = json.loads(result.stdout)
        assert payload["compliance_updated"] == ["pkg@1.0.0"]


class TestRebalanceBatchedDependencyResolution:
    """Rebalance must resolve every dependency from one batched repo query.

    Regression test for the N+1 Pulp query bug: before this fix,
    ``find_resolved_version_for_dep`` issued one fresh
    ``closure_pulp.list_versions_in_repo`` Pulp query per dependency per
    package -- O(packages x dependencies) queries for a single rebalance
    pass. Rebalance must instead fetch the repo's full content listing
    once (the same ``list_repo_packages`` call its outer loop already
    makes) and resolve every dependency in-memory against it, leaving
    ``list_versions_in_repo`` untouched.

    Unlike ``TestRebalanceCommand``, this does not use the ``mocks``
    fixture: that fixture replaces ``find_resolved_version_for_dep``
    wholesale, which would hide the very per-dependency Pulp call this
    test exists to count.
    """

    def _doc(self, name: str, deps: list[dict]) -> dict:
        base = {
            "name": name,
            "version": "1.0.0",
            "compliance_level": "L3",
            "direct_dependencies": deps,
            "missing_gaps": [],
            "pending_l3_gaps": [],
        }
        return closure_model.normalize_doc(base)

    def test_rebalance_resolves_many_dependencies_with_one_repo_content_query(
        self, runner: CliRunner
    ) -> None:
        """2 packages x (2+1) deps -> zero per-dependency Pulp queries."""
        repo_rows = [
            {"name": "pkg-a", "version": "1.0.0", "pulp_href": "href-a"},
            {"name": "pkg-b", "version": "1.0.0", "pulp_href": "href-b"},
            {"name": "dep-1", "version": "1.2.0", "pulp_href": "href-d1"},
            {"name": "dep-2", "version": "2.0.0", "pulp_href": "href-d2"},
        ]
        docs = {
            "pkg-a@1.0.0": self._doc(
                "pkg-a",
                [
                    {"name": "dep-1", "requested": "^1.0.0"},
                    {"name": "dep-2", "requested": "^2.0.0"},
                ],
            ),
            "pkg-b@1.0.0": self._doc(
                "pkg-b", [{"name": "dep-1", "requested": "^1.0.0"}]
            ),
        }

        def _fake_pull_compliance_doc(name, version, *_args, **_kwargs):
            return docs.get(closure_model.node_key(name, version)), DIGEST

        with ExitStack() as stack:
            client = MagicMock()
            client_cls = stack.enter_context(
                patch("slan_cuan.npm.closure.PulpNpmClient")
            )
            client_cls.return_value.__enter__.return_value = client
            stack.enter_context(
                patch(
                    "slan_cuan.npm.closure._resolve_repo",
                    return_value=dict(_REPO),
                )
            )
            list_repo_packages = stack.enter_context(
                patch(
                    "slan_cuan.npm.closure.closure_pulp.list_repo_packages",
                    side_effect=lambda *a, **k: iter(repo_rows),
                )
            )
            stack.enter_context(
                patch(
                    "slan_cuan.npm.closure.closure_oci.pull_compliance_doc",
                    side_effect=_fake_pull_compliance_doc,
                )
            )
            list_versions_in_repo = stack.enter_context(
                patch("slan_cuan.npm.closure.closure_pulp.list_versions_in_repo")
            )
            stack.enter_context(
                patch("slan_cuan.npm.closure.tl_level_for_key", return_value="L3")
            )
            stack.enter_context(
                patch(
                    "slan_cuan.npm.closure.closure_oci.publish_compliance_doc",
                    return_value=DIGEST,
                )
            )
            stack.enter_context(
                patch(
                    "slan_cuan.npm.closure.closure_oci.cas_push_index",
                    return_value=({"revision": 1}, INDEX_DIGEST),
                )
            )

            result = runner.invoke(
                main, ["npm", "closure", "rebalance", *_PULP_ARGS, *_OCI_ARGS]
            )

        assert result.exit_code == 0, result.output
        list_repo_packages.assert_called_once()
        list_versions_in_repo.assert_not_called()


class TestFindResolvedVersionForDep:
    """Direct unit tests for find_resolved_version_for_dep's resolution."""

    def _doc(self, **overrides) -> dict:
        base = {
            "name": "pkg",
            "version": "1.0.0",
            "compliance_level": "L3",
            "direct_dependencies": [{"name": "dep", "requested": "^4.17.21"}],
            "missing_gaps": [],
            "pending_l3_gaps": [],
        }
        base.update(overrides)
        return closure_model.normalize_doc(base)

    def test_resolves_non_pinned_range_against_a_satisfying_repo_version(
        self,
    ) -> None:
        """A semver-range spec resolves to the highest satisfying version.

        Regression test: an exact-match lookup against a range spec like
        ``^4.17.21`` would (almost) never find a byte-identical version
        string, leaving the dependency stuck unresolved even though a
        satisfying version genuinely exists in the repo.
        """
        client = MagicMock()
        doc = self._doc()
        rows = [
            {"name": "dep", "version": "4.17.20"},
            {"name": "dep", "version": "4.17.21"},
            {"name": "dep", "version": "4.18.0"},
        ]
        with patch(
            "slan_cuan.npm.closure.closure_pulp.list_versions_in_repo",
            return_value=rows,
        ) as list_versions:
            resolved = find_resolved_version_for_dep(
                client, "dep", "^4.17.21", doc, _REPO_VERSION_HREF
            )

        assert resolved == "4.18.0"
        list_versions.assert_called_once_with(client, "dep", _REPO_VERSION_HREF)

    def test_returns_none_when_no_repo_version_satisfies_the_range(self) -> None:
        """No row satisfies the range -> None (falls through to a gap)."""
        client = MagicMock()
        doc = self._doc()
        rows = [{"name": "dep", "version": "3.0.0"}]
        with patch(
            "slan_cuan.npm.closure.closure_pulp.list_versions_in_repo",
            return_value=rows,
        ):
            resolved = find_resolved_version_for_dep(
                client, "dep", "^4.17.21", doc, _REPO_VERSION_HREF
            )

        assert resolved is None

    def test_gap_keys_are_checked_before_the_repo_lookup(self) -> None:
        """An already-recorded gap key short-circuits the repo lookup."""
        client = MagicMock()
        doc = self._doc(missing_gaps=["dep@4.17.21"])
        with patch(
            "slan_cuan.npm.closure.closure_pulp.list_versions_in_repo"
        ) as list_versions:
            resolved = find_resolved_version_for_dep(
                client, "dep", "^4.17.21", doc, _REPO_VERSION_HREF
            )

        assert resolved == "4.17.21"
        list_versions.assert_not_called()

    def test_available_versions_resolves_in_memory_without_touching_pulp(
        self,
    ) -> None:
        """An ``available_versions`` dict skips the Pulp lookup entirely.

        Passes a client that would raise if any method were called on it,
        proving the batched (rebalance) resolution path never falls back
        to a per-dependency Pulp query.
        """
        client = MagicMock()
        client.side_effect = AssertionError(
            "available_versions path must not touch the Pulp client"
        )
        doc = self._doc()
        available_versions = {"dep": ["4.17.20", "4.17.21", "4.18.0"]}
        with patch(
            "slan_cuan.npm.closure.closure_pulp.list_versions_in_repo"
        ) as list_versions:
            resolved = find_resolved_version_for_dep(
                client,
                "dep",
                "^4.17.21",
                doc,
                _REPO_VERSION_HREF,
                available_versions=available_versions,
            )

        assert resolved == "4.18.0"
        list_versions.assert_not_called()
        client.assert_not_called()

    def test_available_versions_missing_dep_name_resolves_to_none(self) -> None:
        """A dep name absent from ``available_versions`` resolves to None."""
        client = MagicMock()
        doc = self._doc()
        with patch(
            "slan_cuan.npm.closure.closure_pulp.list_versions_in_repo"
        ) as list_versions:
            resolved = find_resolved_version_for_dep(
                client,
                "dep",
                "^4.17.21",
                doc,
                _REPO_VERSION_HREF,
                available_versions={},
            )

        assert resolved is None
        list_versions.assert_not_called()


def _assert_no_io(mocks: SimpleNamespace) -> None:
    """Assert no Pulp client, Pulp helper, or OCI I/O was touched."""
    for name in (
        "client_cls",
        "resolve_repo",
        "pull_index",
        "cas_publish_compliance",
        "cas_push_index",
        "publish_compliance_doc",
        "publish_index",
        "pull_compliance_doc",
        "list_repo_packages",
        "find_content_in_repo",
        "drain",
        "find_resolved_version_for_dep",
        "tl_level_for_key",
    ):
        getattr(mocks, name).assert_not_called()
    assert mocks.client.method_calls == []


class TestDryRun:
    """--dry-run previews closure write commands without any I/O."""

    def test_update_dry_run_makes_no_calls(self, runner, mocks, tmp_path):
        """Update --dry-run names the sidecar and makes zero I/O calls."""
        sidecar = _write_sidecar(tmp_path, name="pkg", version="1.0.0")
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(sidecar),
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Would publish L3 compliance document for pkg@1.0.0" in (
            result.output
        )
        assert str(sidecar) in result.output
        _assert_no_io(mocks)

    def test_seed_dry_run_makes_no_calls(self, runner, mocks):
        """Seed --dry-run --init-index previews both steps, no I/O."""
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "npm",
                "closure",
                "seed",
                "--init-index",
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Would push a seed compliance document" in result.output
        assert "Would rebuild the closure index" in result.output
        _assert_no_io(mocks)

    def test_rebalance_dry_run_makes_no_calls(self, runner, mocks):
        """Rebalance --dry-run previews gap re-derive + index push, no I/O."""
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "npm",
                "closure",
                "rebalance",
                *_PULP_ARGS,
                *_OCI_ARGS,
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Would re-derive gap lists" in result.output
        assert "Would rebuild the closure index" in result.output
        _assert_no_io(mocks)


def _pulp_args_for_repo(repo_name: str) -> list[str]:
    """Return _PULP_ARGS with --pulp-repository swapped for repo_name."""
    args = list(_PULP_ARGS)
    args[args.index("--pulp-repository") + 1] = repo_name
    return args


class TestPythonWheelsRepositoryGuard:
    """--pulp-repository main (the python-wheels repo) is refused early."""

    @pytest.mark.parametrize("dry_run", [False, True])
    @pytest.mark.parametrize("command", ["update", "seed", "rebalance"])
    def test_refuses_python_wheels_repository_before_any_io(
        self, runner, mocks, tmp_path, command, dry_run
    ):
        """Each write command fails with a clear error and makes no I/O."""
        extra = (
            ["--sidecar", str(_write_sidecar(tmp_path))]
            if command == "update"
            else []
        )
        result = runner.invoke(
            main,
            [
                *(["--dry-run"] if dry_run else []),
                "npm",
                "closure",
                command,
                *extra,
                *_pulp_args_for_repo(closure_model.PYTHON_WHEELS_REPOSITORY),
                *_OCI_ARGS,
            ],
        )
        assert result.exit_code != 0
        assert "python-wheels Pulp repository" in result.output
        assert "PULP_REPOSITORY=main" in result.output
        assert "Would " not in result.output
        _assert_no_io(mocks)

    def test_refuses_case_variant_of_python_wheels_repository(
        self, runner, mocks, tmp_path
    ):
        """A case/whitespace variant like 'Main' is refused too."""
        result = runner.invoke(
            main,
            [
                "npm",
                "closure",
                "update",
                "--sidecar",
                str(_write_sidecar(tmp_path)),
                *_pulp_args_for_repo("Main"),
                *_OCI_ARGS,
            ],
        )
        assert result.exit_code != 0
        assert "python-wheels Pulp repository" in result.output
        _assert_no_io(mocks)


class TestShowCommand:
    """CLI-level tests for `slan-cuan npm closure show`."""

    def test_show_command_prints_compliance_path_file_verbatim_when_given(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """--compliance-path prints the file's exact content, no OCI pull."""
        content = json.dumps({"name": "pkg", "version": "1.0.0"})
        path = tmp_path / "local.tl-compliance.json"
        path.write_text(content)

        with patch(
            "slan_cuan.npm.closure.closure_oci.pull_compliance_doc"
        ) as pull_doc:
            result = runner.invoke(
                main,
                ["npm", "closure", "show", "--compliance-path", str(path)],
            )

        assert result.exit_code == 0, result.output
        assert result.output == content
        pull_doc.assert_not_called()

    def test_show_command_raises_when_no_doc_found(
        self, runner: CliRunner
    ) -> None:
        """No compliance doc in OCI raises a ClickException."""
        with patch(
            "slan_cuan.npm.closure.closure_oci.pull_compliance_doc",
            return_value=(None, None),
        ):
            result = runner.invoke(
                main,
                [
                    "npm",
                    "closure",
                    "show",
                    "--name",
                    "pkg",
                    "--version",
                    "1.0.0",
                    *_OCI_ARGS,
                ],
            )

        assert result.exit_code != 0
        assert "No compliance OCI for pkg@1.0.0" in result.output


class TestShowIndexCommand:
    """CLI-level tests for `slan-cuan npm closure show-index`."""

    def test_show_index_command_prints_digest_and_index(
        self, runner: CliRunner
    ) -> None:
        """show-index prints the pulled digest and index verbatim as JSON."""
        index = {"schema_version": 1, "revision": 2, "entries": {}}
        with patch(
            "slan_cuan.npm.closure.closure_oci.pull_index",
            return_value=(index, DIGEST),
        ):
            result = runner.invoke(
                main, ["npm", "closure", "show-index", *_OCI_ARGS]
            )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["digest"] == DIGEST
        assert payload["index"] == index


class TestDrainBlockerParents:
    """Direct unit tests for drain_blocker_parents's transitive promotion."""

    def test_drain_blocker_parents_promotes_transitively(self) -> None:
        """A parent reaching L3 after promotion has its own parents promoted."""
        index = {
            "schema_version": 1,
            "revision": 0,
            "updated_at": "2026-01-01T00:00:00Z",
            "entries": {
                "dep@1.0.0": {"parents": ["mid@1.0.0"]},
                "mid@1.0.0": {"parents": ["top@1.0.0"]},
            },
        }
        mid_doc = closure_model.normalize_doc(
            {
                "name": "mid",
                "version": "1.0.0",
                "missing_gaps": ["dep@1.0.0"],
                "compliance_level": "L1",
            }
        )
        top_doc = closure_model.normalize_doc(
            {
                "name": "top",
                "version": "1.0.0",
                "missing_gaps": ["mid@1.0.0"],
                "compliance_level": "L1",
            }
        )
        docs = {"mid@1.0.0": mid_doc, "top@1.0.0": top_doc}

        def _fake_pull_compliance_doc(name, version, *args, **kwargs):
            key = closure_model.node_key(name, version)
            doc = docs.get(key)
            return (copy.deepcopy(doc), None) if doc else (None, None)

        def _fake_cas_publish_compliance(client, doc, repo, **kwargs):
            key = closure_model.node_key(doc["name"], doc["version"])
            docs[key] = copy.deepcopy(doc)
            return (
                "sha256:"
                + key.replace("@", "").replace(".", "").ljust(64, "0")[:64]
            )

        client = MagicMock()
        with (
            patch(
                "slan_cuan.npm.closure.closure_oci.pull_compliance_doc",
                side_effect=_fake_pull_compliance_doc,
            ),
            patch(
                "slan_cuan.npm.closure.closure_oci.cas_publish_compliance",
                side_effect=_fake_cas_publish_compliance,
            ),
        ):
            refreshed = drain_blocker_parents(
                client,
                dict(_REPO),
                index,
                "dep@1.0.0",
                "L3",
                compliance_image_prefix="quay.io/org/tl-compliance",
                registry_url="https://registry.example.com",
            )

        assert refreshed == ["mid@1.0.0", "top@1.0.0"]
        assert docs["mid@1.0.0"]["compliance_level"] == "L3"
        assert docs["mid@1.0.0"]["missing_gaps"] == []
        assert docs["top@1.0.0"]["compliance_level"] == "L3"
        assert docs["top@1.0.0"]["missing_gaps"] == []
