"""Tests for the pure npm closure compliance doc/index data model."""

from __future__ import annotations

import click
import pytest

from slan_cuan.npm.closure_model import (
    SCHEMA_VERSION,
    apply_index_release,
    compliance_filename,
    compliance_oci_tag,
    compute_level,
    direct_dep_names,
    doc_to_compliance_json,
    empty_index,
    find_index_blocker_keys_for_release,
    gap_keys,
    hydrate_seed_doc,
    index_add_parent,
    index_remove_key,
    node_key,
    normalize_direct_dependencies,
    normalize_doc,
    normalize_gap_list,
    normalize_index,
    parse_node_key,
    rebuild_index_from_docs,
    refresh_parent_doc,
    register_package_on_index,
    sidecar_to_doc,
    validate_gap_subset,
)


class TestNodeKey:
    """node_key / parse_node_key round-tripping."""

    def test_node_key_builds_name_at_version(self):
        """node_key joins name and version with a single '@'."""
        assert node_key("lodash", "4.17.21") == "lodash@4.17.21"

    def test_node_key_and_parse_round_trip_scoped_name(self):
        """A scoped name's own '@' must not confuse rsplit("@", 1)."""
        key = node_key("@scope/pkg", "1.0.0")
        assert key == "@scope/pkg@1.0.0"
        assert parse_node_key(key) == ("@scope/pkg", "1.0.0")

    def test_parse_node_key_unscoped(self):
        """Unscoped name/version round-trips too."""
        assert parse_node_key("lodash@4.17.21") == ("lodash", "4.17.21")


class TestComputeLevel:
    """compute_level sticky-gap precedence."""

    def test_compute_level_l1_l2_l3(self):
        """missing_gaps wins over pending_l3_gaps; empty of both is L3."""
        assert (
            compute_level(
                {"missing_gaps": ["a@1.0.0"], "pending_l3_gaps": ["b@1.0.0"]}
            )
            == "L1"
        )
        assert (
            compute_level({"missing_gaps": [], "pending_l3_gaps": ["b@1.0.0"]})
            == "L2"
        )
        assert compute_level({"missing_gaps": [], "pending_l3_gaps": []}) == "L3"


class TestNormalizeGapList:
    """normalize_gap_list accepts string lists or dict lists."""

    def test_normalize_gap_list_empty(self):
        """Falsy input normalizes to an empty list."""
        assert normalize_gap_list(None) == []
        assert normalize_gap_list([]) == []

    def test_normalize_gap_list_of_strings_sorted_deduped(self):
        """String list is sorted and deduplicated."""
        assert normalize_gap_list(["b@1.0.0", "a@1.0.0", "a@1.0.0"]) == [
            "a@1.0.0",
            "b@1.0.0",
        ]

    def test_normalize_gap_list_of_dicts(self):
        """Dict entries build node keys from name + version/requested."""
        value = [
            {"name": "b", "version": "2.0.0"},
            {"name": "a", "requested": "1.0.0"},
            {"name": "", "version": "9.9.9"},
        ]
        assert normalize_gap_list(value) == ["a@1.0.0", "b@2.0.0"]


class TestNormalizeDirectDependencies:
    """normalize_direct_dependencies filters to name+requested pairs."""

    def test_normalize_direct_dependencies_basic(self):
        """Keeps name + requested, falls back to 'version' key."""
        value = [
            {"name": "a", "requested": "^1.0.0"},
            {"name": "b", "version": "2.0.0"},
            {"name": "", "requested": "1.0.0"},
            {"name": "c"},
            "not-a-dict",
        ]
        assert normalize_direct_dependencies(value) == [
            {"name": "a", "requested": "^1.0.0"},
            {"name": "b", "requested": "2.0.0"},
        ]

    def test_normalize_direct_dependencies_empty(self):
        """Falsy input normalizes to an empty list."""
        assert normalize_direct_dependencies(None) == []


class TestNormalizeDoc:
    """normalize_doc migrates legacy shapes to the internal v3 schema."""

    def test_normalize_doc_migrates_legacy_closure_gaps_field(self):
        """v1 'closure_gaps' migrates into missing_gaps.

        Only when both v3 lists (missing_gaps/pending_l3_gaps) are absent.
        """
        legacy = {
            "name": "lodash",
            "version": "4.17.21",
            "closure_gaps": [{"name": "minimist", "version": "1.2.0"}],
        }
        doc = normalize_doc(legacy)
        assert doc["missing_gaps"] == ["minimist@1.2.0"]
        assert doc["pending_l3_gaps"] == []
        assert doc["compliance_level"] == "L1"

    def test_normalize_doc_does_not_migrate_when_v3_lists_present(self):
        """Legacy closure_gaps is ignored once v3 gap lists are present."""
        doc = normalize_doc(
            {
                "name": "lodash",
                "version": "4.17.21",
                "missing_gaps": ["a@1.0.0"],
                "closure_gaps": [{"name": "minimist", "version": "1.2.0"}],
            }
        )
        assert doc["missing_gaps"] == ["a@1.0.0"]

    def test_normalize_doc_defaults_schema_version_and_revision(self):
        """schema_version is always stamped; revision defaults to 1."""
        doc = normalize_doc({"name": "a", "version": "1.0.0"})
        assert doc["schema_version"] == SCHEMA_VERSION
        assert SCHEMA_VERSION == 3
        assert doc["compliance_revision"] == 1
        assert doc["compliance_level"] == "L3"

    def test_normalize_doc_preserves_existing_revision(self):
        """An existing compliance_revision is coerced to int, not reset."""
        doc = normalize_doc(
            {"name": "a", "version": "1.0.0", "compliance_revision": 4}
        )
        assert doc["compliance_revision"] == 4

    def test_normalize_doc_does_not_mutate_input(self):
        """normalize_doc deep-copies rather than mutating the caller's dict."""
        original = {"name": "a", "version": "1.0.0", "missing_gaps": ["a@1.0.0"]}
        normalize_doc(original)
        assert original == {
            "name": "a",
            "version": "1.0.0",
            "missing_gaps": ["a@1.0.0"],
        }


class TestGapKeysAndDeps:
    """gap_keys / direct_dep_names / validate_gap_subset."""

    def test_gap_keys_union_sorted(self):
        """gap_keys is the sorted union of both gap lists."""
        doc = {
            "missing_gaps": ["b@1.0.0"],
            "pending_l3_gaps": ["a@1.0.0", "b@1.0.0"],
        }
        assert gap_keys(doc) == ["a@1.0.0", "b@1.0.0"]

    def test_direct_dep_names(self):
        """direct_dep_names is the set of direct dependency names."""
        doc = {
            "direct_dependencies": [
                {"name": "a", "requested": "1.0.0"},
                {"name": "b", "requested": "2.0.0"},
            ]
        }
        assert direct_dep_names(doc) == {"a", "b"}

    def test_validate_gap_subset_passes_for_direct_dependency_gap(self):
        """No exception when every gap's package name is a direct dep."""
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "direct_dependencies": [{"name": "a", "requested": "1.0.0"}],
            "missing_gaps": ["a@1.0.0"],
            "pending_l3_gaps": [],
        }
        validate_gap_subset(doc)

    def test_validate_gap_subset_raises_for_non_direct_dependency_gap(self):
        """A gap whose package isn't a direct dependency is rejected.

        This is a real data-integrity check, not a decorative assertion.
        """
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "direct_dependencies": [{"name": "a", "requested": "1.0.0"}],
            "missing_gaps": ["rogue@1.0.0"],
            "pending_l3_gaps": [],
        }
        with pytest.raises(click.ClickException):
            validate_gap_subset(doc)


class TestRefreshParentDoc:
    """refresh_parent_doc mutates gap lists and recomputes level."""

    def test_refresh_parent_doc_moves_blocker_from_missing_to_pending_when_not_l3(
        self,
    ):
        """A blocker landing below L3 moves missing -> pending."""
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "missing_gaps": ["dep@1.0.0"],
            "pending_l3_gaps": [],
            "compliance_revision": 1,
        }
        updated = refresh_parent_doc(doc, "dep@1.0.0", "L2")
        assert updated["missing_gaps"] == []
        assert updated["pending_l3_gaps"] == ["dep@1.0.0"]
        assert updated["compliance_level"] == "L2"

    def test_refresh_parent_doc_removes_blocker_from_pending_when_l3(self):
        """A blocker reaching L3 is dropped from pending_l3_gaps entirely."""
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "missing_gaps": [],
            "pending_l3_gaps": ["dep@1.0.0"],
            "compliance_revision": 1,
        }
        updated = refresh_parent_doc(doc, "dep@1.0.0", "L3")
        assert updated["missing_gaps"] == []
        assert updated["pending_l3_gaps"] == []
        assert updated["compliance_level"] == "L3"

    def test_refresh_parent_doc_missing_to_l3_drops_entirely(self):
        """A blocker landing at L3 from missing_gaps is dropped entirely.

        Not parked in pending_l3_gaps first, since L3 is terminal.
        """
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "missing_gaps": ["dep@1.0.0"],
            "pending_l3_gaps": [],
            "compliance_revision": 1,
        }
        updated = refresh_parent_doc(doc, "dep@1.0.0", "L3")
        assert updated["missing_gaps"] == []
        assert updated["pending_l3_gaps"] == []
        assert updated["compliance_level"] == "L3"

    def test_refresh_parent_doc_bumps_revision_and_timestamp(self):
        """Revision and timestamp are bumped on every refresh.

        compliance_revision increments by one; closure_updated_at is stamped.
        """
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "missing_gaps": ["dep@1.0.0"],
            "pending_l3_gaps": [],
            "compliance_revision": 3,
            "closure_updated_at": None,
        }
        updated = refresh_parent_doc(doc, "dep@1.0.0", "L2")
        assert updated["compliance_revision"] == 4
        assert updated["closure_updated_at"]
        assert updated["closure_updated_at"].endswith("Z")

    def test_refresh_parent_doc_does_not_mutate_direct_dependencies(self):
        """direct_dependencies is carried through unchanged."""
        deps = [{"name": "dep", "requested": "1.0.0"}]
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "direct_dependencies": deps,
            "missing_gaps": ["dep@1.0.0"],
            "pending_l3_gaps": [],
            "compliance_revision": 1,
        }
        updated = refresh_parent_doc(doc, "dep@1.0.0", "L3")
        assert updated["direct_dependencies"] == deps


class TestDocToComplianceJson:
    """doc_to_compliance_json builds the external JSON shape."""

    def test_doc_to_compliance_json_uses_passed_compliance_oci(self):
        """compliance_oci comes from the caller, never computed internally."""
        doc = normalize_doc(
            {
                "name": "lodash",
                "version": "4.17.21",
                "direct_dependencies": [],
                "missing_gaps": [],
                "pending_l3_gaps": [],
            }
        )
        out = doc_to_compliance_json(
            doc,
            registry_url="https://registry.example/javascript",
            compliance_oci="quay.io/example/npm-compliance:lodash-4.17.21",
        )
        assert out["compliance_oci"] == (
            "quay.io/example/npm-compliance:lodash-4.17.21"
        )
        assert out["registry"] == "https://registry.example/javascript"
        assert out["schema_version"] == SCHEMA_VERSION
        assert out["name"] == "lodash"
        assert out["version"] == "4.17.21"

    def test_doc_to_compliance_json_doc_registry_overrides_param(self):
        """An explicit doc['registry'] wins over the passed registry_url."""
        doc = normalize_doc(
            {
                "name": "a",
                "version": "1.0.0",
                "registry": "https://custom.example/registry",
            }
        )
        out = doc_to_compliance_json(
            doc,
            registry_url="https://default.example/registry",
            compliance_oci="oci:tag",
        )
        assert out["registry"] == "https://custom.example/registry"

    def test_doc_to_compliance_json_includes_optional_fields_when_present(self):
        """tarball/tarball_sha256/built_from are included only when set."""
        doc = normalize_doc(
            {
                "name": "a",
                "version": "1.0.0",
                "tarball_sha256": "deadbeef",
                "tarball": "a-1.0.0.tgz",
                "built_from": "upstream-commit",
            }
        )
        out = doc_to_compliance_json(
            doc, registry_url="https://r.example", compliance_oci="oci:tag"
        )
        assert out["tarball_sha256"] == "deadbeef"
        assert out["tarball"] == "a-1.0.0.tgz"
        assert out["built_from"] == "upstream-commit"

    def test_doc_to_compliance_json_omits_optional_fields_when_absent(self):
        """Optional fields are left out entirely, not set to None/empty."""
        doc = normalize_doc({"name": "a", "version": "1.0.0"})
        out = doc_to_compliance_json(
            doc, registry_url="https://r.example", compliance_oci="oci:tag"
        )
        assert "tarball_sha256" not in out
        assert "tarball" not in out
        assert "built_from" not in out


class TestSidecarToDoc:
    """sidecar_to_doc normalizes + validates an already-parsed sidecar dict."""

    def test_sidecar_to_doc_normalizes_and_sets_pulp_href(self):
        """Valid sidecar normalizes and records the given pulp_href."""
        sidecar = {
            "name": "pkg",
            "version": "1.0.0",
            "direct_dependencies": [{"name": "dep", "requested": "1.0.0"}],
            "missing_gaps": ["dep@1.0.0"],
        }
        doc = sidecar_to_doc(sidecar, pulp_href="/api/pulp/.../content/abc/")
        assert doc["name"] == "pkg"
        assert doc["pulp_href"] == "/api/pulp/.../content/abc/"

    def test_sidecar_to_doc_raises_on_missing_name_version(self):
        """Missing name or version is a hard error."""
        with pytest.raises(click.ClickException):
            sidecar_to_doc({"version": "1.0.0"})
        with pytest.raises(click.ClickException):
            sidecar_to_doc({"name": "pkg"})

    def test_sidecar_to_doc_raises_on_gap_not_in_direct_dependencies(self):
        """A gap outside direct_dependencies fails validate_gap_subset."""
        sidecar = {
            "name": "pkg",
            "version": "1.0.0",
            "direct_dependencies": [{"name": "dep", "requested": "1.0.0"}],
            "missing_gaps": ["rogue@1.0.0"],
        }
        with pytest.raises(click.ClickException):
            sidecar_to_doc(sidecar)

    def test_sidecar_to_doc_does_not_mutate_input(self):
        """The caller's sidecar dict is not mutated in place."""
        sidecar = {"name": "pkg", "version": "1.0.0"}
        sidecar_to_doc(sidecar, pulp_href="/href/")
        assert sidecar == {"name": "pkg", "version": "1.0.0"}


class TestIndex:
    """empty_index / normalize_index / index mutation helpers."""

    def test_empty_index_shape(self):
        """A fresh index has schema_version 1, revision 0, no entries."""
        index = empty_index()
        assert index["schema_version"] == 1
        assert index["revision"] == 0
        assert index["entries"] == {}

    def test_empty_index_and_normalize_index_drop_entries_with_no_parents(self):
        """normalize_index(None) equals empty_index().

        Entries with empty/absent parents are dropped on normalization.
        """
        assert normalize_index(None)["entries"] == {}
        raw = {
            "revision": 2,
            "entries": {
                "a@1.0.0": {"parents": ["p@1.0.0"]},
                "b@1.0.0": {"parents": []},
                "c@1.0.0": {},
            },
        }
        normalized = normalize_index(raw)
        assert normalized["entries"] == {"a@1.0.0": {"parents": ["p@1.0.0"]}}
        assert normalized["revision"] == 2

    def test_index_add_parent_dedupes_and_sorts(self):
        """index_add_parent accumulates a sorted, deduplicated parent set."""
        index = empty_index()
        index_add_parent(index, "dep@1.0.0", "b@1.0.0")
        index_add_parent(index, "dep@1.0.0", "a@1.0.0")
        index_add_parent(index, "dep@1.0.0", "a@1.0.0")
        assert index["entries"]["dep@1.0.0"]["parents"] == [
            "a@1.0.0",
            "b@1.0.0",
        ]

    def test_index_remove_key(self):
        """index_remove_key is a no-op-safe pop."""
        index = empty_index()
        index_add_parent(index, "dep@1.0.0", "p@1.0.0")
        index_remove_key(index, "dep@1.0.0")
        assert "dep@1.0.0" not in index["entries"]
        index_remove_key(index, "not-there@1.0.0")  # does not raise

    def test_rebuild_index_from_docs_matches_manual_construction(self):
        """rebuild_index_from_docs equals manually adding each doc's gaps."""
        docs_by_key = {
            "p@1.0.0": {
                "missing_gaps": ["dep@1.0.0"],
                "pending_l3_gaps": ["dep2@1.0.0"],
            },
            "q@1.0.0": {
                "missing_gaps": ["dep@1.0.0"],
                "pending_l3_gaps": [],
            },
        }
        rebuilt = rebuild_index_from_docs(docs_by_key)

        manual = empty_index()
        index_add_parent(manual, "dep@1.0.0", "p@1.0.0")
        index_add_parent(manual, "dep2@1.0.0", "p@1.0.0")
        index_add_parent(manual, "dep@1.0.0", "q@1.0.0")

        assert rebuilt["entries"] == manual["entries"]


class TestFindIndexBlockerKeysForRelease:
    """find_index_blocker_keys_for_release matches exact and range specs."""

    def test_find_index_blocker_keys_matches_exact_and_satisfying_spec(self):
        """Exact-string and satisfying-semver-range blockers both match.

        A mismatched name or a non-satisfying spec does not match.
        """
        index = empty_index()
        index_add_parent(index, "dep@1.0.0", "exact-parent@1.0.0")
        index_add_parent(index, "dep@^1.0.0", "range-parent@1.0.0")
        index_add_parent(index, "dep@^2.0.0", "nonmatching-parent@1.0.0")
        index_add_parent(index, "other@1.0.0", "other-parent@1.0.0")

        matched = find_index_blocker_keys_for_release(index, "dep", "1.0.0")

        assert matched == ["dep@1.0.0", "dep@^1.0.0"]

    def test_find_index_blocker_keys_for_release_no_match(self):
        """No blockers for an unrelated package name return an empty list."""
        index = empty_index()
        index_add_parent(index, "dep@1.0.0", "p@1.0.0")
        assert (
            find_index_blocker_keys_for_release(index, "unrelated", "1.0.0") == []
        )


class TestApplyIndexRelease:
    """apply_index_release clears blockers only when landing at L3."""

    def test_apply_index_release_clears_blockers_only_at_l3(self):
        """L3 release clears satisfied blocker entries and its own key.

        A non-L3 release leaves existing blocker entries untouched (see
        the sibling test below).
        """
        index = empty_index()
        index_add_parent(index, "dep@1.0.0", "waiter@1.0.0")
        index_add_parent(index, "dep@1.0.0", "dep-waiter@1.0.0")

        release_doc = {
            "missing_gaps": [],
            "pending_l3_gaps": ["other@1.0.0"],
        }
        updated = apply_index_release(index, "dep@1.0.0", release_doc, "L3")
        assert "dep@1.0.0" not in updated["entries"]
        assert updated["entries"]["other@1.0.0"]["parents"] == ["dep@1.0.0"]

    def test_apply_index_release_non_l3_keeps_existing_blocker_entries(self):
        """A non-L3 release does not clear any existing blocker entries."""
        index = empty_index()
        index_add_parent(index, "dep@1.0.0", "waiter@1.0.0")

        release_doc = {"missing_gaps": [], "pending_l3_gaps": []}
        updated = apply_index_release(index, "dep@1.0.0", release_doc, "L2")
        assert updated["entries"]["dep@1.0.0"]["parents"] == ["waiter@1.0.0"]

    def test_register_package_on_index_adds_parent_for_each_gap(self):
        """The package is indexed as a parent of every one of its gaps."""
        index = empty_index()
        doc = {
            "missing_gaps": ["dep@1.0.0"],
            "pending_l3_gaps": ["dep2@1.0.0"],
        }
        register_package_on_index(index, "pkg@1.0.0", doc)
        assert index["entries"]["dep@1.0.0"]["parents"] == ["pkg@1.0.0"]
        assert index["entries"]["dep2@1.0.0"]["parents"] == ["pkg@1.0.0"]


class TestHydrateSeedDoc:
    """hydrate_seed_doc builds a normalized doc from a Pulp content row."""

    def test_hydrate_seed_doc_defaults_to_l3_without_label(self):
        """No compliance level label defaults the seed doc to L3."""
        row = {"name": "pkg", "version": "1.0.0", "pulp_href": "/href/"}
        doc = hydrate_seed_doc(row)
        assert doc["name"] == "pkg"
        assert doc["version"] == "1.0.0"
        assert doc["pulp_href"] == "/href/"
        assert doc["compliance_level"] == "L3"
        assert doc["missing_gaps"] == []
        assert doc["pending_l3_gaps"] == []
        assert doc["schema_version"] == SCHEMA_VERSION

    def test_hydrate_seed_doc_uses_existing_label(self):
        """An existing compliance-level Pulp label is carried through."""
        row = {
            "name": "pkg",
            "version": "1.0.0",
            "pulp_labels": {"tl.compliance_level": "L1"},
        }
        doc = hydrate_seed_doc(row)
        assert doc["compliance_level"] == "L1"


class TestComplianceNamingHelpers:
    """compliance_oci_tag / compliance_filename pure naming helpers."""

    def test_compliance_oci_tag_unscoped_name(self):
        """Unscoped name builds 'name-version'."""
        assert compliance_oci_tag("lodash", "4.17.21") == "lodash-4.17.21"

    def test_compliance_oci_tag_scoped_name(self):
        """Scoped name strips the leading '@' and replaces '/' with '-'.

        This is a different sanitization than attestation_oci_tag's
        regex-based one — no "--" separator, no "-att" suffix, no
        character-class sanitization or length cap.
        """
        assert compliance_oci_tag("@scope/pkg", "1.0.0") == "scope-pkg-1.0.0"

    def test_compliance_filename_matches_tag_convention(self):
        """compliance_filename appends '.tl-compliance.json' to the tag."""
        assert (
            compliance_filename("@scope/pkg", "1.0.0")
            == "scope-pkg-1.0.0.tl-compliance.json"
        )
        assert (
            compliance_filename("lodash", "4.17.21")
            == "lodash-4.17.21.tl-compliance.json"
        )
