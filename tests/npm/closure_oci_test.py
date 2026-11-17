"""Tests for npm closure compliance-document / index OCI artifact I/O."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from slan_cuan import oci
from slan_cuan.npm import closure_model
from slan_cuan.npm.closure_oci import (
    cas_publish_compliance,
    cas_push_index,
    closure_index_image_ref,
    compliance_image_ref,
    publish_compliance_doc,
    publish_index,
    pull_compliance_doc,
    pull_index,
    pull_json_artifact,
    push_json_artifact,
)

PREFIX = "quay.io/org/tl-compliance:latest"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


class TestComplianceImageRef:
    """compliance_image_ref -- tag/digest stripping on the prefix."""

    def test_compliance_image_ref_strips_tag_and_digest_from_prefix(self):
        """A trailing :tag or @digest on the prefix is stripped first."""
        assert (
            compliance_image_ref("lodash", "4.17.21", "quay.io/org/repo:latest")
            == "quay.io/org/repo:lodash-4.17.21"
        )
        assert (
            compliance_image_ref("chalk", "5.0.0", "quay.io/org/repo@" + "f" * 64)
            == "quay.io/org/repo:chalk-5.0.0"
        )
        assert (
            compliance_image_ref("express", "4.0.0", "quay.io/org/repo")
            == "quay.io/org/repo:express-4.0.0"
        )

    def test_compliance_image_ref_sanitizes_scoped_name(self):
        """A scoped package name uses compliance_oci_tag's collision-free tag."""
        assert compliance_image_ref(
            "@scope/pkg", "1.0.0", "quay.io/org/repo:latest"
        ) == "quay.io/org/repo:" + closure_model.compliance_oci_tag(
            "@scope/pkg", "1.0.0"
        )
        assert compliance_image_ref(
            "@scope/pkg", "1.0.0", "quay.io/org/repo"
        ) != compliance_image_ref("scope-pkg", "1.0.0", "quay.io/org/repo")


class TestClosureIndexImageRef:
    """closure_index_image_ref -- explicit override vs. derived default."""

    def test_closure_index_image_ref_uses_explicit_override_when_set(self):
        """An explicit closure_index_image wins, returned verbatim."""
        assert (
            closure_index_image_ref(PREFIX, "quay.io/org/other-index:v2")
            == "quay.io/org/other-index:v2"
        )

    def test_closure_index_image_ref_defaults_from_prefix(self):
        """With no override, the index ref is derived from the prefix."""
        assert (
            closure_index_image_ref("quay.io/org/repo:latest")
            == "quay.io/org/repo/npm-closure-index:latest"
        )


class TestPullJsonArtifact:
    """pull_json_artifact -- pull, find-by-suffix, parse, resolve digest."""

    @pytest.mark.parametrize(
        ("message", "stderr"),
        [
            (f"Image not found: {PREFIX}", "Error: 404 Not Found"),
            (
                f"Image not found: {PREFIX}",
                "Error: GET ...: MANIFEST_UNKNOWN: manifest unknown",
            ),
            (
                "oras pull failed: NAME_UNKNOWN",
                "Error: NAME_UNKNOWN: repository name not known to registry",
            ),
        ],
    )
    def test_pull_json_artifact_returns_none_when_image_not_found(
        self, message, stderr
    ):
        """A not-found oci.pull (image not seeded yet) yields (None, None)."""
        with patch(
            "slan_cuan.npm.closure_oci.oci.pull",
            side_effect=oci.OrasError(message, stderr, 1),
        ):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)

    #: Verbatim stderr from real ``oras pull`` (oras 1.3.0) against Quay
    #: for a tag that does not exist. None of the 404/MANIFEST_UNKNOWN
    #: markers appear in it, so ``oci.pull`` falls through to its
    #: generic "oras pull failed: ..." message.
    REAL_ORAS_MISSING_TAG_STDERR = (
        "Error response from registry: "
        "quay.io/prometheus/busybox:lwlp4134-nonexistent-tag: not found"
    )

    def test_pull_json_artifact_returns_none_for_real_oras_not_found(self):
        """Real oras 1.3.0 missing-tag output yields (None, None)."""
        stderr = self.REAL_ORAS_MISSING_TAG_STDERR
        with patch(
            "slan_cuan.npm.closure_oci.oci.pull",
            side_effect=oci.OrasError(f"oras pull failed: {stderr}", stderr, 1),
        ):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)

    def test_pull_json_artifact_not_found_beats_network_keyword_in_ref(self):
        """A ref containing "timeout"/"connection" is still not-found.

        ``oci.pull`` checks for "network"/"connection"/"timeout" anywhere
        in stderr, and the image ref (which embeds the npm package name,
        e.g. ``timeout-signal``) is echoed in oras's not-found message --
        so a never-seeded package with such a name gets mislabelled
        "Network error". The trailing ``: not found`` must still win.
        """
        stderr = (
            "Error response from registry: "
            "quay.io/org/repo:timeout-signal-2.0.0: not found"
        )
        with patch(
            "slan_cuan.npm.closure_oci.oci.pull",
            side_effect=oci.OrasError(
                f"Network error pulling {PREFIX}", stderr, 1
            ),
        ):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)

    @pytest.mark.parametrize(
        ("message", "stderr"),
        [
            (
                f"Authentication failed for {PREFIX}",
                "Error: 401 Unauthorized",
            ),
            (
                f"Network error pulling {PREFIX}",
                "Error: dial tcp: connection refused",
            ),
            ("oras pull failed: boom", "boom"),
            # "not found" mid-string, not as the trailing ": not found"
            # oras emits for a missing tag/repo -- must stay a hard error.
            (
                "oras pull failed: resource not found: access denied",
                "Error: resource not found: access denied",
            ),
            (
                "oras pull failed: credential helper not found in PATH",
                "Error: credential helper not found in PATH",
            ),
        ],
    )
    def test_pull_json_artifact_raises_on_non_not_found_errors(
        self, message, stderr
    ):
        """Auth/network/unclassified failures raise, never "not seeded"."""
        with (
            patch(
                "slan_cuan.npm.closure_oci.oci.pull",
                side_effect=oci.OrasError(message, stderr, 1),
            ),
            pytest.raises(click.ClickException, match="Failed to pull"),
        ):
            pull_json_artifact(PREFIX, ".tl-compliance.json")

    def test_cas_push_index_does_not_push_after_transient_pull_error(self):
        """A network blip pulling the index must not push an empty index."""
        with (
            patch(
                "slan_cuan.npm.closure_oci.oci.pull",
                side_effect=oci.OrasError(
                    f"Network error pulling {PREFIX}", "timeout", 1
                ),
            ),
            patch("slan_cuan.npm.closure_oci.oci.push") as mock_push,
            pytest.raises(click.ClickException),
        ):
            cas_push_index(lambda idx: idx, compliance_image_prefix=PREFIX)
        mock_push.assert_not_called()

    def test_pull_json_artifact_finds_matching_suffix_file_and_parses_json(
        self,
    ):
        """The one file ending in filename_suffix is parsed as JSON."""
        payload = {"name": "lodash", "version": "4.17.21"}

        def _fake_pull(image, output_dir, auth_file=None, verbose=False):
            (Path(output_dir) / "other-file.txt").write_text("noise")
            (Path(output_dir) / "lodash-4.17.21.tl-compliance.json").write_text(
                json.dumps(payload)
            )

        fake_resolve = Mock(
            returncode=0,
            stdout=f"quay.io/org/repo@{DIGEST}\n",
            stderr="",
        )
        with (
            patch(
                "slan_cuan.npm.closure_oci.oci.pull", side_effect=_fake_pull
            ) as mock_pull,
            patch(
                "slan_cuan.npm.closure_oci.subprocess.run",
                return_value=fake_resolve,
            ) as mock_run,
        ):
            data, digest = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert data == payload
        assert digest == DIGEST
        mock_pull.assert_called_once()
        mock_run.assert_called_once_with(
            ["oras", "resolve", PREFIX],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_pull_json_artifact_returns_none_when_no_suffix_match(self):
        """A pull that succeeds but has no matching file yields (None, None)."""

        def _fake_pull(image, output_dir, auth_file=None, verbose=False):
            (Path(output_dir) / "unrelated.json").write_text("{}")

        with patch("slan_cuan.npm.closure_oci.oci.pull", side_effect=_fake_pull):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)


class TestPullComplianceDoc:
    """pull_compliance_doc -- pull_json_artifact + normalize_doc."""

    def test_pull_compliance_doc_normalizes_result(self):
        """A pulled raw doc is run through normalize_doc, href fallback set."""
        raw = {
            "name": "lodash",
            "version": "4.17.21",
            "missing_gaps": ["a@1.0.0", "a@1.0.0"],
        }
        with patch(
            "slan_cuan.npm.closure_oci.pull_json_artifact",
            return_value=(raw, DIGEST),
        ):
            doc, digest = pull_compliance_doc(
                "lodash", "4.17.21", PREFIX, pulp_href_fallback="/fallback/"
            )
        assert digest == DIGEST
        assert doc["missing_gaps"] == ["a@1.0.0"]
        assert doc["pulp_href"] == "/fallback/"
        assert doc["schema_version"] == closure_model.SCHEMA_VERSION

    def test_pull_compliance_doc_returns_none_when_not_found(self):
        """No artifact yet -> (None, None), no normalization attempted."""
        with patch(
            "slan_cuan.npm.closure_oci.pull_json_artifact",
            return_value=(None, None),
        ):
            result = pull_compliance_doc("lodash", "4.17.21", PREFIX)
        assert result == (None, None)


class TestPullIndex:
    """pull_index -- pull_json_artifact + normalize_index, empty default."""

    def test_pull_index_defaults_to_empty_index_when_not_found(self):
        """No index artifact yet -> empty_index(), digest None."""
        with patch(
            "slan_cuan.npm.closure_oci.pull_json_artifact",
            return_value=(None, None),
        ):
            index, digest = pull_index(PREFIX)
        assert digest is None
        assert index == closure_model.empty_index()

    def test_pull_index_normalizes_found_result(self):
        """A found raw index is run through normalize_index."""
        raw = {"revision": 3, "entries": {"a@1.0.0": {"parents": ["b@2.0.0"]}}}
        with patch(
            "slan_cuan.npm.closure_oci.pull_json_artifact",
            return_value=(raw, DIGEST),
        ):
            index, digest = pull_index(PREFIX)
        assert digest == DIGEST
        assert index["revision"] == 3
        assert index["entries"] == {"a@1.0.0": {"parents": ["b@2.0.0"]}}


class TestPushJsonArtifact:
    """push_json_artifact -- temp file write + oci.push with title annotation."""

    def test_push_json_artifact_writes_temp_file_and_calls_oci_push(self):
        """The payload is written to a temp file named filename, then pushed.

        Reads the written file's contents inside oci.push's side_effect,
        not after push_json_artifact returns -- the temp directory is
        cleaned up on return, so the file no longer exists by then.
        """
        payload = {"b": 2, "a": 1}
        captured = {}

        def _fake_push(path, target_ref, **kwargs):
            captured["name"] = path.name
            captured["contents"] = json.loads(path.read_text())
            captured["target_ref"] = target_ref
            captured["kwargs"] = kwargs
            return DIGEST

        with patch(
            "slan_cuan.npm.closure_oci.oci.push", side_effect=_fake_push
        ) as mock_push:
            digest = push_json_artifact(
                PREFIX,
                "lodash-4.17.21.tl-compliance.json",
                payload,
                artifact_type="application/vnd.npm.tl-compliance+json",
            )
        assert digest == DIGEST
        mock_push.assert_called_once()
        assert captured["name"] == "lodash-4.17.21.tl-compliance.json"
        assert captured["contents"] == payload
        assert captured["target_ref"] == PREFIX
        assert captured["kwargs"]["artifact_type"] == (
            "application/vnd.npm.tl-compliance+json"
        )
        assert captured["kwargs"]["annotations"] == {
            "org.opencontainers.image.title": "npm-closure-artifact"
        }


class TestPublishComplianceDoc:
    """publish_compliance_doc -- push + href resolution + Pulp label sync."""

    def test_publish_compliance_doc_calls_sync_when_pulp_href_known(self):
        """When doc already has a pulp_href, it's used without a repo lookup."""
        client = Mock()
        doc = {
            "name": "lodash",
            "version": "4.17.21",
            "pulp_href": "/content/abc/",
            "compliance_level": "L2",
        }
        repo = {"latest_version_href": "/repo/versions/9/"}
        with (
            patch(
                "slan_cuan.npm.closure_oci.push_json_artifact",
                return_value=DIGEST,
            ),
            patch(
                "slan_cuan.npm.closure_oci.closure_pulp.find_content_in_repo"
            ) as mock_find,
            patch(
                "slan_cuan.npm.closure_oci.closure_pulp.sync_content_pulp_labels"
            ) as mock_sync,
        ):
            digest = publish_compliance_doc(
                client,
                doc,
                repo,
                compliance_image_prefix=PREFIX,
                registry_url="https://registry.npmjs.org",
            )
        assert digest == DIGEST
        mock_find.assert_not_called()
        mock_sync.assert_called_once_with(
            client,
            "/content/abc/",
            "/repo/versions/9/",
            "lodash",
            "4.17.21",
            "L2",
            DIGEST,
        )

    def test_publish_compliance_doc_falls_back_to_repo_lookup(self):
        """No pulp_href yet -> find_content_in_repo resolves it, stamps doc."""
        client = Mock()
        doc = {
            "name": "lodash",
            "version": "4.17.21",
            "compliance_level": "L1",
        }
        repo = {"latest_version_href": "/repo/versions/9/"}
        with (
            patch(
                "slan_cuan.npm.closure_oci.push_json_artifact",
                return_value=DIGEST,
            ),
            patch(
                "slan_cuan.npm.closure_oci.closure_pulp.find_content_in_repo",
                return_value={"pulp_href": "/content/found/"},
            ) as mock_find,
            patch(
                "slan_cuan.npm.closure_oci.closure_pulp.sync_content_pulp_labels"
            ) as mock_sync,
        ):
            publish_compliance_doc(
                client,
                doc,
                repo,
                compliance_image_prefix=PREFIX,
                registry_url="https://registry.npmjs.org",
            )
        mock_find.assert_called_once_with(
            client, "lodash", "4.17.21", "/repo/versions/9/"
        )
        assert doc["pulp_href"] == "/content/found/"
        mock_sync.assert_called_once_with(
            client,
            "/content/found/",
            "/repo/versions/9/",
            "lodash",
            "4.17.21",
            "L1",
            DIGEST,
        )


class TestPublishIndex:
    """publish_index -- normalize, revision bump, push."""

    def test_publish_index_bumps_revision_and_pushes(self):
        """Revision increments by one; expected_revision mismatch is forced."""
        index = {"revision": 5, "entries": {}}
        with patch(
            "slan_cuan.npm.closure_oci.push_json_artifact",
            return_value=DIGEST,
        ) as mock_push:
            pushed, digest = publish_index(
                index,
                compliance_image_prefix=PREFIX,
                expected_revision=2,
            )
        assert digest == DIGEST
        assert pushed["revision"] == 3
        mock_push.assert_called_once()
        _args, kwargs = mock_push.call_args
        assert kwargs["artifact_type"] == (
            "application/vnd.npm.closure-index+json"
        )


class TestCasPushIndex:
    """cas_push_index -- pull/mutate/push loop with OrasError retry."""

    def test_cas_push_index_retries_on_revision_conflict(self):
        """A failed push round is retried; the next round's push wins."""
        pulled = ({"revision": 0, "entries": {}}, None)
        success = ({"revision": 1, "entries": {}}, DIGEST)
        with (
            patch(
                "slan_cuan.npm.closure_oci.pull_index",
                return_value=pulled,
            ) as mock_pull_index,
            patch(
                "slan_cuan.npm.closure_oci.publish_index",
                side_effect=[
                    oci.OrasError("conflict", "stderr", 1),
                    success,
                ],
            ) as mock_publish_index,
            patch("slan_cuan.npm.closure_oci.time.sleep"),
        ):
            result = cas_push_index(
                lambda idx: idx,
                compliance_image_prefix=PREFIX,
                max_retries=5,
            )
        assert result == success
        assert mock_pull_index.call_count == 2
        assert mock_publish_index.call_count == 2

    def test_cas_push_index_raises_after_max_retries(self):
        """Persistent push failure raises click.ClickException, not OrasError."""
        pulled = ({"revision": 0, "entries": {}}, None)
        with (
            patch("slan_cuan.npm.closure_oci.pull_index", return_value=pulled),
            patch(
                "slan_cuan.npm.closure_oci.publish_index",
                side_effect=oci.OrasError("conflict", "stderr", 1),
            ) as mock_publish_index,
            patch("slan_cuan.npm.closure_oci.time.sleep") as mock_sleep,
            pytest.raises(click.ClickException, match="Index CAS failed"),
        ):
            cas_push_index(
                lambda idx: idx,
                compliance_image_prefix=PREFIX,
                max_retries=3,
            )
        assert mock_publish_index.call_count == 3
        assert mock_sleep.call_count == 2


class TestCasPublishCompliance:
    """cas_publish_compliance -- revision bump past existing + verify loop."""

    def test_cas_publish_compliance_bumps_revision_past_existing(self):
        """Doc's compliance_revision is bumped to existing + 1, then verified."""
        client = Mock()
        repo = {"latest_version_href": "/repo/versions/9/"}
        doc = {
            "name": "pkg",
            "version": "1.0.0",
            "compliance_revision": 1,
        }
        existing = {"compliance_revision": 5, "direct_dependencies": []}
        verify = {"compliance_revision": 6}
        with (
            patch(
                "slan_cuan.npm.closure_oci.pull_compliance_doc",
                side_effect=[(existing, OTHER_DIGEST), (verify, DIGEST)],
            ) as mock_pull_doc,
            patch(
                "slan_cuan.npm.closure_oci.publish_compliance_doc",
                return_value=DIGEST,
            ) as mock_publish_doc,
            patch("slan_cuan.npm.closure_oci.time.sleep"),
        ):
            digest = cas_publish_compliance(
                client,
                doc,
                repo,
                compliance_image_prefix=PREFIX,
                registry_url="https://registry.npmjs.org",
            )
        assert digest == DIGEST
        assert doc["compliance_revision"] == 6
        assert mock_pull_doc.call_count == 2
        mock_publish_doc.assert_called_once()

    def test_cas_publish_compliance_raises_after_max_retries(self):
        """A verify that never catches up raises click.ClickException."""
        client = Mock()
        repo = {"latest_version_href": "/repo/versions/9/"}
        doc = {"name": "pkg", "version": "1.0.0", "compliance_revision": 1}
        with (
            patch(
                "slan_cuan.npm.closure_oci.pull_compliance_doc",
                return_value=(None, None),
            ),
            patch(
                "slan_cuan.npm.closure_oci.publish_compliance_doc",
                return_value=DIGEST,
            ),
            patch("slan_cuan.npm.closure_oci.time.sleep"),
            pytest.raises(click.ClickException, match="Compliance CAS failed"),
        ):
            cas_publish_compliance(
                client,
                doc,
                repo,
                compliance_image_prefix=PREFIX,
                registry_url="https://registry.npmjs.org",
                max_retries=2,
            )


class TestCasDefaultMaxRetries:
    """Both OCI CAS loops default to closure_pulp.DEFAULT_CAS_MAX_RETRIES."""

    def test_cas_push_index_default_retries_follow_closure_pulp(self):
        """Patching the shared constant changes cas_push_index's default."""
        pulled = ({"revision": 0, "entries": {}}, None)
        with (
            patch("slan_cuan.npm.closure_pulp.DEFAULT_CAS_MAX_RETRIES", 4),
            patch("slan_cuan.npm.closure_oci.pull_index", return_value=pulled),
            patch(
                "slan_cuan.npm.closure_oci.publish_index",
                side_effect=oci.OrasError("conflict", "stderr", 1),
            ) as mock_publish_index,
            patch("slan_cuan.npm.closure_oci.time.sleep"),
            pytest.raises(click.ClickException, match="after 4 retries"),
        ):
            cas_push_index(lambda idx: idx, compliance_image_prefix=PREFIX)
        assert mock_publish_index.call_count == 4

    def test_cas_publish_compliance_default_retries_follow_closure_pulp(self):
        """Patching the shared constant changes cas_publish_compliance's too."""
        doc = {"name": "pkg", "version": "1.0.0", "compliance_revision": 1}
        with (
            patch("slan_cuan.npm.closure_pulp.DEFAULT_CAS_MAX_RETRIES", 3),
            patch(
                "slan_cuan.npm.closure_oci.pull_compliance_doc",
                return_value=(None, None),
            ),
            patch(
                "slan_cuan.npm.closure_oci.publish_compliance_doc",
                return_value=DIGEST,
            ) as mock_publish_doc,
            patch("slan_cuan.npm.closure_oci.time.sleep"),
            pytest.raises(click.ClickException, match="Compliance CAS failed"),
        ):
            cas_publish_compliance(
                Mock(),
                doc,
                {"latest_version_href": "/repo/versions/9/"},
                compliance_image_prefix=PREFIX,
                registry_url="https://registry.npmjs.org",
            )
        assert mock_publish_doc.call_count == 3

    def test_explicit_max_retries_overrides_shared_default(self):
        """A per-call max_retries still wins over the shared default."""
        pulled = ({"revision": 0, "entries": {}}, None)
        with (
            patch("slan_cuan.npm.closure_pulp.DEFAULT_CAS_MAX_RETRIES", 7),
            patch("slan_cuan.npm.closure_oci.pull_index", return_value=pulled),
            patch(
                "slan_cuan.npm.closure_oci.publish_index",
                side_effect=oci.OrasError("conflict", "stderr", 1),
            ) as mock_publish_index,
            patch("slan_cuan.npm.closure_oci.time.sleep"),
            pytest.raises(click.ClickException),
        ):
            cas_push_index(
                lambda idx: idx, compliance_image_prefix=PREFIX, max_retries=2
            )
        assert mock_publish_index.call_count == 2
