"""Tests for npm closure compliance-document / index OCI artifact I/O."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from slan_cuan import oci
from slan_cuan.javascript import closure_model
from slan_cuan.javascript.closure_oci import (
    cas_publish_compliance,
    cas_push_index,
    closure_index_image_ref,
    compliance_image_ref,
    legacy_compliance_image_ref,
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
    """pull_json_artifact -- resolve digest first, pull pinned, find+parse."""

    @staticmethod
    def _resolve_ok(digest: str = DIGEST):
        """Patch ``_resolve_oras_digest`` to succeed, for pull-path tests.

        Decouples the pull-path tests below (which exercise the PULL
        call's not-found/hard-error classification) from the resolve
        step, which always runs first now -- see
        ``TestResolveThenPull``/``TestPullJsonArtifactResolveNotFound``
        for tests of the resolve step itself.
        """
        return patch(
            "slan_cuan.javascript.closure_oci._resolve_oras_digest",
            return_value=digest,
        )

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
        """A not-found oci.pull (image not seeded yet) yields (None, None).

        Resolve succeeds (so the pull step, pinned to that digest, is
        actually reached) and then the pull itself fails not-found.
        """
        with (
            self._resolve_ok(),
            patch(
                "slan_cuan.javascript.closure_oci.oci.pull",
                side_effect=oci.OrasError(message, stderr, 1),
            ),
        ):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)

    #: Verbatim stderr from real ``oras pull``/``oras resolve`` (oras 1.3.0)
    #: against Quay for a tag that does not exist -- no 404/MANIFEST_UNKNOWN
    #: markers.
    REAL_ORAS_MISSING_TAG_STDERR = (
        "Error response from registry: "
        "quay.io/prometheus/busybox:lwlp4134-nonexistent-tag: not found"
    )

    @staticmethod
    def _oras_fails(stderr: str):
        """Patch the subprocess under the REAL ``oci.pull`` to fail.

        Exercises ``oci.pull``'s own stderr classification end to end,
        rather than hand-picking the ``OrasError.message`` it would produce.
        Combine with ``_resolve_ok`` so the (separately tested) resolve
        step doesn't also hit this same patched subprocess.
        """
        return patch(
            "slan_cuan.oci.subprocess.run",
            return_value=Mock(returncode=1, stderr=stderr, stdout=""),
        )

    @pytest.mark.parametrize(
        "stderr",
        [
            REAL_ORAS_MISSING_TAG_STDERR,
            # The echoed ref embeds the npm package name; one containing
            # "timeout"/"connection" must not be mislabelled a network error.
            "Error response from registry: "
            "quay.io/org/repo:timeout-signal-2.0.0: not found",
            "Error: 404 Not Found",
            "Error: NAME_UNKNOWN: repository name not known to registry",
        ],
    )
    def test_pull_json_artifact_returns_none_for_real_oras_not_found(
        self, stderr
    ):
        """Real oras not-found output, via real ``oci.pull``, -> (None, None)."""
        with self._resolve_ok(), self._oras_fails(stderr):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)

    @pytest.mark.parametrize(
        ("stderr", "expected"),
        [
            ("Error: 401 Unauthorized", "Authentication failed"),
            ("Error: dial tcp: connection refused", "Network error pulling"),
            (
                "Error: credential helper not found in PATH",
                "oras pull failed: Error: credential helper not found",
            ),
            (
                "Error: resource not found: access denied",
                "oras pull failed: Error: resource not found",
            ),
        ],
    )
    def test_pull_json_artifact_raises_for_real_oras_hard_errors(
        self, stderr, expected
    ):
        """Auth/network/unanchored-"not found", via real ``oci.pull``, raise."""
        with (
            self._resolve_ok(),
            self._oras_fails(stderr),
            pytest.raises(click.ClickException, match=expected),
        ):
            pull_json_artifact(PREFIX, ".tl-compliance.json")

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
            self._resolve_ok(),
            patch(
                "slan_cuan.javascript.closure_oci.oci.pull",
                side_effect=oci.OrasError(message, stderr, 1),
            ),
            pytest.raises(click.ClickException, match="Failed to pull"),
        ):
            pull_json_artifact(PREFIX, ".tl-compliance.json")

    def test_cas_push_index_does_not_push_after_transient_pull_error(self):
        """A network blip pulling the index must not push an empty index."""
        with (
            self._resolve_ok(),
            patch(
                "slan_cuan.javascript.closure_oci.oci.pull",
                side_effect=oci.OrasError(
                    f"Network error pulling {PREFIX}", "timeout", 1
                ),
            ),
            patch("slan_cuan.javascript.closure_oci.oci.push") as mock_push,
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
                "slan_cuan.javascript.closure_oci.oci.pull",
                side_effect=_fake_pull,
            ) as mock_pull,
            patch(
                "slan_cuan.javascript.closure_oci.subprocess.run",
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

    def test_pull_json_artifact_pulls_pinned_digest_not_mutable_tag(self):
        """The pull call is pinned to the resolved digest, not the tag.

        Guards the atomicity fix: between resolve and pull, a concurrent
        writer could push a new revision onto the mutable tag -- pulling
        ``repo@digest`` instead means the parsed JSON always matches the
        digest this call returns, regardless of any such race.
        """
        payload = {"name": "lodash", "version": "4.17.21"}

        def _fake_pull(image, output_dir, auth_file=None, verbose=False):
            (Path(output_dir) / "x.tl-compliance.json").write_text(
                json.dumps(payload)
            )

        with (
            self._resolve_ok(),
            patch(
                "slan_cuan.javascript.closure_oci.oci.pull",
                side_effect=_fake_pull,
            ) as mock_pull,
        ):
            data, digest = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert data == payload
        assert digest == DIGEST
        pulled_ref = mock_pull.call_args.args[0]
        assert str(pulled_ref) == f"quay.io/org/tl-compliance@{DIGEST}"
        assert ":latest" not in str(pulled_ref)

    def test_pull_json_artifact_returns_none_when_no_suffix_match(self):
        """A pull that succeeds but has no matching file yields (None, None)."""

        def _fake_pull(image, output_dir, auth_file=None, verbose=False):
            (Path(output_dir) / "unrelated.json").write_text("{}")

        with (
            self._resolve_ok(),
            patch(
                "slan_cuan.javascript.closure_oci.oci.pull",
                side_effect=_fake_pull,
            ),
        ):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)


class TestPullJsonArtifactResolveNotFound:
    """pull_json_artifact -- a not-found *resolve* also yields (None, None).

    Distinct from the pull-fails-not-found tests above: here the resolve
    step itself (which now runs first) is what reports not-found, and
    oci.pull must never even be attempted.
    """

    @pytest.mark.parametrize(
        "stderr",
        [
            "Error: 404 Not Found",
            "Error: GET ...: MANIFEST_UNKNOWN: manifest unknown",
            TestPullJsonArtifact.REAL_ORAS_MISSING_TAG_STDERR,
            "Error: NAME_UNKNOWN: repository name not known to registry",
        ],
    )
    def test_resolve_not_found_returns_none_without_pulling(self, stderr):
        """A not-found ``oras resolve`` -> (None, None), no pull attempted."""
        with (
            patch(
                "slan_cuan.javascript.closure_oci.subprocess.run",
                return_value=Mock(returncode=1, stderr=stderr, stdout=""),
            ),
            patch("slan_cuan.javascript.closure_oci.oci.pull") as mock_pull,
        ):
            result = pull_json_artifact(PREFIX, ".tl-compliance.json")
        assert result == (None, None)
        mock_pull.assert_not_called()

    @pytest.mark.parametrize(
        ("stderr", "expected"),
        [
            ("Error: 401 Unauthorized", "Authentication failed"),
            ("Error: dial tcp: connection refused", "Network error resolving"),
            ("boom", "Failed to resolve"),
        ],
    )
    def test_resolve_hard_error_raises_without_pulling(self, stderr, expected):
        """An auth/network/unclassified resolve failure raises, not None."""
        with (
            patch(
                "slan_cuan.javascript.closure_oci.subprocess.run",
                return_value=Mock(returncode=1, stderr=stderr, stdout=""),
            ),
            patch("slan_cuan.javascript.closure_oci.oci.pull") as mock_pull,
            pytest.raises(click.ClickException, match=expected),
        ):
            pull_json_artifact(PREFIX, ".tl-compliance.json")
        mock_pull.assert_not_called()


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
            "slan_cuan.javascript.closure_oci.pull_json_artifact",
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
            "slan_cuan.javascript.closure_oci.pull_json_artifact",
            return_value=(None, None),
        ):
            result = pull_compliance_doc("lodash", "4.17.21", PREFIX)
        assert result == (None, None)


class TestPullComplianceDocLegacyFallback:
    """pull_compliance_doc falls back to the pre-port bash-tool tag."""

    def _pull(self, by_ref, name="@babel/core", version="7.0.0"):
        calls = []

        def _fake(image_ref, filename_suffix):
            calls.append(image_ref)
            return by_ref.get(image_ref, (None, None))

        with patch(
            "slan_cuan.javascript.closure_oci.pull_json_artifact",
            side_effect=_fake,
        ):
            return pull_compliance_doc(name, version, PREFIX), calls

    def test_legacy_ref_uses_bash_tag_on_stripped_prefix(self):
        """The legacy ref is the bash tag appended to the stripped prefix."""
        assert (
            legacy_compliance_image_ref("@babel/core", "7.0.0", PREFIX)
            == "quay.io/org/tl-compliance:babel-core-7.0.0"
        )
        assert legacy_compliance_image_ref("lodash", "4.17.21", PREFIX) is None

    def test_falls_back_to_legacy_tag_when_current_tag_absent(self):
        """A pre-port scoped doc is found, so it isn't treated as unseeded."""
        legacy_ref = "quay.io/org/tl-compliance:babel-core-7.0.0"
        raw = {
            "name": "@babel/core",
            "version": "7.0.0",
            "compliance_revision": 4,
        }
        (doc, digest), calls = self._pull({legacy_ref: (raw, DIGEST)})
        assert digest == DIGEST
        assert doc["compliance_revision"] == 4
        assert calls == [
            compliance_image_ref("@babel/core", "7.0.0", PREFIX),
            legacy_ref,
        ]

    def test_current_tag_wins_without_probing_legacy(self):
        """When the current tag exists the legacy tag is never pulled."""
        current_ref = compliance_image_ref("@babel/core", "7.0.0", PREFIX)
        raw = {"name": "@babel/core", "version": "7.0.0"}
        (_, digest), calls = self._pull({current_ref: (raw, DIGEST)})
        assert digest == DIGEST
        assert calls == [current_ref]

    def test_legacy_doc_for_a_different_package_is_ignored(self):
        """Legacy tags collided (@a/b vs a-b); a mismatched doc is not ours."""
        legacy_ref = "quay.io/org/tl-compliance:babel-core-7.0.0"
        other = {"name": "babel-core", "version": "7.0.0"}
        result, _ = self._pull({legacy_ref: (other, DIGEST)})
        assert result == (None, None)

    def test_unscoped_name_does_not_probe_a_second_tag(self):
        """No distinct legacy tag -> a single pull, then (None, None)."""
        result, calls = self._pull({}, name="lodash", version="4.17.21")
        assert result == (None, None)
        assert len(calls) == 1


class TestPullIndex:
    """pull_index -- pull_json_artifact + normalize_index, empty default."""

    def test_pull_index_defaults_to_empty_index_when_not_found(self):
        """No index artifact yet -> empty_index(), digest None."""
        with patch(
            "slan_cuan.javascript.closure_oci.pull_json_artifact",
            return_value=(None, None),
        ):
            index, digest = pull_index(PREFIX)
        assert digest is None
        assert index == closure_model.empty_index()

    def test_pull_index_normalizes_found_result(self):
        """A found raw index is run through normalize_index."""
        raw = {"revision": 3, "entries": {"a@1.0.0": {"parents": ["b@2.0.0"]}}}
        with patch(
            "slan_cuan.javascript.closure_oci.pull_json_artifact",
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
            "slan_cuan.javascript.closure_oci.oci.push", side_effect=_fake_push
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
                "slan_cuan.javascript.closure_oci.push_json_artifact",
                return_value=DIGEST,
            ),
            patch(
                "slan_cuan.javascript.closure_oci.closure_pulp.find_content_in_repo"
            ) as mock_find,
            patch(
                "slan_cuan.javascript.closure_oci.closure_pulp.sync_content_pulp_labels"
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
                "slan_cuan.javascript.closure_oci.push_json_artifact",
                return_value=DIGEST,
            ),
            patch(
                "slan_cuan.javascript.closure_oci.closure_pulp.find_content_in_repo",
                return_value={"pulp_href": "/content/found/"},
            ) as mock_find,
            patch(
                "slan_cuan.javascript.closure_oci.closure_pulp.sync_content_pulp_labels"
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
            "slan_cuan.javascript.closure_oci.push_json_artifact",
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
                "slan_cuan.javascript.closure_oci.pull_index",
                # pull, pull (retry round), verify-after-write re-pull.
                side_effect=[pulled, pulled, success],
            ) as mock_pull_index,
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                side_effect=[
                    oci.OrasError("conflict", "stderr", 1),
                    success,
                ],
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
        ):
            result = cas_push_index(
                lambda idx: idx,
                compliance_image_prefix=PREFIX,
                max_retries=5,
            )
        assert result == success
        assert mock_pull_index.call_count == 3
        assert mock_publish_index.call_count == 2

    def test_cas_push_index_verifies_uncontested_push(self):
        """An uncontested push is re-pulled once, verified, and returned."""
        pulled = ({"revision": 4, "entries": {}}, OTHER_DIGEST)
        entries = {"a@1": {"parents": ["b@1"]}}
        pushed = ({"revision": 5, "entries": entries}, DIGEST)
        with (
            patch(
                "slan_cuan.javascript.closure_oci.pull_index",
                side_effect=[pulled, pushed],
            ) as mock_pull_index,
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                return_value=pushed,
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep") as mock_sleep,
        ):
            result = cas_push_index(
                lambda idx: idx, compliance_image_prefix=PREFIX, max_retries=3
            )
        assert result == pushed
        assert mock_pull_index.call_count == 2
        mock_publish_index.assert_called_once()
        mock_sleep.assert_not_called()

    def test_cas_push_index_accepts_later_revision_on_verify(self):
        """A strictly-higher live revision also counts as verified.

        A re-pulled revision strictly above ours means some writer has
        since pushed a higher revision, so ours is no longer the latest
        either way -- this is the accept-a-later-revision heuristic, not
        a guarantee that revision was built on top of ours.
        """
        pulled = ({"revision": 4, "entries": {}}, OTHER_DIGEST)
        pushed = ({"revision": 5, "entries": {}}, DIGEST)
        later = ({"revision": 6, "entries": {}}, "sha256:" + "c" * 64)
        with (
            patch(
                "slan_cuan.javascript.closure_oci.pull_index",
                side_effect=[pulled, later],
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                return_value=pushed,
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
        ):
            result = cas_push_index(
                lambda idx: idx, compliance_image_prefix=PREFIX, max_retries=3
            )
        assert result == pushed
        mock_publish_index.assert_called_once()

    def test_cas_push_index_retries_when_concurrent_writer_overwrote(self):
        """Same revision, different digest on re-pull -> lost race, retry.

        Simulates two writers that both pulled revision 4 and both pushed
        revision 5: the other writer's push landed on top of ours, so the
        re-pull shows revision 5 with THEIR digest. The mutation must be
        re-applied against that newer state (revision 5 -> 6).
        """
        racer_digest = "sha256:" + "c" * 64
        first_pull = ({"revision": 4, "entries": {}}, OTHER_DIGEST)
        racer_state = (
            {"revision": 5, "entries": {"x@1": {"parents": ["racer@1"]}}},
            racer_digest,
        )
        ours_lost = ({"revision": 5, "entries": {}}, DIGEST)
        ours_final = (
            {"revision": 6, "entries": {"x@1": {"parents": ["racer@1"]}}},
            "sha256:" + "d" * 64,
        )
        mutated_inputs: list[dict] = []

        def _mutator(idx: dict) -> dict:
            mutated_inputs.append(idx)
            return idx

        with (
            patch(
                "slan_cuan.javascript.closure_oci.pull_index",
                side_effect=[first_pull, racer_state, racer_state, ours_final],
            ) as mock_pull_index,
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                side_effect=[ours_lost, ours_final],
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
        ):
            result = cas_push_index(
                _mutator, compliance_image_prefix=PREFIX, max_retries=3
            )
        assert result == ours_final
        assert mock_pull_index.call_count == 4
        assert mock_publish_index.call_count == 2
        # Retry round re-mutated the racer's newer state, pinned to rev 5.
        assert mutated_inputs[1] == racer_state[0]
        assert mock_publish_index.call_args.kwargs["expected_revision"] == 5

    def test_cas_push_index_raises_when_verify_never_confirms(self):
        """A push that never verifies within max_retries raises."""
        pulled = ({"revision": 4, "entries": {}}, OTHER_DIGEST)
        pushed = ({"revision": 5, "entries": {}}, DIGEST)
        overwritten = ({"revision": 5, "entries": {}}, "sha256:" + "c" * 64)
        with (
            patch(
                "slan_cuan.javascript.closure_oci.pull_index",
                side_effect=[pulled, overwritten] * 3,
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                return_value=pushed,
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep") as mock_sleep,
            pytest.raises(click.ClickException, match="Index CAS failed"),
        ):
            cas_push_index(
                lambda idx: idx, compliance_image_prefix=PREFIX, max_retries=3
            )
        assert mock_publish_index.call_count == 3
        assert mock_sleep.call_count == 2

    def test_cas_push_index_retries_when_verify_finds_no_index(self):
        """A re-pull that finds no index at all is not a verified write."""
        pulled = ({"revision": 0, "entries": {}}, None)
        pushed = ({"revision": 1, "entries": {}}, DIGEST)
        with (
            patch(
                "slan_cuan.javascript.closure_oci.pull_index",
                side_effect=[pulled, pulled, pulled, pushed],
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                return_value=pushed,
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
        ):
            result = cas_push_index(
                lambda idx: idx, compliance_image_prefix=PREFIX, max_retries=3
            )
        assert result == pushed
        assert mock_publish_index.call_count == 2

    def test_cas_push_index_raises_after_max_retries(self):
        """Persistent push failure raises click.ClickException, not OrasError."""
        pulled = ({"revision": 0, "entries": {}}, None)
        with (
            patch(
                "slan_cuan.javascript.closure_oci.pull_index", return_value=pulled
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                side_effect=oci.OrasError("conflict", "stderr", 1),
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep") as mock_sleep,
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
                "slan_cuan.javascript.closure_oci.pull_compliance_doc",
                side_effect=[(existing, OTHER_DIGEST), (verify, DIGEST)],
            ) as mock_pull_doc,
            patch(
                "slan_cuan.javascript.closure_oci.publish_compliance_doc",
                return_value=DIGEST,
            ) as mock_publish_doc,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
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
                "slan_cuan.javascript.closure_oci.pull_compliance_doc",
                return_value=(None, None),
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_compliance_doc",
                return_value=DIGEST,
            ),
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
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
            patch("slan_cuan.javascript.closure_pulp.DEFAULT_CAS_MAX_RETRIES", 4),
            patch(
                "slan_cuan.javascript.closure_oci.pull_index", return_value=pulled
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                side_effect=oci.OrasError("conflict", "stderr", 1),
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
            pytest.raises(click.ClickException, match="after 4 retries"),
        ):
            cas_push_index(lambda idx: idx, compliance_image_prefix=PREFIX)
        assert mock_publish_index.call_count == 4

    def test_cas_publish_compliance_default_retries_follow_closure_pulp(self):
        """Patching the shared constant changes cas_publish_compliance's too."""
        doc = {"name": "pkg", "version": "1.0.0", "compliance_revision": 1}
        with (
            patch("slan_cuan.javascript.closure_pulp.DEFAULT_CAS_MAX_RETRIES", 3),
            patch(
                "slan_cuan.javascript.closure_oci.pull_compliance_doc",
                return_value=(None, None),
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_compliance_doc",
                return_value=DIGEST,
            ) as mock_publish_doc,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
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
            patch("slan_cuan.javascript.closure_pulp.DEFAULT_CAS_MAX_RETRIES", 7),
            patch(
                "slan_cuan.javascript.closure_oci.pull_index", return_value=pulled
            ),
            patch(
                "slan_cuan.javascript.closure_oci.publish_index",
                side_effect=oci.OrasError("conflict", "stderr", 1),
            ) as mock_publish_index,
            patch("slan_cuan.javascript.closure_oci.time.sleep"),
            pytest.raises(click.ClickException),
        ):
            cas_push_index(
                lambda idx: idx, compliance_image_prefix=PREFIX, max_retries=2
            )
        assert mock_publish_index.call_count == 2
