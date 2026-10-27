"""Unit tests for the generate-security-metadata subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.models import EXTRACT_RESULT_FILENAME, ExtractResult, GlobalContext
from slan_cuan.tasks.generate_security_metadata import (
    generate_security_metadata,
)


@pytest.fixture
def ctx() -> GlobalContext:
    """Default non-verbose, non-dry-run context."""
    return GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=None,
    )


@pytest.fixture
def fake_osv_records() -> list[dict]:
    """Sample OSV records as returned by process_osv."""
    return [
        {
            "id": "x_RHLW-CVE-2024-001-1.0.0",
            "summary": "Buffer overflow in example-lib",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:example-lib",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }
    ]


def _create_index_file(directory: Path, name: str = "gav-index.json") -> Path:
    """Write a minimal build-index JSON file into *directory*."""
    data = {
        "buildId": "12345",
        "vulns": ["CVE-2024-1234"],
        "primaryGav": "org.example:lib:1.0.0",
        "artifacts": [
            {
                "groupId": "org.example",
                "artifactId": "lib",
                "version": "1.0.0",
            }
        ],
    }
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def _create_extract_result(workdir: Path, create_repo: bool = False) -> None:
    """Write a minimal extract-result.json into *workdir*.

    When *create_repo* is True, also create the ``repository/``
    subdirectory so that ``repo_dir`` resolves in production code.
    """
    data = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-06-19T12:00:00Z",
    }
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / EXTRACT_RESULT_FILENAME).write_text(json.dumps(data, indent=2))
    if create_repo:
        repo_dir = workdir / "TEST-build-output" / "repository"
        repo_dir.mkdir(parents=True, exist_ok=True)


def _invoke(
    runner,
    index_basedir,
    output_dir,
    ctx,
    index_filename=None,
    workdir=None,
    osidb_keytab=None,
    osidb_kerberos_principal="user@REALM",
    osidb_api_url="https://osidb.example.com/api/v1",
    advisory_id=None,
):
    args = [
        "--index-basedir",
        str(index_basedir),
        "--output-dir",
        str(output_dir),
        "--osidb-api-url",
        osidb_api_url,
        "--osidb-kerberos-principal",
        osidb_kerberos_principal,
    ]
    if workdir is not None:
        args += ["--workdir", str(workdir)]
    if index_filename is not None:
        args += ["--index-filename", index_filename]
    if osidb_keytab is not None:
        args += ["--osidb-keytab", str(osidb_keytab)]
    if advisory_id is not None:
        args += ["--advisory-id", advisory_id]
    return runner.invoke(generate_security_metadata, args, obj=ctx)


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_creates_osv_output(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Successful attestation writes an OSV file from the index."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert "Processing" in result.output
    assert "Security metadata generation completed" in result.output

    assert output_dir.is_dir()
    osv_file = output_dir / "x_RHLW-CVE-2024-001-1.0.0.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records[0]

    updated_result = ExtractResult.from_file(workdir / EXTRACT_RESULT_FILENAME)
    assert updated_result.security_metadata_dir == "security_metadata"


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_custom_filename(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A custom --index-filename produces an OSV file named after the stem."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir, name="cve-report.json")

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        index_filename="cve-report.json",
        workdir=workdir,
    )

    assert result.exit_code == 0, result.output

    osv_file = output_dir / "x_RHLW-CVE-2024-001-1.0.0.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records[0]


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_passes_index_data_to_process_osv(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """process_osv receives the parsed JSON data from the index file."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    index_data = {"buildId": "99", "artifacts": []}
    (index_dir / "gav-index.json").write_text(json.dumps(index_data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = []

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_process_osv.assert_called_once_with(index_data, osidb_client=None)


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_writes_tekton_results(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    tmp_path: Path,
) -> None:
    """SECURITY_METADATA_DIR Tekton result is written when results dir is set."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"
    results_dir = tmp_path / "results"

    mock_process_osv.return_value = fake_osv_records

    tekton_ctx = GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=results_dir,
    )

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, tekton_ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    security_metadata_dir_file = results_dir / "SECURITY_METADATA_DIR"
    assert security_metadata_dir_file.exists()
    assert security_metadata_dir_file.read_text() == str(output_dir)


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_creates_nested_output_dir(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Nested output_dir is created with intermediate parents."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "nested" / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert output_dir.is_dir()
    assert (output_dir / "x_RHLW-CVE-2024-001-1.0.0.json").exists()


def test_generate_security_metadata_missing_required_options() -> None:
    """Missing --index-basedir or --output-dir produces an error."""
    runner = CliRunner()

    result = runner.invoke(
        generate_security_metadata, ["--output-dir", "/tmp/out"]
    )
    assert result.exit_code != 0

    result = runner.invoke(
        generate_security_metadata, ["--index-basedir", "/tmp/idx"]
    )
    assert result.exit_code != 0


def test_generate_security_metadata_allows_omitted_osidb_options(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Omitting the osidb-* options is allowed (they default to empty)."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    runner = CliRunner()
    result = runner.invoke(
        generate_security_metadata,
        [
            "--index-basedir",
            str(tmp_path / "nonexistent"),
            "--output-dir",
            str(workdir / "security_metadata"),
            "--workdir",
            str(workdir),
        ],
        obj=ctx,
    )

    assert result.exit_code == 0, result.output
    assert "osidb-api-url" not in result.output
    assert "osidb-kerberos-principal" not in result.output


def test_generate_security_metadata_allows_empty_osidb_options(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Passing empty strings for the osidb-* options is allowed."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    runner = CliRunner()
    result = runner.invoke(
        generate_security_metadata,
        [
            "--index-basedir",
            str(tmp_path / "nonexistent"),
            "--output-dir",
            str(workdir / "security_metadata"),
            "--workdir",
            str(workdir),
            "--osidb-api-url",
            "",
            "--osidb-kerberos-principal",
            "",
            "--osidb-keytab",
            "",
        ],
        obj=ctx,
    )

    assert result.exit_code == 0, result.output


def test_generate_security_metadata_file_not_found(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A missing index file skips generation gracefully."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    runner = CliRunner()
    result = _invoke(
        runner, tmp_path / "nonexistent", output_dir, ctx, workdir=workdir
    )

    assert result.exit_code == 0
    assert "skipping security metadata generation" in result.output
    assert not output_dir.exists()


# ── OSIDB authentication tests ──────────────────────────────────


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_no_keytab_skips_osidb(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Without a keytab, OSIDB is skipped and process_osv gets None."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert "skipping OSIDB fetching" in result.output
    mock_process_osv.assert_called_once()
    call_args = mock_process_osv.call_args
    assert call_args[1]["osidb_client"] is None
    assert "advisory_id" in call_args[0][0]


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_nonexistent_keytab_skips_osidb(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A keytab path that doesn't exist skips OSIDB."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=tmp_path / "missing.keytab",
    )

    assert result.exit_code == 0, result.output
    assert "skipping OSIDB fetching" in result.output
    mock_process_osv.assert_called_once()
    call_args = mock_process_osv.call_args
    assert call_args[1]["osidb_client"] is None
    assert "advisory_id" in call_args[0][0]


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_empty_vulnerabilities_skip_osidb_with_valid_keytab(
    mock_process_osv: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Validated builds skip OSIDB even when a keytab is available."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    index_path = _create_index_file(index_dir)
    index_data = json.loads(index_path.read_text())
    index_data["vulns"] = []
    index_path.write_text(json.dumps(index_data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"
    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")
    mock_process_osv.return_value = fake_osv_records

    result = _invoke(
        CliRunner(),
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=keytab,
    )

    assert result.exit_code == 0, result.output
    assert "No vulnerabilities found in index" in result.output
    mock_get_token.assert_not_called()
    mock_osidb_client_cls.assert_not_called()
    mock_process_osv.assert_called_once_with(index_data, osidb_client=None)


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_valid_keytab_creates_osidb_client(
    mock_process_osv: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A valid keytab authenticates and passes the client to process_osv."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")

    mock_get_token.return_value = "jwt-token-123"
    mock_client = MagicMock()
    mock_client.available = True
    mock_osidb_client_cls.return_value = mock_client
    mock_process_osv.return_value = fake_osv_records

    api_url = "https://osidb.example.com/api/v1"
    principal = "user@REALM"

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=keytab,
        osidb_kerberos_principal=principal,
        osidb_api_url=api_url,
    )

    assert result.exit_code == 0, result.output
    assert "Creating OSIDB client" in result.output

    mock_get_token.assert_called_once_with(
        api_url, principal, str(keytab), verbose=False
    )
    mock_osidb_client_cls.assert_called_once_with(
        base_url="https://osidb.example.com", token="jwt-token-123"
    )
    mock_process_osv.assert_called_once()
    call_args = mock_process_osv.call_args
    assert call_args[1]["osidb_client"] is mock_client
    assert "advisory_id" in call_args[0][0]


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_osidb_client_unavailable_aborts(
    mock_process_osv: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """When OsidbClient reports unavailable, the command aborts."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")

    mock_get_token.return_value = "jwt-token-123"
    mock_client = MagicMock()
    mock_client.available = False
    mock_osidb_client_cls.return_value = mock_client

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=keytab,
    )

    assert result.exit_code != 0
    assert "Failed to create OSIDB client" in result.output
    mock_process_osv.assert_not_called()


@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_uses_spnego(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
) -> None:
    """_get_osidb_auth_token gets a TGT and negotiates via SPNEGO."""
    import os
    import tempfile

    from slan_cuan.tasks.generate_security_metadata import (
        _get_osidb_auth_token,
    )

    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.json.return_value = {"access": "my-jwt"}
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    mock_session_cls.return_value = mock_session

    token = _get_osidb_auth_token(
        "https://osidb.example.com/api/v1",
        "user@REALM",
        "/path/to/keytab",
    )

    assert token == "my-jwt"
    expected_ccache = os.path.join(tempfile.gettempdir(), "osidb_krb5cc")
    mock_krbticket_cls.init.assert_called_once_with(
        "user@REALM", keytab="/path/to/keytab", ccache_name=expected_ccache
    )
    call_args = mock_session.get.call_args
    assert call_args[0][0] == "https://osidb.example.com/auth/token"
    mock_response.raise_for_status.assert_called_once()


@patch("slan_cuan.tasks.generate_security_metadata.time.sleep")
@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_retries_on_failure(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
    mock_sleep: Mock,
) -> None:
    """_get_osidb_auth_token retries transient failures and succeeds."""
    import requests

    from slan_cuan.tasks.generate_security_metadata import _get_osidb_auth_token

    ok_response = MagicMock()
    ok_response.json.return_value = {"access": "my-jwt"}
    mock_session = MagicMock()
    mock_session.get.side_effect = [
        requests.exceptions.ConnectionError("boom"),
        requests.exceptions.ConnectionError("boom again"),
        ok_response,
    ]
    mock_session_cls.return_value = mock_session

    token = _get_osidb_auth_token(
        "https://osidb.example.com/api/v1",
        "user@REALM",
        "/path/to/keytab",
    )

    assert token == "my-jwt"
    assert mock_session.get.call_count == 3
    assert mock_sleep.call_count == 2


@patch("slan_cuan.tasks.generate_security_metadata.time.sleep")
@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_raises_after_max_retries(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
    mock_sleep: Mock,
) -> None:
    """_get_osidb_auth_token raises once all retries are exhausted."""
    import click
    import requests

    from slan_cuan.tasks.generate_security_metadata import (
        _OSIDB_TOKEN_MAX_RETRIES,
        _get_osidb_auth_token,
    )

    mock_session = MagicMock()
    mock_session.get.side_effect = requests.exceptions.ConnectionError("boom")
    mock_session_cls.return_value = mock_session

    with pytest.raises(click.ClickException, match="Failed to retrieve OSIDB"):
        _get_osidb_auth_token(
            "https://osidb.example.com/api/v1",
            "user@REALM",
            "/path/to/keytab",
        )

    assert mock_session.get.call_count == _OSIDB_TOKEN_MAX_RETRIES


@patch("slan_cuan.tasks.generate_security_metadata.time.sleep")
@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_missing_access_key(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
    mock_sleep: Mock,
) -> None:
    """_get_osidb_auth_token fails when the 'access' key is absent."""
    import click

    from slan_cuan.tasks.generate_security_metadata import _get_osidb_auth_token

    bad_response = MagicMock()
    bad_response.json.return_value = {"detail": "unauthorized"}
    mock_session = MagicMock()
    mock_session.get.return_value = bad_response
    mock_session_cls.return_value = mock_session

    with pytest.raises(click.ClickException, match="Failed to retrieve OSIDB"):
        _get_osidb_auth_token(
            "https://osidb.example.com/api/v1",
            "user@REALM",
            "/path/to/keytab",
        )


# ---------------------------------------------------------------------------
# Advisory ID injection tests
# ---------------------------------------------------------------------------


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_advisory_id_injected(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """advisory_id appears in the dict passed to process_osv."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    aid = "RHLW-2026-aaaaaaaaaaaaaaaa"
    mock_process_osv.return_value = [{"id": aid, "affected": []}]

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        advisory_id=aid,
    )
    assert result.exit_code == 0, result.output
    call_args = mock_process_osv.call_args
    index_data = call_args[0][0]
    assert index_data["advisory_id"] == aid


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_advisory_id_auto_derived(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Without --advisory-id, the derived ID is injected automatically."""
    from slan_cuan.tasks.generate_security_metadata import (
        _ADVISORY_ID_RE,
    )

    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)
    assert result.exit_code == 0, result.output
    call_args = mock_process_osv.call_args
    index_data = call_args[0][0]
    assert "advisory_id" in index_data
    assert _ADVISORY_ID_RE.match(index_data["advisory_id"])


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_output_filename_uses_advisory_id(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Output file is named with a valid MurmurHash advisory ID."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    aid = "RHLW-2026-aaaaaaaaaaaaaaaa"
    mock_process_osv.return_value = [{"id": aid, "affected": []}]

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        advisory_id=aid,
    )
    assert result.exit_code == 0, result.output
    assert (output_dir / f"{aid}.json").exists()


# ---------------------------------------------------------------------------
# _derive_advisory_id tests
# ---------------------------------------------------------------------------


def test_derive_advisory_id_purl_path() -> None:
    """PURL-based build index produces a deterministic MurmurHash ID."""
    from slan_cuan.tasks.generate_security_metadata import (
        _ADVISORY_ID_RE,
        _derive_advisory_id,
    )

    index = {
        "ecosystem": "maven",
        "primaryPurl": "pkg:maven/org.example/artifact@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-25710"],
        "created": "2026-07-15T14:02:27+00:00",
    }
    result = _derive_advisory_id(index)
    assert result is not None
    assert _ADVISORY_ID_RE.match(result)
    assert result == "RHLW-2026-5fc0229c48c1b99c"


def test_derive_advisory_id_gav_path() -> None:
    """GAV-based build index produces a deterministic MurmurHash ID."""
    from slan_cuan.tasks.generate_security_metadata import (
        _ADVISORY_ID_RE,
        _derive_advisory_id,
    )

    index = {
        "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
        "vulns": ["CVE-2024-25710"],
        "created": "2026-07-15T14:02:27+00:00",
    }
    result = _derive_advisory_id(index)
    assert result is not None
    assert _ADVISORY_ID_RE.match(result)
    assert result == "RHLW-2026-5fc0229c48c1b99c"


def test_derive_advisory_id_deterministic() -> None:
    """Same input always produces the same hash."""
    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
        "vulns": ["CVE-2024-25710"],
        "created": "2026-07-15T14:02:27+00:00",
    }
    assert _derive_advisory_id(index) == _derive_advisory_id(index)


def test_derive_advisory_id_no_vulns() -> None:
    """No vulns returns None."""
    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {"primaryGav": "org.example:artifact:1.0.0", "vulns": []}
    assert _derive_advisory_id(index) is None


def test_derive_advisory_id_no_primary() -> None:
    """Missing primary purl and GAV raises ClickException."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {"vulns": ["CVE-2024-25710"]}
    with pytest.raises(click.ClickException, match="no primaryGav"):
        _derive_advisory_id(index)


def test_derive_advisory_id_missing_version() -> None:
    """A GAV with no version raises ClickException."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "primaryGav": "org.example:artifact:",
        "vulns": ["CVE-2024-25710"],
    }
    with pytest.raises(click.ClickException, match="empty version"):
        _derive_advisory_id(index)


def test_derive_advisory_id_bad_ecosystem() -> None:
    """Unsupported ecosystem raises ClickException."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "ecosystem": "npm",
        "purls": ["pkg:npm/foo@1.0.0"],
        "vulns": ["CVE-2024-25710"],
    }
    with pytest.raises(click.ClickException, match="not supported"):
        _derive_advisory_id(index)


def test_derive_advisory_id_golden_value() -> None:
    """Golden-value test with a synthetic package."""
    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "ecosystem": "maven",
        "primaryPurl": "pkg:maven/com.example/foobar@1.0.0.rhlw-00042",
        "purls": ["pkg:maven/com.example/foobar@1.0.0.rhlw-00042"],
        "vulns": ["CVE-2099-00001"],
        "created": "2026-01-01T00:00:00+00:00",
    }
    result = _derive_advisory_id(index)
    assert result == "RHLW-2026-1c8a4ea22ac9467c"


# ---------------------------------------------------------------------------
# _validate_advisory_id tests
# ---------------------------------------------------------------------------


def test_validate_advisory_id_accepts_valid() -> None:
    """Valid MurmurHash-format ID is accepted."""
    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    result = _validate_advisory_id(None, None, "RHLW-2026-5fc0229c48c1b99c")
    assert result == "RHLW-2026-5fc0229c48c1b99c"


def test_validate_advisory_id_rejects_old_dot_format() -> None:
    """Old dot-delimited format is rejected."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    with pytest.raises(click.BadParameter, match="must match"):
        _validate_advisory_id(None, None, "RHLW-Maven.org.example:artifact.1.0.0")


def test_validate_advisory_id_rejects_old_numeric() -> None:
    """Old numeric ID is rejected."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    with pytest.raises(click.BadParameter, match="must match"):
        _validate_advisory_id(None, None, "RHLW-2026-00042")


def test_validate_advisory_id_rejects_path_separator() -> None:
    """Path separators in the ID are rejected by the regex."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    with pytest.raises(click.BadParameter, match="must match"):
        _validate_advisory_id(None, None, "RHLW-2026-5fc0229c/8c1b99c")


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_derived_id_malformed_raises(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A malformed derived ID raises ClickException."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata._derive_advisory_id",
        return_value="RHLW-bad-format",
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)
    assert result.exit_code != 0
    assert "malformed" in result.output


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_override_divergence_warning(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """When --advisory-id diverges from derivation, a warning is emitted."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "12345",
        "vulns": ["CVE-2024-1234"],
        "primaryGav": "org.example:lib:1.0.0",
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"
    mock_process_osv.return_value = []

    override_id = "RHLW-2026-aaaaaaaaaaaaaaaa"
    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        advisory_id=override_id,
    )
    assert result.exit_code == 0, result.output
    assert "overrides" in result.output


# --- Regression tests for reviewer findings ---


def test_clean_build_enriched_sbom(ctx: GlobalContext, tmp_path: Path) -> None:
    """A clean build (no vulns) produces an enriched SBOM in enriched-sboms/.

    The enriched SBOM must have empty pedigree.patches and "validated
    build" notes. No repo_dir is required.
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "clean-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists(), f"Expected enriched SBOM at {sbom_path}"
    sbom = json.loads(sbom_path.read_text())

    assert sbom["bomFormat"] == "CycloneDX"
    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    assert pedigree["patches"] == []
    assert "validated build" in pedigree["notes"].lower()
    assert "remediation" not in pedigree["notes"].lower()

    # PURL must use the validated repository URL
    assert "/validated/" in comp["purl"]
    assert "/remediated/" not in comp["purl"]


def test_clean_build_skips_vex(ctx: GlobalContext, tmp_path: Path) -> None:
    """A clean build (no vulns) must not call _generate_vex_from_index."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "clean-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_vex.assert_not_called()


def test_remediation_enriched_sbom(ctx: GlobalContext, tmp_path: Path) -> None:
    """Remediation builds produce an enriched SBOM with correct notes."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "remediation-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "2.0.0",
            "full": "2.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/com.example/core@2.0.0.rhlw-00001",
        "purls": ["pkg:maven/com.example/core@2.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-1234"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_vex.assert_called_once()

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "com/example/core/2.0.0.rhlw-00001"
        / "core-2.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists(), f"Expected enriched SBOM at {sbom_path}"
    sbom = json.loads(sbom_path.read_text())

    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    assert "backported security fixes" in pedigree["notes"].lower()
    assert len(pedigree["patches"]) == 1
    assert pedigree["patches"][0]["resolves"][0]["id"] == "CVE-2024-1234"

    assert "/remediated/" in comp["purl"]
    assert "/validated/" not in comp["purl"]


def test_repo_dir_missing_succeeds(ctx: GlobalContext, tmp_path: Path) -> None:
    """Generate succeeds without repository/ — enriched SBOMs still written."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "no-repo-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists(), "Enriched SBOM must be written without repo_dir"


def test_lw_only_vulns_novel_notes(ctx: GlobalContext, tmp_path: Path) -> None:
    """LW-only vulns produce novel-fix notes with empty patches.

    LW- IDs denote embargoed/novel fixes, not backports of publicly
    disclosed CVEs. The pedigree notes must say "novel fix," and
    LW- IDs are excluded from patches (no NVD entry).
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "novel-only-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["LW-novel-001"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists()
    sbom = json.loads(sbom_path.read_text())

    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    assert pedigree["patches"] == [], "LW- IDs must not appear in patches"
    assert "novel fix" in pedigree["notes"].lower()
    assert "embargoed" in pedigree["notes"].lower()
    assert "backported" not in pedigree["notes"].lower()

    assert "/predisclosure/" in comp["purl"]
    assert "/remediated/" not in comp["purl"]
    assert "/validated/" not in comp["purl"]


def test_lw_only_vulns_calls_vex(ctx: GlobalContext, tmp_path: Path) -> None:
    """LW-only builds (truthy vulns) must still invoke VEX generation."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "novel-vex-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["LW-novel-001"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_vex.assert_called_once()


def test_mixed_cve_lw_build_uses_predisclosure(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """Mixed CVE+LW build is contaminated — predisclosure only."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "mixed-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-1234", "LW-novel-001"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists()
    sbom = json.loads(sbom_path.read_text())
    comp = sbom["components"][0]
    pedigree = comp["pedigree"]

    assert "/predisclosure/" in comp["purl"]
    assert "/remediated/" not in comp["purl"]
    assert "/validated/" not in comp["purl"]

    assert "novel fix" in pedigree["notes"].lower()
    assert "embargoed" in pedigree["notes"].lower()


def test_multi_purl_generates_multiple_sidecars(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """A build index with multiple purls produces one sidecar per artifact."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "multi-purl-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib-core@1.0.0.rhlw-00001",
        "purls": [
            "pkg:maven/org.example/lib-core@1.0.0.rhlw-00001",
            "pkg:maven/org.example/lib-util@1.0.0.rhlw-00001",
        ],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    core_sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib-core/1.0.0.rhlw-00001"
        / "lib-core-1.0.0.rhlw-00001.bom.json"
    )
    util_sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib-util/1.0.0.rhlw-00001"
        / "lib-util-1.0.0.rhlw-00001.bom.json"
    )
    assert core_sbom_path.exists(), f"Expected SBOM at {core_sbom_path}"
    assert util_sbom_path.exists(), f"Expected SBOM at {util_sbom_path}"

    core = json.loads(core_sbom_path.read_text())
    util = json.loads(util_sbom_path.read_text())
    assert core["components"][0]["name"] == "lib-core"
    assert util["components"][0]["name"] == "lib-util"
    assert core["serialNumber"] != util["serialNumber"]


def test_upstream_sbom_enriched(ctx: GlobalContext, tmp_path: Path) -> None:
    """When an upstream SBOM exists, its fields are preserved after enrichment."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "enrich-test",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    # Create an upstream SBOM in upstream-sboms/
    upstream_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "supplier": {"name": "PNC"},
        },
        "components": [
            {
                "type": "library",
                "group": "org.example",
                "name": "lib",
                "version": "1.0.0.rhlw-00001",
                "purl": (
                    "pkg:maven/org.example/lib@1.0.0.rhlw-00001"
                    "?type=jar"
                ),
                "hashes": [
                    {"alg": "SHA-256", "content": "abc123upstream"}
                ],
                "licenses": [
                    {"license": {"id": "Apache-2.0"}}
                ],
            }
        ],
    }
    upstream_dir = (
        workdir
        / "upstream-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
    )
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "lib-1.0.0.rhlw-00001.bom.json").write_text(
        json.dumps(upstream_sbom)
    )

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists()
    sbom = json.loads(sbom_path.read_text())

    # Upstream fields preserved
    assert sbom["specVersion"] == "1.6"
    comp = sbom["components"][0]
    assert comp["hashes"] == [{"alg": "SHA-256", "content": "abc123upstream"}]
    assert comp["licenses"] == [{"license": {"id": "Apache-2.0"}}]

    # Enrichment applied
    assert "pedigree" in comp
    assert "validated build" in comp["pedigree"]["notes"].lower()
    assert "/validated/" in comp["purl"]
    assert "serialNumber" in sbom


def test_version_traversal_rejected(ctx: GlobalContext, tmp_path: Path) -> None:
    """A PURL with '..' in version is rejected by the enrichment guard."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    traversal_version = "..%2F..%2F..%2F..%2Fetc"
    data = {
        "buildId": "traversal-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "../../../../etc",
            "b": 0,
            "n": 0,
        },
        "primaryPurl": f"pkg:maven/org.example/artifact@{traversal_version}",
        "purls": [f"pkg:maven/org.example/artifact@{traversal_version}"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code != 0, "Should reject unsafe version"
    assert "unsafe characters" in result.output.lower()


def test_osgi_qualified_version_sidecar(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """OSGi-qualified versions (hyphen rhlw suffix) produce correct sidecars.

    ADR-0026 §1.1: versions like 4.1.132.Final use a hyphen separator
    (4.1.132.Final-rhlw-00002) because the qualifier already occupies
    the fourth dot segment.
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "osgi-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "4.1.132.Final",
            "full": "4.1.132.Final-rhlw-00002",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": (
            "pkg:maven/io.netty/netty-codec-dns@4.1.132.Final-rhlw-00002"
        ),
        "purls": ["pkg:maven/io.netty/netty-codec-dns@4.1.132.Final-rhlw-00002"],
        "vulns": ["CVE-2025-99999"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "io/netty/netty-codec-dns/4.1.132.Final-rhlw-00002"
        / "netty-codec-dns-4.1.132.Final-rhlw-00002.bom.json"
    )
    assert sbom_path.exists(), f"Expected enriched SBOM at {sbom_path}"
    sbom = json.loads(sbom_path.read_text())

    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    ancestor = pedigree["ancestors"][0]
    assert ancestor["version"] == "4.1.132.Final"
    assert "rhlw" not in ancestor["version"]

    assert "backported security fixes" in pedigree["notes"].lower()
    assert len(pedigree["patches"]) == 1

    assert "/remediated/" in comp["purl"]
