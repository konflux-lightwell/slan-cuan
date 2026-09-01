"""Generate the OSV and VEX attestations for a given build index."""

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import click
from fath_cuan.workflow import process_osv

from slan_cuan.context import GlobalContext, write_tekton_result
from slan_cuan.models import EXTRACT_RESULT_FILENAME, ExtractResult

_OSIDB_TOKEN_REQUEST_TIMEOUT = float(
    os.getenv("OSIDB_TOKEN_REQUEST_TIMEOUT", "10.0")
)
_OSIDB_TOKEN_MAX_RETRIES = int(os.getenv("OSIDB_TOKEN_MAX_RETRIES", "3"))
_OSIDB_TOKEN_RETRY_BACKOFF = float(os.getenv("OSIDB_TOKEN_RETRY_BACKOFF", "2.0"))


def _get_osidb_auth_token(api_url: str, principal: str, keytab: str) -> str:
    # Lazy imports: these come from the optional "kerberos" extra and must not
    # break importing this module (and hence the CLI) when it is not installed.
    import requests
    from krbticket import KrbTicket
    from requests_gssapi import OPTIONAL, HTTPSPNEGOAuth

    parsed = urlparse(api_url)
    token_url = f"{parsed.scheme}://{parsed.netloc}/auth/token"

    # Use a file-based ccache — keyring/API ccache backends are not
    # available in Konflux container environments.
    ccache_path = os.path.join(tempfile.gettempdir(), "osidb_krb5cc")
    os.environ["KRB5CCNAME"] = f"FILE:{ccache_path}"
    KrbTicket.init(principal, keytab=keytab, ccache_name=ccache_path)

    session = requests.Session()
    auth = HTTPSPNEGOAuth(
        mutual_authentication=OPTIONAL, opportunistic_auth=False
    )

    last_error: Exception | None = None
    for attempt in range(1, _OSIDB_TOKEN_MAX_RETRIES + 1):
        try:
            response = session.get(
                token_url,
                timeout=_OSIDB_TOKEN_REQUEST_TIMEOUT,
                auth=auth,
            )
            response.raise_for_status()
            payload = response.json()
            token = payload.get("access")
            if not token:
                raise ValueError(
                    "OSIDB token response is missing the 'access' key "
                    f"(got keys: {sorted(payload)})"
                )
            return token
        except (requests.exceptions.RequestException, ValueError) as e:
            last_error = e
            click.echo(
                f"OSIDB token request attempt {attempt}/"
                f"{_OSIDB_TOKEN_MAX_RETRIES} failed: {e}"
            )
            if attempt < _OSIDB_TOKEN_MAX_RETRIES:
                time.sleep(_OSIDB_TOKEN_RETRY_BACKOFF * attempt)

    raise click.ClickException(
        f"Failed to retrieve OSIDB auth token after "
        f"{_OSIDB_TOKEN_MAX_RETRIES} attempts: {last_error}"
    )


@click.command()
@click.option(
    "--index-basedir",
    type=str,
    required=True,
    help="The base directory of the build index JSON file.",
)
@click.option(
    "--index-filename",
    type=str,
    required=True,
    help="The filename of the build index JSON file "
    "relative to the base directory.",
    default="gav-index.json",
)
@click.option(
    "--osidb-api-url",
    type=str,
    default="",
    show_default=True,
    help="The URL of the OSIDB API to use for authentication on OSIDB.",
)
@click.option(
    "--osidb-keytab",
    type=str,
    default="",
    show_default=True,
    help="The path to the OSIDB keytab file to use for authentication on OSIDB.",
)
@click.option(
    "--osidb-kerberos-principal",
    type=str,
    default="",
    show_default=True,
    help="The Kerberos principal to use for authentication on OSIDB.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to output the attestations to.",
)
@click.option(
    "--workdir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to work in, which is the extracted directory.",
)
@click.pass_obj
def generate_security_metadata(
    ctx: GlobalContext,
    index_basedir: str,
    index_filename: str,
    osidb_api_url: str,
    osidb_keytab: str,
    osidb_kerberos_principal: str,
    output_dir: Path,
    workdir: Path,
) -> None:
    """Generate the OSV and VEX attestations for a given build index."""
    index_full_path = workdir / index_basedir / index_filename
    if not index_full_path.exists():
        click.echo(
            f"Index file not found at {index_full_path}, "
            "skipping security metadata generation."
        )
        return

    osidb_client = None
    if osidb_keytab and Path(osidb_keytab).is_file():
        # Lazy import: fath_cuan.osidb only exists in newer fath-cuan and is
        # only needed when a keytab is supplied.
        from fath_cuan.osidb import OsidbClient

        click.echo(
            f"Creating OSIDB client on {osidb_api_url} "
            f"with keytab file {osidb_keytab}"
        )
        auth_token = _get_osidb_auth_token(
            osidb_api_url, osidb_kerberos_principal, osidb_keytab
        )
        # OsidbClient appends /osidb/api/v1/... paths itself, so pass only
        # the base URL (scheme + host) — not the full API path.
        _parsed = urlparse(osidb_api_url)
        osidb_base_url = f"{_parsed.scheme}://{_parsed.netloc}"
        osidb_client = OsidbClient(base_url=osidb_base_url, token=auth_token)
        if not osidb_client.available:
            click.echo("Failed to create OSIDB client, exiting.")
            raise click.Abort()
    else:
        click.echo("No OSIDB keytab file found, skipping OSIDB fetching.")

    click.echo(f"Processing {index_full_path} to generate OSV and VEX...")
    with open(index_full_path, "r") as f:
        index_data = json.load(f)

    osv_records = process_osv(index_data, osidb_client=osidb_client)
    output_dir.mkdir(parents=True, exist_ok=True)
    for record in osv_records:
        osv_output_path = output_dir / f"{record['id']}.json"
        click.echo(f"Writing OSV record to {osv_output_path}")
        with open(osv_output_path, "w") as f:
            json.dump(record, f, indent=2)

    # TODO: Generate VEX document

    # Save the updated extract result
    result = ExtractResult.from_file(workdir / EXTRACT_RESULT_FILENAME)
    result = dataclasses.replace(
        result, security_metadata_dir=str(output_dir.relative_to(workdir))
    )
    result.save(workdir / EXTRACT_RESULT_FILENAME)

    write_tekton_result(
        ctx.tekton_results_dir,
        "SECURITY_METADATA_DIR",
        str(output_dir),
    )
    click.echo("Security metadata generation completed successfully.")
