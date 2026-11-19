"""Pulp CLI wrapper for Pulp operations (orphan → associate).

Provides a thin subprocess wrapper over the ``hosted-pulp`` (or
compatible ``pulp``) binary that mirrors the ``PulpConfig`` +
``PulpClient`` pattern used for Java but uses curated commands
(``python content upload``, ``python repository modify --wait``, etc.).
The CLI handles name-based lookups and task polling; this module only
builds the invocation and parses ``--output json``.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from slan_cuan.pulp.constants import AUTH_TYPE_CERT, AUTH_TYPE_TBR
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig

PULP_BIN = os.environ.get("PULP_BIN", "hosted-pulp")


def _global_args(
    config: PulpConfig,
    *,
    dry_run: bool = False,
    verbose: int | bool = 0,
    wait: bool = False,
    wait_timeout: float | None = None,
    timeout: float | None = None,
    output: str = "json",
) -> list[str]:
    """Build global flags for ``pulp`` from ``PulpConfig``.

    Only ``tbr`` auth is supported. Credentials are written to a
    temporary ``cli.toml`` (mode 0600) and passed via the process
    environment so ``--password`` never appears on the argv — see
    calungaproject/plumbing#457 for the same fix.

    ``cert`` auth raises ``PulpError`` until a ``cli.toml``-based flow
    that carries ``client_cert``/``client_key`` is added.
    """
    if config.auth_type == AUTH_TYPE_CERT:
        raise PulpError(
            "Certificate auth via pulp CLI is not yet supported; "
            "use the direct REST client for cert auth",
            status_code=0,
            response_body="",
        )
    if config.auth_type != AUTH_TYPE_TBR:
        raise PulpError(
            f"Invalid auth type '{config.auth_type}' for pulp CLI",
            status_code=0,
            response_body="",
        )

    args: list[str] = []

    if config.base_url:
        args.extend(["--base-url", config.base_url])
    if config.domain:
        args.extend(["--domain", config.domain])
    # Username/password are intentionally NOT added to argv here;
    # they are written to a temporary pulp config file in
    # ``run_hosted_pulp`` to avoid leaking secrets in /proc (plumbing#457).
    if timeout is not None:
        args.extend(["--timeout", f"{timeout}s"])
    elif config.task_timeout and output == "json":
        # Default HTTP timeout; wait-timeout is separate.
        pass

    if dry_run:
        args.append("--dry-run")
    if verbose:
        if isinstance(verbose, bool):
            if verbose:
                args.append("-v")
        elif isinstance(verbose, int) and verbose > 0:
            # Counted verbosity: -v, -vv, etc. hosted-pulp accepts -v as count.
            for _ in range(verbose):
                args.append("-v")
    if wait:
        args.append("--wait")
        if wait_timeout is not None:
            args.extend(["--wait-timeout", f"{int(wait_timeout)}s"])
        elif config.task_timeout:
            args.extend(["--wait-timeout", f"{int(config.task_timeout)}s"])
    if output:
        args.extend(["--output", output])

    return args


def _write_pulp_config(config: PulpConfig) -> Path | None:
    """Write a temporary pulp ``cli.toml`` for TBR credentials.

    Returns the temp path (caller must unlink it), or ``None`` when no
    credentials are present. File is created with mode 0600. This
    mirrors plumbing's ``pulp-upload`` credential protection (plumbing#457)
    — credentials on argv would be visible in ``/proc/<pid>/cmdline``.

    The config uses the pulp-cli/hosted-pulp ``cli.toml`` format
    (``[cli]`` section with ``base_url``, ``api_root``, ``username``,
    ``password``, ``domain``) and is consumed via the ``PULP_CLI_CONFIG``
    env var, matching the hosted-pulp ``cli.toml`` location
    ``~/.config/pulp/cli.toml``.
    """
    if not config.username and not config.password:
        return None
    # Minimal cli.toml; hosted-pulp and pulp-cli both read this format.
    lines: list[str] = ["[cli]"]
    if config.base_url:
        lines.append(f'base_url = "{config.base_url}"')
        lines.append('api_root = "/api/pulp/"')
    if config.domain:
        lines.append(f'domain = "{config.domain}"')
    if config.username:
        # Escape embedded quotes defensively.
        u = config.username.replace('"', '\\"')
        lines.append(f'username = "{u}"')
    if config.password:
        p = config.password.replace('"', '\\"')
        lines.append(f'password = "{p}"')
    content = "\n".join(lines) + "\n"
    fd, path = tempfile.mkstemp(prefix="pulp-cli-", suffix=".toml")
    try:
        os.chmod(path, 0o600)
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    return Path(path)


def run_hosted_pulp(
    *cli_args: str,
    config: PulpConfig,
    dry_run: bool = False,
    verbose: int | bool = 0,
    wait: bool = False,
    wait_timeout: float | None = None,
    output: str = "json",
    timeout: float | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, object] | str:
    """Run the Pulp CLI (``hosted-pulp`` or compatible ``pulp``) binary.

    Credentials are protected via a temporary ``cli.toml`` (mode 0600)
    rather than ``--password`` on argv. ``XDG_CACHE_HOME`` is defaulted
    to ``/tmp/pulp-cli-cache`` when unset, matching
    calungaproject/plumbing#464 — production containers can run with
    ``HOME=/`` where pulp-glue would otherwise try to write to
    ``/.cache/squeezer``.

    Args:
        *cli_args: Curated subcommand and flags (e.g. ``python content upload``).
        config: Connection config (base_url, domain, tbr creds, timeouts).
        dry_run: Pass ``--dry-run`` and return raw text (not JSON).
        verbose: ``0``, ``1``, ``2`` or ``True`` → ``-v``/``-vv``.
        wait: Add ``--wait``/``--wait-timeout`` for async modify.
        wait_timeout: Override wait timeout in seconds.
        output: ``json`` (default) or ``json-compact`` etc.; ``""`` disables.
        timeout: HTTP timeout seconds (→ ``--timeout``).
        extra_env: Extra env vars for the subprocess.

    Returns:
        Parsed JSON dict when ``output`` is ``json``/``json-compact``,
        otherwise raw stdout string. For ``dry_run`` the raw DRY RUN text
        is returned even when ``output=json``.

    """
    global_flags = _global_args(
        config,
        dry_run=dry_run,
        verbose=verbose,
        wait=wait,
        wait_timeout=wait_timeout,
        timeout=timeout,
        output=output,
    )
    cmd = [PULP_BIN, *global_flags, *cli_args]

    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    # Writable default for pulp-glue OpenAPI cache (plumbing#464).
    # Fixed /tmp path is intentional: a per-invocation mkdtemp would
    # defeat cache reuse and leak dirs across CLI calls; the container
    # is single-tenant/ephemeral and the cache holds only the public
    # OpenAPI schema, not secrets.
    env.setdefault(
        "XDG_CACHE_HOME",
        "/tmp/pulp-cli-cache",  # nosec B108 - /tmp cache, not secrets
    )

    # Protect credentials: temp cli.toml not --password on argv (plumbing#457).
    pulp_cfg_path = _write_pulp_config(config)
    if pulp_cfg_path:
        # Both pulp-cli and hosted-pulp honor this env var / config path.
        env["PULP_CLI_CONFIG"] = str(pulp_cfg_path)
        # Some distributions also read XDG_CONFIG_HOME; keep HOME out of it.

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    finally:
        if pulp_cfg_path:
            try:
                pulp_cfg_path.unlink()
            except OSError:
                pass

    if result.returncode != 0:
        raise PulpError(
            result.stderr.strip() or result.stdout.strip() or "pulp CLI failed",
            status_code=result.returncode,
            response_body=(result.stdout or "") + (result.stderr or ""),
        )

    stdout = result.stdout.strip()
    if dry_run:
        return stdout

    if output in ("json", "json-compact"):
        if not stdout:
            return {}
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                return parsed
            # List output (e.g. list) → wrap
            return (
                {"results": parsed}
                if isinstance(parsed, list)
                else {"data": parsed}
            )
        except json.JSONDecodeError as e:
            raise PulpError(
                f"Failed to parse hosted-pulp JSON output: {e}",
                status_code=result.returncode,
                response_body=stdout,
            ) from e

    return stdout


def upload_python_content(
    file_path: Path,
    config: PulpConfig,
    sha256: str | None = None,
    pulp_labels: dict[str, str] | None = None,
    attestations: str | None = None,
    dry_run: bool = False,
    verbose: int | bool = 0,
) -> str:
    """Upload a Python distribution as orphan content.

    Args:
        file_path: Local wheel/sdist path.
        config: Pulp connection config.
        sha256: Optional SHA-256 hex digest; computed if omitted.
        pulp_labels: Optional labels dict (→ ``--pulp-labels`` JSON).
        attestations: Optional JSON list for PEP 740.
        dry_run: Dry-run mode (returns raw DRY RUN text, still validates).
        verbose: Verbosity for hosted-pulp.

    Returns:
        ``pulp_href`` of the created PythonPackageContent.

    Raises:
        PulpError: If the file is missing or the CLI fails.

    """
    if not file_path.exists():
        raise PulpError(
            f"File not found: {file_path}",
            status_code=0,
            response_body="",
        )

    # Compute sha256 if not provided (mirrors direct REST clients that
    # always send a digest for File uploads; Python upload makes it optional
    # but we populate it for reproducibility).
    effective_sha256 = sha256
    if effective_sha256 is None:
        from slan_cuan.utils.checksum import compute_checksum

        effective_sha256 = compute_checksum(file_path, "sha256")

    args: list[str] = [
        "python",
        "content",
        "upload",
        "--file",
        str(file_path),
    ]
    if effective_sha256:
        args.extend(["--sha256", effective_sha256])
    if pulp_labels:
        args.extend(["--pulp-labels", json.dumps(pulp_labels)])
    if attestations:
        args.extend(["--attestations", attestations])

    out = run_hosted_pulp(
        *args,
        config=config,
        dry_run=dry_run,
        verbose=verbose,
        wait=False,
        output="json",
    )
    if isinstance(out, str):
        # Dry-run path — no href to return; caller should handle preview.
        return out

    href = out.get("pulp_href") or out.get("pulpHref")
    if not isinstance(href, str) or not href:
        raise PulpError(
            "Python content upload returned no pulp_href",
            status_code=0,
            response_body=json.dumps(out),
        )
    return href


def modify_python_repository(
    repo_name: str,
    content_hrefs: list[str],
    config: PulpConfig,
    dry_run: bool = False,
    verbose: int | bool = 0,
    wait_timeout: float | None = None,
) -> dict[str, object]:
    """Add orphan content units to a Python repository (async, waited).

    Args:
        repo_name: Repository name (name-based lookup via hosted-pulp).
        content_hrefs: List of ``pulp_href`` to add.
        config: Pulp connection config.
        dry_run: Dry-run mode (returns DRY RUN text in ``{"dry_run": …}``).
        verbose: Verbosity for hosted-pulp.
        wait_timeout: Override ``--wait-timeout``.

    Returns:
        Modify result dict (task/repository_version) or ``{"dry_run": str}``
        when ``dry_run`` is true.

    Raises:
        PulpError: If no hrefs or the CLI fails.

    """
    if not content_hrefs:
        raise PulpError(
            "No content hrefs to add to repository",
            status_code=0,
            response_body="",
        )
    if not repo_name:
        raise PulpError(
            "Repository name is required",
            status_code=0,
            response_body="",
        )

    args: list[str] = [
        "python",
        "repository",
        "modify",
        "--name",
        repo_name,
    ]
    for href in content_hrefs:
        args.extend(["--add-content-units", href])

    out = run_hosted_pulp(
        *args,
        config=config,
        dry_run=dry_run,
        verbose=verbose,
        wait=True,
        wait_timeout=wait_timeout,
        output="json",
    )
    if isinstance(out, str):
        return {"dry_run": out}
    return out


def upload_file_content(
    file_path: Path,
    relative_path: str,
    sha256: str,
    config: PulpConfig,
    repository: str | None = None,
    dry_run: bool = False,
    verbose: int | bool = 0,
) -> str:
    """Upload a generic File content unit (for OSV/VEX future use).

    Args:
        file_path: Local file path.
        relative_path: ``relative_path`` in the File repo.
        sha256: SHA-256 hex digest (required for File).
        config: Pulp connection config.
        repository: Optional repo name to associate at create time.
        dry_run: Dry-run flag.
        verbose: Verbosity.

    Returns:
        ``pulp_href`` of the FileContent.

    """
    if not file_path.exists():
        raise PulpError(
            f"File not found: {file_path}",
            status_code=0,
            response_body="",
        )

    args: list[str] = [
        "file",
        "content",
        "upload",
        "--file",
        str(file_path),
        "--relative-path",
        relative_path,
    ]
    # The curated ``file content upload`` has no ``--sha256`` flag — the
    # checksum is derived server-side. Keep ``sha256`` in the signature for
    # API parity with ``PulpFileClient`` but do not forward it; when the CLI
    # gains the flag we can add it here. Tracked as a TODO on the caller.
    _ = sha256  # TODO(pulp-cli): forward when ``--sha256`` is supported
    if repository:
        args.extend(["--repository", repository])

    out = run_hosted_pulp(
        *args,
        config=config,
        dry_run=dry_run,
        verbose=verbose,
        wait=False,
        output="json",
    )
    if isinstance(out, str):
        return out
    href = out.get("pulp_href") or out.get("pulpHref")
    if not isinstance(href, str) or not href:
        raise PulpError(
            "File content upload returned no pulp_href",
            status_code=0,
            response_body=json.dumps(out),
        )
    return href


def modify_file_repository(
    repo_name: str,
    content_hrefs: list[str],
    config: PulpConfig,
    dry_run: bool = False,
    verbose: int | bool = 0,
    wait_timeout: float | None = None,
) -> dict[str, object]:
    """Add File content units to a File repository."""
    if not content_hrefs:
        raise PulpError(
            "No content hrefs to add to repository",
            status_code=0,
            response_body="",
        )
    args: list[str] = [
        "file",
        "repository",
        "modify",
        "--name",
        repo_name,
    ]
    for href in content_hrefs:
        args.extend(["--add-content-units", href])

    out = run_hosted_pulp(
        *args,
        config=config,
        dry_run=dry_run,
        verbose=verbose,
        wait=True,
        wait_timeout=wait_timeout,
        output="json",
    )
    if isinstance(out, str):
        return {"dry_run": out}
    return out
