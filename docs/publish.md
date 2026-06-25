# Publish

Upload Maven artifacts to a Pulp repository for distribution via `packages.redhat.com`.

## What It Does

1. Reads `extract-result.json` from the artifact directory
2. Discovers Maven artifacts in the `repository/` tree
3. Parses Maven coordinates (group, artifact, version) from
   directory paths
4. Reads checksum sidecars (`.md5`, `.sha1`, `.sha256`)
5. Uploads each artifact to Pulp via REST API (`PUT`)
6. Saves `publish-result.json` with upload summary

The artifact directory must be the output of the `extract` stage, containing a valid `extract-result.json`.

## Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--pulp-url` | string | Yes | -- | Pulp instance base URL |
| `--pulp-repository` | string | Yes | -- | Maven distribution name |
| `--artifact-dir` | path | Yes | -- | Extract stage output directory |
| `--insecure` | flag | No | `False` | Disable TLS certificate verification |
| `--pulp-auth-type` | choice | No | `tbr` | Authentication method (`tbr` or `cert`) |
| `--pulp-username` | string | When `tbr` | -- | Username for TBR basic auth |
| `--pulp-password` | string | When `tbr` | -- | Password for TBR basic auth |
| `--pulp-client-cert` | path | When `cert` | -- | Client certificate for entitlement cert auth |
| `--pulp-client-key` | path | When `cert` | -- | Client key for entitlement cert auth |

The `--pulp-repository` is the Maven distribution name visible at `<pulp-url>/pulp/maven/<repository>/`.

The `--insecure` flag is intended for development only. In production, use the global `--ca-cert` option for custom certificate authorities.

## Environment Variables

See [CLI Reference](cli.md#environment-variables) for naming conventions.

| Flag | Environment Variable |
|------|---------------------|
| `--pulp-url` | `SLAN_CUAN_PUBLISH_PULP_URL` |
| `--pulp-repository` | `SLAN_CUAN_PUBLISH_PULP_REPOSITORY` |
| `--artifact-dir` | `SLAN_CUAN_PUBLISH_ARTIFACT_DIR` |
| `--insecure` | `SLAN_CUAN_PUBLISH_INSECURE` |
| `--pulp-auth-type` | `SLAN_CUAN_PUBLISH_PULP_AUTH_TYPE` |
| `--pulp-username` | `SLAN_CUAN_PUBLISH_PULP_USERNAME` |
| `--pulp-password` | `SLAN_CUAN_PUBLISH_PULP_PASSWORD` |
| `--pulp-client-cert` | `SLAN_CUAN_PUBLISH_PULP_CLIENT_CERT` |
| `--pulp-client-key` | `SLAN_CUAN_PUBLISH_PULP_CLIENT_KEY` |

## Authentication

The `publish` command supports two authentication methods for Pulp, selected by `--pulp-auth-type`.

### TBR Basic Auth (default)

TBR (Terms-Based Registry) uses HTTP Basic Authentication. Both `--pulp-username` and `--pulp-password` are required.

```bash
slan-cuan publish \
    --pulp-url https://pulp.example.com \
    --pulp-repository my-repo \
    --pulp-username "$PULP_USER" \
    --pulp-password "$PULP_PASS" \
    --artifact-dir /var/workdir/extracted
```

### Entitlement Certificate Auth

Entitlement certificate auth uses mTLS (mutual TLS). Both `--pulp-client-cert` and `--pulp-client-key` are required.

```bash
slan-cuan publish \
    --pulp-url https://pulp.example.com \
    --pulp-repository my-repo \
    --pulp-auth-type cert \
    --pulp-client-cert /certs/client/tls.crt \
    --pulp-client-key /certs/client/tls.key \
    --artifact-dir /var/workdir/extracted
```

## TLS Configuration

By default, TLS verification uses the system CA bundle. Two global options modify this behavior:

- `--ca-cert /path/to/ca.crt` — use a custom CA certificate bundle (e.g. for enterprise proxies or self-signed certificates)
- `--insecure` — disable TLS verification entirely (development only)

When both are set, `--insecure` takes precedence and `--ca-cert` is ignored.

Example with a custom CA:

```bash
slan-cuan --ca-cert /etc/ssl/certs/lan-ca.crt \
    publish --pulp-url https://rachael.home.lan ...
```

## Dry-Run Behavior

With `--dry-run`, loads the extract result and discovers artifacts but does not upload. Displays the authentication type, distribution name, Pulp URL, artifact count, coordinate count, and each artifact path that would be uploaded.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-publish`, defined at `tekton/tasks/slan-cuan-publish.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
