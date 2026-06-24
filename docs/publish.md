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

With `--dry-run`, loads the extract result and discovers artifacts but does not upload. Displays the distribution name, Pulp URL, artifact count, coordinate count, and each artifact path that would be uploaded.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-publish`, defined at `tekton/tasks/slan-cuan-publish.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
