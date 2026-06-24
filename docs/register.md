# Register

Upload CycloneDX SBOMs to Trustify for vulnerability cross-referencing.

## What It Does

1. Reads `extract-result.json` from the artifact directory
2. Locates the CycloneDX SBOM (`cyclonedx.json`) in the deliverable
3. Authenticates with Red Hat SSO via OIDC client credentials
4. Uploads the SBOM to Trustify via REST API (`POST /api/v2/sbom`)
5. Saves `register-result.json` with the SBOM URN

The artifact directory must be the output of the `extract` stage, containing a valid `extract-result.json`.

## Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--trustify-api-url` | string | Yes | -- | Trustify instance API URL |
| `--sso-token-url` | string | Yes | -- | OIDC token endpoint URL for OIDC authentication |
| `--sso-client-id` | string | Yes | -- | OIDC client ID |
| `--sso-client-secret` | string | Yes | -- | OIDC client secret |
| `--artifact-dir` | path | Yes | -- | Extract stage output directory |
| `--insecure` | flag | No | `False` | Disable TLS certificate verification |
| `--retries` | int | No | `3` | Retry attempts for transient errors |

The `--insecure` flag is intended for development only. In production, use the global `--ca-cert` option for custom certificate authorities.

## Environment Variables

See [CLI Reference](cli.md#environment-variables) for naming conventions.

| Flag | Environment Variable |
|------|---------------------|
| `--trustify-api-url` | `SLAN_CUAN_REGISTER_TRUSTIFY_API_URL` |
| `--sso-token-url` | `SLAN_CUAN_REGISTER_SSO_TOKEN_URL` |
| `--sso-client-id` | `SLAN_CUAN_REGISTER_SSO_CLIENT_ID` |
| `--sso-client-secret` | `SLAN_CUAN_REGISTER_SSO_CLIENT_SECRET` |
| `--artifact-dir` | `SLAN_CUAN_REGISTER_ARTIFACT_DIR` |
| `--insecure` | `SLAN_CUAN_REGISTER_INSECURE` |
| `--retries` | `SLAN_CUAN_REGISTER_RETRIES` |

## TLS Configuration

By default, TLS verification uses the system CA bundle. Two global options modify this behavior:

- `--ca-cert /path/to/ca.crt` — use a custom CA certificate bundle (e.g. for enterprise proxies or self-signed certificates)
- `--insecure` — disable TLS verification entirely (development only)

When both are set, `--insecure` takes precedence and `--ca-cert` is ignored.

Example with a custom CA:

```bash
slan-cuan --ca-cert /etc/ssl/certs/lan-ca.crt \
    register --trustify-api-url https://trustify.example.com ...
```

## Retry Behavior

Transient HTTP errors (408, 429, 500, 502, 503, 504) and network errors are retried with exponential backoff. The `--retries` flag controls the maximum number of attempts (default: 3). Non-transient errors (400, 401, 403, 404) fail immediately.

## Dry-Run Behavior

With `--dry-run`, loads the extract result and locates the SBOM but does not make any HTTP requests. Displays the Trustify API URL, OIDC token endpoint URL, SBOM file path, and file size.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-register`, defined at `tekton/tasks/slan-cuan-register.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
