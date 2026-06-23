# Sign

Cryptographically sign Maven artifacts using RADAS (Red Hat Artifact Digital Authentication Service).

## What It Does

1. Submits the artifact repository to RADAS for bulk signing
2. Locates the signed result JSON produced by RADAS
3. Signs individual artifacts using the bulk-sign result and repository metadata
4. Cleans up temporary working files

The command delegates to `novabucks` workflows for the actual RADAS interaction. It orchestrates two sequential signing passes: a repository-level pass and an individual-artifact pass.

## Options

| Flag | Short | Type | Required | Default | Description |
|------|-------|------|----------|---------|-------------|
| `--repo-url` | `-u` | string | Yes | -- | Pullspec of the image containing the Maven repository |
| `--repo-path` | `-p` | string | Yes | -- | Directory or ZIP file with the downloaded Maven repository |
| `--signing-key` | `-k` | string | Yes | -- | The signing key name for RADAS |
| `--output-path` | `-o` | string | Yes | -- | Directory for signed output files |
| `--radas-config` | `-c` | path | Yes | -- | Path to the RADAS configuration file (JSON) |
| `--requester-id` | `-r` | string | No | `slan-cuan@redhat.com` | Requester identity for the signature |
| `--zip-root-path` | `-z` | string | No | `repository` | Root of the Maven repository tree inside the ZIP file |
| `--product-key` | `-b` | string | No | `slan-cuan` | Product key for metadata generation |
| `--ignore-patterns` | `-i` | string (multiple) | No | -- | Regex patterns to exclude files from signing |

The `--radas-config` flag also accepts the `RADAS_CONFIG_PATH` environment variable directly (not prefixed), for compatibility with shared RADAS tooling.

The `--ignore-patterns` flag can be repeated to specify multiple patterns:

```bash
slan-cuan sign ... \
    --ignore-patterns '.*-sources\.jar$' \
    --ignore-patterns '.*-javadoc\.jar$'
```

## Environment Variables

See [CLI Reference](cli.md#environment-variables) for naming conventions.

| Flag | Environment Variable |
|------|---------------------|
| `--repo-url` | `SLAN_CUAN_SIGN_REPO_URL` |
| `--repo-path` | `SLAN_CUAN_SIGN_REPO_PATH` |
| `--signing-key` | `SLAN_CUAN_SIGN_SIGNING_KEY` |
| `--output-path` | `SLAN_CUAN_SIGN_OUTPUT_PATH` |
| `--radas-config` | `RADAS_CONFIG_PATH` |
| `--requester-id` | `SLAN_CUAN_SIGN_REQUESTER_ID` |
| `--zip-root-path` | `SLAN_CUAN_SIGN_ZIP_ROOT_PATH` |
| `--product-key` | `SLAN_CUAN_SIGN_PRODUCT_KEY` |
| `--ignore-patterns` | `SLAN_CUAN_SIGN_IGNORE_PATTERNS` |

## External Dependencies

Requires the `novabucks` Python package, which provides the RADAS workflow implementations (`sign_in_radas_workflow`, `sign_individual_artifacts_workflow`) and logging setup.
