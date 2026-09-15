# Sign

Cryptographically sign Maven artifacts using Konflux direct signing (`middleware-signing` pipeline).

## What It Does

1. Submits an `InternalRequest` to trigger the `middleware-signing` pipeline for direct artifact signing.
2. Fetches the signed results and trusted artifact blob containing detached signatures.
3. Signs individual artifacts natively by unpacking archives, placing detached `.asc` signatures alongside each artifact, and generating/refreshing `maven-metadata.xml` with `.md5`, `.sha1`, and `.sha256` checksum sidecars.
4. Cleans up temporary working files and copies signed repository artifacts into the target output directory.

## Options

| Flag | Short | Type | Required | Default | Description |
|------|-------|------|----------|---------|-------------|
| `--repo-url` | `-u` | string | Yes | -- | Pullspec of the image containing the Maven repository |
| `--repo-path` | `-p` | string | Yes | -- | Directory or ZIP file with the downloaded Maven repository |
| `--signing-key` | `-k` | string | Yes | -- | The signing key name |
| `--output-path` | `-o` | string | Yes | -- | Directory for signed output files |
| `--requester-id` | `-r` | string | No | `slan-cuan@redhat.com` | Requester identity for the signature |
| `--zip-root-path` | `-z` | string | No | `repository` | Root of the Maven repository tree inside the ZIP file |
| `--product-key` | `-b` | string | No | `slan-cuan` | Product key for metadata generation |
| `--ignore-patterns` | `-i` | string (multiple) | No | -- | Regex patterns to exclude files from signing |
| `--registry-auth-file` | -- | path | No | -- | Path to container registry authentication file |
| `--direct-sign` | -- | flag | No | `True` | Direct signing via InternalRequest (default: True) |
| `--direct-sign-pipeline-name` | -- | string | No | `middleware-signing` | Pipeline name for direct signing |
| `--direct-sign-task-git-url` | -- | string | No | `https://gitlab.cee.redhat.com/signing/signing.git` | Git URL for direct signing task |
| `--direct-sign-task-git-revision` | -- | string | No | `main` | Git revision for direct signing task |
| `--direct-sign-task-ta-storage` | -- | string | No | `""` | OCI storage for trusted artifact transfer |
| `--direct-sign-task-ta-source-artifact` | -- | string | No | `""` | Source artifact pullspec for direct signing |
| `--intention` | -- | string | No | `production` | Signing intention label |

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
| `--requester-id` | `SLAN_CUAN_SIGN_REQUESTER_ID` |
| `--zip-root-path` | `SLAN_CUAN_SIGN_ZIP_ROOT_PATH` |
| `--product-key` | `SLAN_CUAN_SIGN_PRODUCT_KEY` |
| `--ignore-patterns` | `SLAN_CUAN_SIGN_IGNORE_PATTERNS` |
| `--registry-auth-file` | `SLAN_CUAN_SIGN_REGISTRY_AUTH_FILE` |

When set via environment variable, `SLAN_CUAN_SIGN_IGNORE_PATTERNS` accepts comma-separated values:

```bash
SLAN_CUAN_SIGN_IGNORE_PATTERNS=".*-sources\.jar$,.*-javadoc\.jar$"
```

## Tekton Task

The corresponding Tekton Task is `slan-cuan-sign`, defined at `tekton/tasks/slan-cuan-sign.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
