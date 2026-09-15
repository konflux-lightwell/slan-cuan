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
| `--requester-id` | `-r` | string | Yes | -- | Requester identity for the signature |
| `--zip-root-path` | `-z` | string | No | `repository` | Root of the Maven repository tree inside the ZIP file |
| `--product-key` | `-b` | string | No | `slan-cuan` | Product key for metadata generation |
| `--ignore-patterns` | `-i` | string (multiple) | No | -- | Regex patterns to exclude files from signing |
| `--registry-auth-file` | -- | path | No | -- | Path to a container registry authentication file |
| `--direct-sign` | -- | flag | No | `True` | Sign directly via the `middleware-signing` internal-request pipeline (the only supported mode; see [Direct Signing](#direct-signing)) |
| `--direct-sign-pipeline-name` | -- | string | No | `middleware-signing` | Internal-request pipeline name for direct signing |
| `--direct-sign-task-git-url` | -- | string | No | `https://gitlab.cee.redhat.com/signing/signing.git` | Git URL of the signing task repo |
| `--direct-sign-task-git-revision` | -- | string | No | `main` | Git revision (branch/tag/SHA) of the signing task repo |
| `--direct-sign-verbose` | -- | flag | No | `false` | Enable verbose Kerberos diagnostics for direct signing |
| `--direct-sign-task-ta-storage` | -- | string | No | -- | `ociStorage` for the trusted artifact passed to the internal task |
| `--direct-sign-task-ta-source-artifact` | -- | string | No | -- | `sourceDataArtifact` pullspec for the trusted artifact passed to the internal task |
| `--direct-sign-task-ta-source-artifact-file` | -- | path | No | -- | File containing the `sourceDataArtifact` pullspec; takes precedence over `--direct-sign-task-ta-source-artifact` when set |
| `--intention` | -- | string | No | `production` | Intention label applied to the direct-sign internal request |

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
| `--direct-sign` | `SLAN_CUAN_SIGN_DIRECT_SIGN` |
| `--direct-sign-pipeline-name` | `SLAN_CUAN_SIGN_DIRECT_SIGN_PIPELINE_NAME` |
| `--direct-sign-task-git-url` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_GIT_URL` |
| `--direct-sign-task-git-revision` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_GIT_REVISION` |
| `--direct-sign-verbose` | `SLAN_CUAN_SIGN_DIRECT_SIGN_VERBOSE` |
| `--direct-sign-task-ta-storage` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_STORAGE` |
| `--direct-sign-task-ta-source-artifact` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_SOURCE_ARTIFACT` |
| `--direct-sign-task-ta-source-artifact-file` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_SOURCE_ARTIFACT_FILE` |
| `--intention` | `SLAN_CUAN_SIGN_INTENTION` |

When set via environment variable, `SLAN_CUAN_SIGN_IGNORE_PATTERNS` accepts comma-separated values:

```bash
SLAN_CUAN_SIGN_IGNORE_PATTERNS=".*-sources\.jar$,.*-javadoc\.jar$"
```

## Direct Signing

Signing runs through the `middleware-signing` internal-request pipeline. This
path takes a small input: only the repository ZIP is handed to the internal
task as its own trusted artifact, keeping the signing pod's ephemeral storage
footprint down. It is the only supported signing mode — the former RADAS/UMB
broker path has been removed, and `--direct-sign` defaults to enabled.

The reduced trusted artifact's `sourceDataArtifact` pullspec is produced by an
earlier pipeline step and written to a file. Rather than splicing that pullspec
in with inline shell, point the CLI at the file with
`--direct-sign-task-ta-source-artifact-file` (env
`SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_SOURCE_ARTIFACT_FILE`); its contents take
precedence over `--direct-sign-task-ta-source-artifact`. An empty or unreadable
file is a usage error rather than a silently-empty pullspec.

The internal-request task itself is git-resolved per request from
`--direct-sign-task-git-url` at `--direct-sign-task-git-revision`.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-sign`, defined at `tekton/tasks/slan-cuan-sign.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
