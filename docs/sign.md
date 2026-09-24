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
| `--radas-umb-host` | -- | string | Yes | -- | Host of the RADAS UMB service |
| `--radas-result-queue` | -- | string | Yes | -- | Result queue name for RADAS |
| `--radas-request-channel` | -- | string | Yes | -- | Request channel name for RADAS |
| `--radas-client-ca` | -- | string | Yes | -- | Path to the RADAS client CA certificate |
| `--radas-client-key` | -- | string | Yes | -- | Path to the RADAS client key |
| `--radas-client-key-pass-file` | -- | string | Yes | -- | Path to the file containing the RADAS client key password |
| `--radas-root-ca` | -- | string | Yes | -- | Path to the RADAS root CA certificate |
| `--radas-receiver-timeout` | -- | int | No | `3600` | Timeout for the RADAS receiver (seconds) |
| `--requester-id` | `-r` | string | Yes | -- | Requester identity for the signature |
| `--zip-root-path` | `-z` | string | No | `repository` | Root of the Maven repository tree inside the ZIP file |
| `--product-key` | `-b` | string | No | `slan-cuan` | Product key for metadata generation |
| `--ignore-patterns` | `-i` | string (multiple) | No | -- | Regex patterns to exclude files from signing |
| `--registry-auth-file` | -- | path | No | -- | Path to a container registry authentication file |
| `--direct-sign` | -- | flag | No | `false` | Sign directly via the internal-request pipeline instead of RADAS (see [Direct Signing](#direct-signing)) |
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
| `--radas-umb-host` | `SLAN_CUAN_RADAS_UMB_HOST` |
| `--radas-result-queue` | `SLAN_CUAN_RADAS_RESULT_QUEUE` |
| `--radas-request-channel` | `SLAN_CUAN_RADAS_REQUEST_CHANNEL` |
| `--radas-client-ca` | `SLAN_CUAN_RADAS_CLIENT_CA` |
| `--radas-client-key` | `SLAN_CUAN_RADAS_CLIENT_KEY` |
| `--radas-client-key-pass-file` | `SLAN_CUAN_RADAS_CLIENT_KEY_PASS_FILE` |
| `--radas-root-ca` | `SLAN_CUAN_RADAS_ROOT_CA` |
| `--radas-receiver-timeout` | `SLAN_CUAN_RADAS_RECEIVER_TIMEOUT` |
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

When `--direct-sign` is set, the command bypasses RADAS and signs the repository
through the `middleware-signing` internal-request pipeline instead. This path
takes a much smaller input than the full RADAS flow: only the repository ZIP is
handed to the internal task as its own trusted artifact, keeping the signing
pod's ephemeral storage footprint down.

The reduced trusted artifact's `sourceDataArtifact` pullspec is produced by an
earlier pipeline step and written to a file. Rather than splicing that pullspec
in with inline shell, point the CLI at the file with
`--direct-sign-task-ta-source-artifact-file` (env
`SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_SOURCE_ARTIFACT_FILE`); its contents take
precedence over `--direct-sign-task-ta-source-artifact`. An empty or unreadable
file is a usage error rather than a silently-empty pullspec.

The internal-request task itself is git-resolved per request from
`--direct-sign-task-git-url` at `--direct-sign-task-git-revision`.

## External Dependencies

Requires the `novabucks` Python package, which provides the RADAS workflow implementations (`sign_in_radas_workflow`, `sign_individual_artifacts_workflow`) and logging setup.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-sign`, defined at `tekton/tasks/slan-cuan-sign.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
