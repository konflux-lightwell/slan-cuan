# Extract

Pull artifacts from a PNC (Project Newcastle) container image and catalog them for downstream stages.

## What It Does

1. Parses and validates the OCI image reference
2. Fetches the OCI manifest for metadata extraction
3. Pulls all layers to the output directory using `oras`
4. Walks the extracted tree and catalogs file paths
5. Saves `extract-result.json` for downstream stages

The result manifest contains the image reference, manifest digest, layer metadata, annotations, and a full file listing. Downstream stages (e.g., `publish`) consume this file.

## Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--image` | string | Yes | -- | OCI image reference (tag or digest) |
| `--output-dir` | path | Yes | -- | Directory to extract artifacts to |
| `--registry-auth-file` | path | No | `None` | Registry authentication file |
| `--force` | flag | No | `False` | Overwrite existing output directory |

The `--image` flag accepts both tag-based (`registry/repo:tag`) and digest-based (`registry/repo@sha256:...`) references. Digest-based references are recommended for reproducibility.

The `--registry-auth-file` flag points to a container auth file (e.g., Docker's `config.json` or Podman's `auth.json`) for private registries.

Without `--force`, the command refuses to overwrite an existing output directory.

## Environment Variables

See [CLI Reference](cli.md#environment-variables) for naming conventions.

| Flag | Environment Variable |
|------|---------------------|
| `--image` | `SLAN_CUAN_EXTRACT_IMAGE` |
| `--output-dir` | `SLAN_CUAN_EXTRACT_OUTPUT_DIR` |
| `--registry-auth-file` | `SLAN_CUAN_EXTRACT_REGISTRY_AUTH_FILE` |
| `--force` | `SLAN_CUAN_EXTRACT_FORCE` |

## Output Directory Layout

```
<output-dir>/
  metadata/
    manifest.json
  <deliverable-name>/
    repository/
      <maven-layout>/
    cyclonedx.json
    provenance.json
  extract-result.json
```

The deliverable name comes from the OCI manifest's `org.opencontainers.image.title` annotation.

## External Dependencies

Requires `oras` (OCI Registry as Storage) on `$PATH` for pulling artifacts and fetching manifests.

## Dry-Run Behavior

With `--dry-run`, fetches the manifest but does not pull layers or create the output directory. Displays image metadata: reference, digest, layer count, total size, deliverable name, and annotations.
