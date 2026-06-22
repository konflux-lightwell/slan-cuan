# slan-cuan

Release pipeline for Red Hat Lightwell's Java artifacts. Extracts artifacts from PNC container images, signs them, registers SBOMs and attestations, and publishes to Pulp for distribution via `packages.redhat.com`.

Packaged as a container image that provides both the Python CLI application and Tekton Task definitions for Konflux pipeline orchestration.

## Documentation

| Document | Purpose |
|----------|---------|
| [CLI Reference](docs/cli.md) | Global options, environment variables, architecture |
| [Extract](docs/extract.md) | Extract artifacts from PNC container images |
| [Publish](docs/publish.md) | Publish Maven artifacts to Pulp |
| [Contributing](CONTRIBUTING.md) | Development setup, code style, adding subcommands |
