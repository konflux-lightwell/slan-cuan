# Roadmap

## Foundation

- [x] Bootstrap `pyproject.toml` with project metadata and dependencies
- [x] Python Click CLI skeleton with top-level `slan-cuan` group
- [x] `CONTRIBUTING.md` with development workflow and coding standards
- [ ] `README.md` map-of-content index

## Pipeline Stages (Subcommands)

Each subcommand maps 1:1 to a Tekton Task.

- [ ] `extract` -- Pull artifacts from the PNC-produced container image
- [ ] `identify` -- Determine Maven coordinates (GAV), components, and metadata
- [ ] `sign` -- Cryptographically sign artifacts
- [ ] `register` -- Upload SBOMs and attestations to Trustify (TPA)
- [ ] `publish` -- Push signed artifacts to Pulp for `packages.redhat.com` distribution

## Packaging

- [ ] Containerfile producing the dual-purpose image (Python app + Tekton Task YAML)
- [ ] Tekton Task definitions for each subcommand
- [ ] Konflux pipeline integration (Trusted Artifacts, bundle-referenced Tasks)
