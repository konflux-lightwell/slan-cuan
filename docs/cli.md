# CLI Reference

The `slan-cuan` command is the entry point for all pipeline stages. Each subcommand maps 1:1 to a pipeline stage and a Tekton Task.

## Architecture

Each subcommand lives in its own Python module under `slan_cuan/`. The module name matches the subcommand name. Registration happens in `cli.py` via `main.add_command()`.

This ensures each stage is independently testable and maintains a 1:1 correspondence between Python modules and Tekton Tasks.

See [Adding a New Subcommand](../CONTRIBUTING.md#adding-a-new-subcommand) for the developer workflow.

## Global Options

These options apply to all subcommands and are defined on the top-level group. All subcommands receive them via the shared `GlobalContext` object.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--verbose` | flag | `False` | Detailed progress and file listings |
| `--dry-run` | flag | `False` | Preview without side effects |
| `--ca-cert` | path | `None` | Custom CA certificate bundle for TLS |

**Dry-run mode** executes all read operations normally but skips writes, displaying what would happen instead.

## Environment Variables

The CLI uses Click's `auto_envvar_prefix` with prefix `SLAN_CUAN`. Every flag maps to an environment variable automatically.

**Naming rules:**

- Global flags: `SLAN_CUAN_<FLAG>`
- Subcommand flags: `SLAN_CUAN_<SUBCOMMAND>_<FLAG>`

Hyphens in flag names become underscores. CLI flags always override environment variables when both are set.

| Flag | Environment Variable |
|------|---------------------|
| `--verbose` | `SLAN_CUAN_VERBOSE` |
| `--dry-run` | `SLAN_CUAN_DRY_RUN` |
| `--ca-cert` | `SLAN_CUAN_CA_CERT` |

Subcommand-specific variables are documented in each subcommand's reference page.

## Subcommands

| Subcommand | Stage | Description |
|------------|-------|-------------|
| [extract](extract.md) | Extract | Pull artifacts from PNC container images |
| [publish](publish.md) | Publish | Upload Maven artifacts to Pulp |
