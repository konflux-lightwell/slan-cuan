# Contributing

## Prerequisites

- Python >= 3.11
- [Poe the Poet](https://poethepoet.naber.io/) task runner (installed with dev extras)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Before Every Change

Run the full check suite before pushing:

```bash
poe check
```

This runs, in order:

1. **Lint** (`poe lint`) — Ruff linter checks (pycodestyle, pyflakes, isort, tidy-imports, debugger calls)
2. **Format** (`poe format-check`) — Ruff formatting verification
3. **Unit tests** (`poe test-unit`) — Pytest suite

All three must pass.

## Individual Tasks

| Task | Command | Description |
|---|---|---|
| Lint | `poe lint` | Check for lint violations |
| Format check | `poe format-check` | Verify formatting without changes |
| Format fix | `poe fmt` | Apply formatting |
| Auto-fix lint | `poe format-fix` | Fix lint violations where possible |
| Unit tests | `poe test-unit` | Run unit tests |

## Code Style

- **Line length**: 82 characters
- **Imports**: absolute only (no relative imports)
- **Formatter/linter**: Ruff — do not use Black, isort, or flake8 separately
- **Test files**: named `*_test.py`, placed side-by-side with the module they test
- **Docstrings**: every module, class, and public method must have a docstring (one-line when sufficient)

## CLI Development

See [docs/cli.md](docs/cli.md) for the CLI architecture,
global options, and environment variable conventions.

## Adding a New Subcommand

1. **Create the module** -- Add `slan_cuan/<name>.py` with a single `@click.command()` function. The module name must match the subcommand name. Use `@click.pass_obj` to receive the `GlobalContext`. Include a docstring for `--help` output.

2. **Register in cli.py** -- Import the command and call `main.add_command(<name>)` in `slan_cuan/cli.py`.

3. **Add tests** -- Create a test module following the `*_test.py` naming convention. Test both missing-required and happy-path invocations using Click's `CliRunner`.

4. **Environment variables** -- Automatic. The command's flags are recognized as `SLAN_CUAN_<SUBCOMMAND>_<FLAG>` with no additional configuration.

5. **Add documentation** -- Create `docs/<name>.md` following the structure of the existing subcommand docs. Link it from the subcommands table in [docs/cli.md](docs/cli.md#subcommands).

6. **Verify** -- Run `poe check`. All three checks (lint, format, unit tests) must pass.
