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
