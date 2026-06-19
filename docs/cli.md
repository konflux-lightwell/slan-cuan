# CLI Documentation

## Running the CLI

Install the package in editable mode with development dependencies:

```bash
pip install -e '.[dev]'
```

The installation registers the `slan-cuan` command. View available options:

```bash
slan-cuan --help
slan-cuan extract --help
```

## Subcommand-per-Module Pattern

The CLI architecture follows a one-to-one mapping: each subcommand is defined
in a single Python module with a single `@click.command()` function. The
module name matches the subcommand name exactly.

**Registration:**

1. Subcommand modules live in `slan_cuan/`
2. Each module exports a Click command decorated with `@click.command()`
3. Each command receives global context via `@click.pass_obj`
4. `cli.py` registers subcommands with `main.add_command()`

**Example:**

```python
# slan_cuan/extract.py
import click
from slan_cuan.context import GlobalContext

@click.command()
@click.option(
    "--image",
    required=True,
    type=str,
    help="Container image reference to extract artifacts from.",
)
@click.pass_obj
def extract(ctx: GlobalContext, image: str) -> None:
    """Extract artifacts from a PNC container image."""
    click.echo(f"extract: image={image}")
```

```python
# slan_cuan/cli.py
from slan_cuan.extract import extract

main.add_command(extract)
```

This pattern ensures:
- Each subcommand is independently testable
- Subcommand logic is isolated from CLI wiring
- 1:1 correspondence between Python modules and Tekton Tasks

## Environment Variable Convention

The CLI uses Click's `auto_envvar_prefix` to automatically map CLI flags to
environment variables. The prefix is `SLAN_CUAN`.

**Naming:**

- **Global flags:** `SLAN_CUAN_<FLAG>`
- **Subcommand flags:** `SLAN_CUAN_<SUBCOMMAND>_<FLAG>`

**Examples:**

| CLI Flag | Environment Variable |
|----------|---------------------|
| `--verbose` | `SLAN_CUAN_VERBOSE` |
| `--dry-run` | `SLAN_CUAN_DRY_RUN` |
| `extract --image` | `SLAN_CUAN_EXTRACT_IMAGE` |

**Precedence:** CLI flags always override environment variables.

**Implementation:**

```python
@click.group(context_settings={"auto_envvar_prefix": "SLAN_CUAN"})
```

This applies to the group and all subcommands. Subcommands inherit the prefix
automatically.

## Current Subcommands

| Subcommand | Options | Environment Variable | Description |
|------------|---------|---------------------|-------------|
| `extract` | `--image` (required) | `SLAN_CUAN_EXTRACT_IMAGE` | Extract artifacts from PNC container image |

**Global options (all subcommands):**

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `--verbose` | `SLAN_CUAN_VERBOSE` | Enable verbose output |
| `--dry-run` | `SLAN_CUAN_DRY_RUN` | Perform dry run without changes |

## Adding a New Subcommand

Follow these steps to add a new subcommand:

### 1. Create the subcommand module

Create `slan_cuan/<name>.py` with the command function:

```python
import click
from slan_cuan.context import GlobalContext


@click.command()
@click.option(
    "--required-flag",
    required=True,
    type=str,
    help="Example required option.",
)
@click.pass_obj
def my_command(ctx: GlobalContext, required_flag: str) -> None:
    """Short description of the command."""
    click.echo(f"my_command: flag={required_flag}")
```

**Requirements:**
- Module name must match subcommand name
- Use `@click.pass_obj` to receive `GlobalContext`
- Include a docstring for `--help` output
- Follow the 82-character line length limit

### 2. Register in cli.py

Import and register the command in `slan_cuan/cli.py`:

```python
from slan_cuan.my_command import my_command

# After the main() function definition:
main.add_command(my_command)
```

### 3. Add tests

Create tests in `tests/cli_test.py` or a dedicated test module:

```python
import pytest
from click.testing import CliRunner
from slan_cuan.cli import main


def test_my_command_requires_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["my_command"])
    assert result.exit_code != 0
    assert "required" in result.output.lower()


def test_my_command_with_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["my_command", "--required-flag", "value"])
    assert result.exit_code == 0
    assert "my_command: flag=value" in result.output
```

### 4. Environment variables

Environment variable support is automatic. The command above will
automatically recognize `SLAN_CUAN_MY_COMMAND_REQUIRED_FLAG`.

Test it:

```bash
export SLAN_CUAN_MY_COMMAND_REQUIRED_FLAG=value
slan-cuan my_command
# Equivalent to: slan-cuan my_command --required-flag value
```

### 5. Verify

Run the check suite:

```bash
poe check
```

All three checks (lint, format, unit tests) must pass.
