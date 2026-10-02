# slan-cuan Integrity Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `tests/integrity/` suite to `slan-cuan` that generically verifies the CLI's contract with the `slan-cuan-release` Tekton pipeline (subcommand names, env-var-to-option wiring, on-disk output paths, Tekton results) and, via a vendored fixture, with the Pipeline wiring defined in `release-service-catalog` — so a future internal refactor can't silently break what either repo relies on.

**Architecture:** Five pytest files under `tests/integrity/`, each testing one contract layer, all driven generically off the real `tekton/tasks/*.yaml` files and the real `slan_cuan.cli.main` click object rather than hand-enumerated expectations. A shared `_yaml_helpers.py` centralizes YAML loading, click-context construction, and AST-based result-name extraction. Layer E additionally uses a pinned, vendored copy of `release-service-catalog`'s pipeline YAML, kept honest by a separate non-blocking weekly freshness check. Two pre-existing dead-wiring bugs discovered during planning (one in each repo) are fixed first so the new suite starts from a clean, fully-passing baseline.

**Tech Stack:** Python 3.11+, pytest, click 8.4 (already a dependency), PyYAML (new dev dependency), stdlib `ast`/`inspect`/`urllib.request`.

**Spec:** `docs/superpowers/specs/2026-10-02-slan-cuan-integrity-tests-design.md`

## Global Constraints

- `slan-cuan` test files must match `tests/**/*_test.py` (pytest `python_files = ["*_test.py"]` in `pyproject.toml`) — never `test_*.py`.
- `slan-cuan` ruff config: `line-length = 82`, lint rules include `D` (docstrings required on every module/function/class) — every new `.py` file needs a module docstring and every `def` needs at least a one-line docstring.
- Before every `slan-cuan` commit: run `ruff check --fix . && ruff format .`, then verify with `ruff check . && ruff format --check .` (per `slan-cuan/CLAUDE.md`).
- `slan-cuan`'s click group sets `auto_envvar_prefix = "SLAN_CUAN"` via `context_settings` on `slan_cuan.cli.main` — never hardcode this string in new test code; read it from `cli_main.context_settings["auto_envvar_prefix"]`.
- All `slan-cuan` work for this plan happens on branch `docs/LWLP-2376-integrity-tests-design` (already pushed, currently holding only the spec commit).
- `release-service-catalog` conventions (for Task 1 only): main branch is `development`, not `main`; commits are conventional with a Jira-ticket scope (`fix(LWLP-2376): ...`); **every commit needs DCO signoff** (`git commit -s`); it is GitHub-hosted (`origin` = `https://github.com/konflux-lightwell/release-service-catalog.git`) — use `gh`, not `glab`, for any PR; README files under `pipelines/` are generated — after editing `spec.params`, regenerate with `.github/scripts/readme_generator.sh pipelines/managed/slan-cuan-release`.
- Per this workspace's standing rule: never create a merge/pull request without asking the user first, even mid-plan. Pushing a branch is fine; opening the PR/MR is a separate, explicit confirmation.
- Per this workspace's standing rule: never approve a merge/pull request without asking first.

## Review Focus

- **`env:` entries using `valueFrom: secretKeyRef` instead of `value`** — `register.yaml` (`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`) and `publish.yaml` (`PULP_USERNAME`, `PULP_PASSWORD`) both have env entries with no `value` key at all. Env-name extraction must read only `env["name"]`, never assume a `value` key exists, or it will crash with `KeyError` on exactly these two real files. Pinned in Task 4's parametrized test (all 6 files, including these two).
- **A Task's `run` step `args:` list has a leading global flag before the subcommand** — `sign`, `publish`, `generate-security-metadata`, and `generate-security-metadata-from-snapshot` all use `args: [--verbose, <subcommand>]`, while `extract` and `register` use `args: [<subcommand>]` alone. Subcommand extraction must take the *last* element, not the first. Pinned by parametrizing over all 6 real files (both shapes are present).
- **AST result-name extraction must be scoped per-function, not per-module** — `generate_security_metadata.py` hosts two commands (`generate_security_metadata` and `generate_security_metadata_from_snapshot`). A naive whole-module AST scan would merge both commands' `write_tekton_result` calls. Pinned explicitly in Task 6 by asserting the extracted source for one command's callback does not contain the sibling function's `def` line.
- **Required-option detection must not misfire on boolean flags** — options like `extract`'s `--force` (`is_flag=True, default=False`) must never be treated as "required with no env var wired," even though `is_flag` options have no `required=True` set explicitly. Pinned in Task 4 by asserting `--force` does *not* appear in the "missing required env var" failure list for `extract`.
- **Layer E must correctly skip non-`slan-cuan` pipeline tasks** — the vendored pipeline fixture has 9 `tasks[]` entries, only 4 of which (`extract`, `sign`, `generate-security-metadata`, `publish`) reference a local `tekton/tasks/*.yaml` file; the other 5 (`collect-data`, `collect-task-params`, `collect-snapshot-params`, `extract-requester-from-release`, `verify-conforma`) use an entirely different `taskRef` shape (different `url`, no `tekton/tasks/` path). Task-matching must filter on `pathInRepo` starting with `tekton/tasks/`, not assume every pipeline task maps to a local file. Pinned in Task 7 by asserting exactly 4 tasks are checked, by name.

---

## Task 1: Fix dead `RADAS_UMB_HOST` wiring in `release-service-catalog` (prerequisite, separate repo)

**Context:** `release-service-catalog`'s `slan-cuan-release.yaml` pipeline passes `RADAS_UMB_HOST` to the `sign` task, but `slan-cuan`'s own `tekton/tasks/slan-cuan-sign.yaml` declares no such param (confirmed by reading both files in full — `sign.py` has no RADAS/UMB-related option at all; signing is now done exclusively via `DIRECT_SIGN`, hardcoded `"true"` in this pipeline). This is leftover wiring from before direct-sign became the default path. It must be fixed before vendoring the pipeline fixture in Task 7, or Layer E's test would fail on day one against real content it has no way to fix from the `slan-cuan` side.

**Files:**
- Modify (in `release-service-catalog`, **not** `slan-cuan`): `pipelines/managed/slan-cuan-release/slan-cuan-release.yaml:108-112` (remove the now-fully-unused top-level `radas-umb-host` param) and `:438-439` (remove the `RADAS_UMB_HOST` entry from the `sign` task's `params:` list)
- Auto-regenerate: `pipelines/managed/slan-cuan-release/README.md`

**Interfaces:**
- Produces: a corrected `slan-cuan-release.yaml` with no `radas-umb-host`/`RADAS_UMB_HOST` references anywhere, which Task 7 vendors a copy of.

- [ ] **Step 1: Create a branch in `release-service-catalog`**

```bash
cd /home/jgangi/Documents/RedHat/exd-sp/lightwell/release-service-catalog
git fetch origin development
git checkout -b fix/LWLP-2376-remove-dead-radas-umb-host-param origin/development
```

- [ ] **Step 2: Remove the dead top-level pipeline param**

Open `pipelines/managed/slan-cuan-release/slan-cuan-release.yaml`. Delete these 5 lines (currently 108-112):

```yaml
    - name: radas-umb-host
      description: |
        RADAS UMB host
      type: string
      default: "umb.api.redhat.com"
```

- [ ] **Step 3: Remove the dead `RADAS_UMB_HOST` task param**

In the same file, in the `sign` task's `params:` list, delete these 2 lines (currently 438-439):

```yaml
        - name: RADAS_UMB_HOST
          value: $(params.radas-umb-host)
```

- [ ] **Step 4: Confirm no other references remain**

Run: `grep -rn "radas-umb-host\|RADAS_UMB_HOST" pipelines/managed/slan-cuan-release/slan-cuan-release.yaml`
Expected: no output (empty).

- [ ] **Step 5: Regenerate the pipeline README**

```bash
./.github/scripts/readme_generator.sh pipelines/managed/slan-cuan-release
git diff pipelines/managed/slan-cuan-release/README.md
```
Expected: the diff removes the `radas-umb-host` row from the generated params table and nothing else changes unexpectedly.

- [ ] **Step 6: Run repo validation**

```bash
yamllint pipelines/managed/slan-cuan-release/slan-cuan-release.yaml
```
Expected: no errors.

- [ ] **Step 7: Commit with DCO signoff**

```bash
git add pipelines/managed/slan-cuan-release/slan-cuan-release.yaml pipelines/managed/slan-cuan-release/README.md
git commit -s -m "fix(LWLP-2376): remove dead RADAS_UMB_HOST wiring from slan-cuan-release

The sign task's own Task definition (slan-cuan/tekton/tasks/slan-cuan-sign.yaml)
has never declared a RADAS_UMB_HOST param, and slan-cuan's sign command has no
RADAS/UMB-related option -- signing goes exclusively through DIRECT_SIGN
(hardcoded true in this pipeline). This param and its wiring are leftover from
before direct-sign became the only signing path."
```

- [ ] **Step 8: Push the branch**

```bash
git push -u origin fix/LWLP-2376-remove-dead-radas-umb-host-param
```

- [ ] **Step 9: Ask the user before opening the PR**

Stop here and ask the user to confirm before running `gh pr create`. Do not proceed to open the PR without explicit confirmation, per this workspace's standing rule.

Once confirmed:
```bash
gh pr create --repo konflux-lightwell/release-service-catalog --base development \
  --title "fix(LWLP-2376): remove dead RADAS_UMB_HOST wiring from slan-cuan-release" \
  --body "Removes a param the sign Task never declared and slan-cuan's sign command has no option for -- leftover from before DIRECT_SIGN became the only signing path. Discovered while building cross-repo contract tests for slan-cuan (LWLP-2376)."
```

Record the branch name and PR URL — Task 7 vendors the fixture from this branch's content (the PR does not need to be merged yet for Task 7 to proceed, since Task 7 copies the file content directly).

---

## Task 2: Fix dead `SLAN_CUAN_PULP_USERNAME`/`PASSWORD` env vars in `slan-cuan`

**Context:** `tekton/tasks/slan-cuan-publish.yaml` sets both `SLAN_CUAN_PULP_USERNAME`/`SLAN_CUAN_PULP_PASSWORD` (via `value: $(params.PULP_USERNAME)`) and `SLAN_CUAN_PUBLISH_PULP_USERNAME`/`SLAN_CUAN_PUBLISH_PULP_PASSWORD` (via `valueFrom: secretKeyRef`). `publish.py`'s `--pulp-username`/`--pulp-password` options have no explicit `envvar=` override, so click's real auto-envvar name for them (subcommand prefix `SLAN_CUAN_PUBLISH_`) only matches the second pair. The first pair is dead: verified via `grep -rn "SLAN_CUAN_PULP_USERNAME\|SLAN_CUAN_PULP_PASSWORD"` across the whole repo — it appears nowhere else. Must be removed before Task 4's Layer A/B test can pass cleanly against `publish`.

**Files:**
- Modify: `tekton/tasks/slan-cuan-publish.yaml:944-947`

**Interfaces:**
- Produces: a `slan-cuan-publish.yaml` where every `SLAN_CUAN_*` env var in the `run` step resolves to a real `publish` or group-level option.

- [ ] **Step 1: Remove the dead env entries**

In `tekton/tasks/slan-cuan-publish.yaml`, in the `run` step's `env:` list, delete these 4 lines (currently 944-947):

```yaml
        - name: SLAN_CUAN_PULP_USERNAME
          value: $(params.PULP_USERNAME)
        - name: SLAN_CUAN_PULP_PASSWORD
          value: $(params.PULP_PASSWORD)
```

- [ ] **Step 2: Confirm the real credential wiring is untouched**

Run: `grep -n "SLAN_CUAN_PUBLISH_PULP_USERNAME\|SLAN_CUAN_PUBLISH_PULP_PASSWORD" tekton/tasks/slan-cuan-publish.yaml`
Expected: both still present, each with a `valueFrom.secretKeyRef` block (the real, correctly-wired credential source).

- [ ] **Step 3: Confirm no other references to the removed names exist**

Run: `grep -rn "SLAN_CUAN_PULP_USERNAME\|SLAN_CUAN_PULP_PASSWORD" .`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add tekton/tasks/slan-cuan-publish.yaml
git commit -m "fix(LWLP-2376): remove dead SLAN_CUAN_PULP_USERNAME/PASSWORD wiring

publish.py's --pulp-username/--pulp-password options have no explicit
envvar= override, so click's auto-envvar name for them (subcommand prefix
SLAN_CUAN_PUBLISH_) only ever matched SLAN_CUAN_PUBLISH_PULP_USERNAME/PASSWORD,
which this file already sets correctly via secretKeyRef a few lines down.
SLAN_CUAN_PULP_USERNAME/PASSWORD (no PUBLISH_ segment) matched no option and
was silently ignored -- dead wiring, confirmed unreferenced anywhere else.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: Add `pyyaml` dev dependency

**Files:**
- Modify: `pyproject.toml` (`[project.optional-dependencies]` `dev` list)
- Modify: `tox.ini` (`[testenv]` `deps` list)

**Interfaces:**
- Produces: `yaml` importable in the `py311` tox environment and via `pip install -e ".[dev]"`.

- [ ] **Step 1: Add to `pyproject.toml`**

In `pyproject.toml`, change:
```toml
dev = ["ruff", "pytest", "poethepoet"]
```
to:
```toml
dev = ["ruff", "pytest", "poethepoet", "pyyaml"]
```

- [ ] **Step 2: Add to `tox.ini`**

In `tox.ini`, change:
```ini
[testenv]
deps =
    .
    pytest>=7.0
```
to:
```ini
[testenv]
deps =
    .
    pytest>=7.0
    pyyaml
```

- [ ] **Step 3: Verify it installs**

```bash
.venv/bin/pip install pyyaml
.venv/bin/python -c "import yaml; print(yaml.__name__)"
```
Expected: prints `yaml`.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml tox.ini
git commit -m "build(LWLP-2376): add pyyaml dev dependency for integrity tests

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: Layer A/B — subcommand and env-var-to-option contract (`cli_task_yaml_test.py` + `_yaml_helpers.py`)

**Files:**
- Create: `tests/integrity/__init__.py`
- Create: `tests/integrity/_yaml_helpers.py`
- Create: `tests/integrity/cli_task_yaml_test.py`

**Interfaces:**
- Produces (in `_yaml_helpers.py`, consumed by every later task in this plan):
  - `TEKTON_TASKS_DIR: pathlib.Path` — absolute path to `slan-cuan/tekton/tasks/`
  - `TASK_YAML_FILENAMES: list[str]` — the 6 real filenames, sorted
  - `load_task_yaml(filename: str) -> dict` — parses one file under `TEKTON_TASKS_DIR`
  - `get_run_step(task_doc: dict) -> dict` — returns the `spec.steps[]` entry named `"run"`
  - `get_subcommand_name(run_step: dict) -> str` — last element of `run_step["args"]`
  - `get_env_var_names(run_step: dict) -> list[str]` — `[e["name"] for e in run_step.get("env", [])]`
  - `build_contexts(subcommand_name: str) -> tuple[click.Context, click.Context]` — `(group_ctx, sub_ctx)`
  - `resolve_env_var_to_param(env_var_name: str, group_ctx: click.Context, sub_ctx: click.Context) -> click.Parameter | None`

- [ ] **Step 1: Write the failing tests**

Create `tests/integrity/__init__.py`:
```python
"""Integrity tests verifying slan-cuan's CLI contract with the Tekton
tasks and pipeline that depend on it (see docs/superpowers/specs/
2026-10-02-slan-cuan-integrity-tests-design.md)."""
```

Create `tests/integrity/_yaml_helpers.py`:
```python
"""Shared YAML-loading and click-introspection helpers for the integrity
test suite. Not a test module itself -- deliberately named without a
_test.py suffix so pytest does not collect it."""

from __future__ import annotations

import os
from pathlib import Path

import click
import yaml

from slan_cuan.cli import main as cli_main

TEKTON_TASKS_DIR = Path(__file__).resolve().parents[2] / "tekton" / "tasks"

TASK_YAML_FILENAMES = sorted(p.name for p in TEKTON_TASKS_DIR.glob("*.yaml"))


def load_task_yaml(filename: str) -> dict:
    """Parse one Tekton Task YAML file by filename under tekton/tasks/."""
    return yaml.safe_load((TEKTON_TASKS_DIR / filename).read_text())


def get_run_step(task_doc: dict) -> dict:
    """Return the step named 'run' -- the one invoking the slan-cuan CLI."""
    steps = task_doc["spec"]["steps"]
    return next(s for s in steps if s["name"] == "run")


def get_subcommand_name(run_step: dict) -> str:
    """Return the CLI subcommand name from a run step's args.

    The subcommand is always the last element -- several Tasks prefix it
    with a global flag, e.g. args: [--verbose, sign].
    """
    return run_step["args"][-1]


def get_env_var_names(run_step: dict) -> list[str]:
    """Return every env var name set on a run step.

    Reads only the 'name' key -- some entries use valueFrom.secretKeyRef
    instead of value and have no 'value' key at all.
    """
    return [e["name"] for e in run_step.get("env", [])]


def build_contexts(subcommand_name: str) -> tuple[click.Context, click.Context]:
    """Build the (group_ctx, sub_ctx) click Context chain for a subcommand.

    Mirrors exactly how click builds this chain internally when invoking a
    subcommand, so auto_envvar_prefix propagation matches real CLI
    behavior -- never hardcode the prefix string.
    """
    group_ctx = click.Context(
        cli_main, info_name="slan-cuan", **cli_main.context_settings
    )
    sub_cmd = cli_main.commands[subcommand_name]
    sub_ctx = click.Context(sub_cmd, parent=group_ctx, info_name=subcommand_name)
    return group_ctx, sub_ctx


def resolve_env_var_to_param(
    env_var_name: str, group_ctx: click.Context, sub_ctx: click.Context
) -> click.Parameter | None:
    """Find which click Parameter resolves an env var name, if any.

    Uses click's own Parameter.resolve_envvar_value, not a reimplementation
    of its naming rule, so this can't drift from click's real behavior.
    Checks both the subcommand's own params and the group's params, since
    Task YAMLs mix both kinds (e.g. SLAN_CUAN_EXTRACT_IMAGE is a subcommand
    option, SLAN_CUAN_TEKTON_RESULTS_DIR is a group option).
    """
    sentinel = f"__INTEGRITY_PROBE__{env_var_name}__"
    old_value = os.environ.get(env_var_name)
    os.environ[env_var_name] = sentinel
    try:
        candidates = [(p, sub_ctx) for p in sub_ctx.command.params]
        candidates += [(p, group_ctx) for p in group_ctx.command.params]
        matches = [
            p for p, ctx in candidates if p.resolve_envvar_value(ctx) == sentinel
        ]
    finally:
        if old_value is None:
            del os.environ[env_var_name]
        else:
            os.environ[env_var_name] = old_value
    if len(matches) > 1:
        raise AssertionError(
            f"{env_var_name} resolves to multiple params: "
            f"{[m.name for m in matches]}"
        )
    return matches[0] if matches else None
```

Create `tests/integrity/cli_task_yaml_test.py`:
```python
"""Layer A/B: every Tekton Task's subcommand and env vars must map to a
real slan-cuan CLI command and option. See tests/integrity/README.md."""

from __future__ import annotations

import pytest

from slan_cuan.cli import main as cli_main

from tests.integrity._yaml_helpers import (
    TASK_YAML_FILENAMES,
    build_contexts,
    get_env_var_names,
    get_run_step,
    get_subcommand_name,
    load_task_yaml,
    resolve_env_var_to_param,
)


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_subcommand_is_registered(filename: str) -> None:
    """Each Task's run-step subcommand is a real slan-cuan CLI command."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    subcommand_name = get_subcommand_name(run_step)

    assert subcommand_name in cli_main.commands, (
        f"{filename}: subcommand {subcommand_name!r} is not registered on "
        f"slan_cuan.cli.main -- was it renamed or removed?"
    )


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_every_env_var_resolves_to_a_real_option(filename: str) -> None:
    """Each Task's SLAN_CUAN_* env var must map to a real CLI option."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    subcommand_name = get_subcommand_name(run_step)
    group_ctx, sub_ctx = build_contexts(subcommand_name)

    for env_var_name in get_env_var_names(run_step):
        param = resolve_env_var_to_param(env_var_name, group_ctx, sub_ctx)
        assert param is not None, (
            f"{filename}: env var {env_var_name!r} does not resolve to any "
            f"option on '{subcommand_name}' or the top-level group -- "
            f"likely a renamed or removed CLI option that this Task's env "
            f"list was never updated for"
        )


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_every_required_option_has_a_wired_env_var(filename: str) -> None:
    """Each required (no-default) option must have a matching env var."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    subcommand_name = get_subcommand_name(run_step)
    group_ctx, sub_ctx = build_contexts(subcommand_name)
    env_var_names = get_env_var_names(run_step)

    wired_param_names = {
        p.name
        for name in env_var_names
        if (p := resolve_env_var_to_param(name, group_ctx, sub_ctx)) is not None
    }

    all_params = list(sub_ctx.command.params) + list(group_ctx.command.params)
    missing = [
        p.name
        for p in all_params
        if getattr(p, "required", False) and p.name not in wired_param_names
    ]
    assert missing == [], (
        f"{filename}: subcommand '{subcommand_name}' has required option(s) "
        f"{missing} with no env var wired anywhere in this Task's env list "
        f"-- this Task would fail at runtime with 'Missing option'"
    )


def test_force_flag_is_not_flagged_as_missing_required_env_var() -> None:
    """Pin: a boolean is_flag option (extract's --force) is never flagged
    as a missing-required-env-var case, even though it has no env var in
    extract.yaml and no explicit required=True."""
    task_doc = load_task_yaml("slan-cuan-extract.yaml")
    run_step = get_run_step(task_doc)
    _, sub_ctx = build_contexts("extract")

    force_param = next(p for p in sub_ctx.command.params if p.name == "force")
    assert getattr(force_param, "required", False) is False


def test_valuefrom_env_entries_do_not_crash_name_extraction() -> None:
    """Pin: register.yaml's SSO_CLIENT_ID/SECRET use valueFrom with no
    'value' key -- name extraction must not assume 'value' exists."""
    task_doc = load_task_yaml("slan-cuan-register.yaml")
    run_step = get_run_step(task_doc)
    env_var_names = get_env_var_names(run_step)

    assert "SLAN_CUAN_REGISTER_SSO_CLIENT_ID" in env_var_names
    assert "SLAN_CUAN_REGISTER_SSO_CLIENT_SECRET" in env_var_names
```

- [ ] **Step 2: Run tests to verify they fail for the right reason first, before the fixes land**

Run (from a clean checkout *before* Task 2's fix, to confirm the suite actually catches the real bug -- if you're executing tasks in order and Task 2 already landed, skip to Step 3 and trust Task 2's own verification instead):

```bash
.venv/bin/python -m pytest tests/integrity/ -v
```
Expected (pre-Task-2): `test_every_env_var_resolves_to_a_real_option[slan-cuan-publish.yaml]` FAILS with a message naming `SLAN_CUAN_PULP_USERNAME`.

- [ ] **Step 3: Run tests to verify they pass (with Task 2's fix already applied)**

```bash
.venv/bin/python -m pytest tests/integrity/cli_task_yaml_test.py -v
```
Expected: all PASS (6 files x 3 parametrized tests + 2 pinned tests = 20 passed).

- [ ] **Step 4: Lint and format**

```bash
.venv/bin/ruff check --fix tests/integrity/
.venv/bin/ruff format tests/integrity/
.venv/bin/ruff check tests/integrity/
.venv/bin/ruff format --check tests/integrity/
```
Expected: no errors after the fix pass.

- [ ] **Step 5: Commit**

```bash
git add tests/integrity/__init__.py tests/integrity/_yaml_helpers.py tests/integrity/cli_task_yaml_test.py
git commit -m "test(LWLP-2376): add Layer A/B integrity tests for CLI<->Task env wiring

Generically verifies, for every tekton/tasks/*.yaml file, that the run
step's subcommand is a real CLI command and every SLAN_CUAN_* env var
resolves to a real option (group- or subcommand-level) via click's own
Context/resolve_envvar_value -- not a reimplementation of its naming rule.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Layer C — on-disk output path contract (`output_contract_test.py`)

**Files:**
- Create: `tests/integrity/output_contract_test.py`

**Interfaces:**
- Consumes: `load_task_yaml`, `get_run_step` from `tests/integrity/_yaml_helpers.py` (Task 4); `slan_cuan.models.EXTRACT_RESULT_FILENAME`

- [ ] **Step 1: Write the failing test**

```python
"""Layer C: Tekton Task steps that read CLI output paths directly via raw
shell (not through another CLI call) must stay in sync with the real
filename/dirname constants. See tests/integrity/README.md."""

from __future__ import annotations

from slan_cuan.models import EXTRACT_RESULT_FILENAME

from tests.integrity._yaml_helpers import load_task_yaml


def test_extract_prepare_source_data_paths_match_code_constants() -> None:
    """extract's prepare-source-data step hardcodes paths the CLI writes;
    they must match the real constants/dirnames, not a stale literal."""
    task_doc = load_task_yaml("slan-cuan-extract.yaml")
    steps = task_doc["spec"]["steps"]
    prepare_step = next(s for s in steps if s["name"] == "prepare-source-data")
    script = prepare_step["script"]

    assert EXTRACT_RESULT_FILENAME in script, (
        f"prepare-source-data no longer references "
        f"EXTRACT_RESULT_FILENAME ({EXTRACT_RESULT_FILENAME!r}) -- if "
        f"slan_cuan.models.EXTRACT_RESULT_FILENAME changed, update this "
        f"Task's prepare-source-data script to match"
    )
    assert "metadata" in script, (
        "prepare-source-data no longer references the 'metadata' "
        "subdirectory that extract.py writes via output_dir / 'metadata'"
    )
    assert "attachments" in script, (
        "prepare-source-data no longer references the 'attachments' "
        "subdirectory that extract.py writes via output_dir / 'attachments'"
    )
```

- [ ] **Step 2: Run test to verify it fails before the assertion can be trusted**

Temporarily change the first assertion to `assert "nonexistent-filename.json" in script` and run:
```bash
.venv/bin/python -m pytest tests/integrity/output_contract_test.py -v
```
Expected: FAILS. Revert the temporary change back to `EXTRACT_RESULT_FILENAME in script`.

- [ ] **Step 3: Run test to verify it passes**

```bash
.venv/bin/python -m pytest tests/integrity/output_contract_test.py -v
```
Expected: 1 passed.

- [ ] **Step 4: Lint and format**

```bash
.venv/bin/ruff check --fix tests/integrity/output_contract_test.py
.venv/bin/ruff format tests/integrity/output_contract_test.py
```

- [ ] **Step 5: Commit**

```bash
git add tests/integrity/output_contract_test.py
git commit -m "test(LWLP-2376): add Layer C integrity test for extract output paths

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: Layer D — Tekton results contract (`tekton_results_test.py`)

**Files:**
- Modify: `tests/integrity/_yaml_helpers.py` (add AST extraction function)
- Create: `tests/integrity/tekton_results_test.py`

**Interfaces:**
- Produces (added to `_yaml_helpers.py`): `written_tekton_result_names(command: click.Command) -> set[str]`
- Consumes: `load_task_yaml`, `TASK_YAML_FILENAMES`, `get_run_step`, `get_subcommand_name` (Task 4)

- [ ] **Step 1: Write the failing test**

Add to `tests/integrity/_yaml_helpers.py` (append at the end of the file):
```python
import ast
import inspect


def written_tekton_result_names(command: click.Command) -> set[str]:
    """AST-extract literal result-name strings from write_tekton_result(...)
    calls inside a click command's own callback function.

    Scoped to exactly that function's source (via inspect.getsource, which
    follows __wrapped__ through click's pass_obj/pass_context decorators),
    not the whole module -- generate_security_metadata.py hosts two
    commands, so a whole-module scan would merge their result names.

    Assumption: only recognizes a literal string as the second positional
    argument, matching every write_tekton_result call site today. A future
    call site computing the name dynamically would be invisible here.
    """
    source = inspect.getsource(command.callback)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "write_tekton_result"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            names.add(node.args[1].value)
    return names
```

Create `tests/integrity/tekton_results_test.py`:
```python
"""Layer D: every Tekton result name a CLI command writes must be declared
on its Task. See tests/integrity/README.md."""

from __future__ import annotations

import pytest

from slan_cuan.cli import main as cli_main

from tests.integrity._yaml_helpers import (
    TASK_YAML_FILENAMES,
    get_run_step,
    get_subcommand_name,
    load_task_yaml,
    written_tekton_result_names,
)


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_written_results_are_declared_on_the_task(filename: str) -> None:
    """Every result name the CLI writes must appear in the Task's
    declared results -- not the reverse, since some results (e.g.
    sourceDataArtifact) come from a stepaction, not the CLI."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    subcommand_name = get_subcommand_name(run_step)
    command = cli_main.commands[subcommand_name]

    written = written_tekton_result_names(command)
    declared = {r["name"] for r in task_doc["spec"].get("results", [])}

    missing = written - declared
    assert missing == set(), (
        f"{filename}: '{subcommand_name}' writes Tekton result(s) {missing} "
        f"that are not declared in this Task's results: -- Tekton will not "
        f"surface these, silently dropping the data"
    )


def test_ast_extraction_is_scoped_per_function_not_whole_module() -> None:
    """Pin: generate_security_metadata.py hosts two commands; extraction
    for one must not see the other's function body."""
    gsm = cli_main.commands["generate-security-metadata"]
    gsm_source = __import__("inspect").getsource(gsm.callback)
    assert "def generate_security_metadata_from_snapshot" not in gsm_source

    gsm_snap = cli_main.commands["generate-security-metadata-from-snapshot"]
    gsm_snap_source = __import__("inspect").getsource(gsm_snap.callback)
    assert "def generate_security_metadata(" not in gsm_snap_source
```

- [ ] **Step 2: Run tests to verify they fail first (sanity check the scoping pin)**

Temporarily change `written_tekton_result_names` to use `inspect.getsource(inspect.getmodule(command.callback))` instead of `inspect.getsource(command.callback)` and run:
```bash
.venv/bin/python -m pytest tests/integrity/tekton_results_test.py::test_ast_extraction_is_scoped_per_function_not_whole_module -v
```
Expected: FAILS (both assertions trip, since the whole module contains both function defs). Revert the temporary change back to `inspect.getsource(command.callback)`.

- [ ] **Step 3: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest tests/integrity/tekton_results_test.py -v
```
Expected: 7 passed (6 parametrized + 1 pin).

- [ ] **Step 4: Lint and format**

```bash
.venv/bin/ruff check --fix tests/integrity/
.venv/bin/ruff format tests/integrity/
```

- [ ] **Step 5: Commit**

```bash
git add tests/integrity/_yaml_helpers.py tests/integrity/tekton_results_test.py
git commit -m "test(LWLP-2376): add Layer D integrity test for Tekton results contract

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: Layer E — cross-repo pipeline param contract (vendored fixture + `pipeline_contract_test.py`)

**Files:**
- Create: `tests/integrity/fixtures/release-service-catalog/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml`
- Create: `tests/integrity/pipeline_contract_test.py`

**Interfaces:**
- Consumes: `load_task_yaml`, `TEKTON_TASKS_DIR` (Task 4)

- [ ] **Step 1: Vendor the (already-fixed) pipeline YAML**

Copy the corrected file from the `release-service-catalog` branch created in Task 1 (with the `RADAS_UMB_HOST` wiring already removed):

```bash
mkdir -p tests/integrity/fixtures/release-service-catalog/pipelines/managed/slan-cuan-release
cp /home/jgangi/Documents/RedHat/exd-sp/lightwell/release-service-catalog/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml \
   tests/integrity/fixtures/release-service-catalog/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml
```

Then prepend this header comment to the vendored copy (above the existing `---` document start):
```yaml
# VENDORED FIXTURE -- pinned, not live-fetched.
# Source: https://github.com/konflux-lightwell/release-service-catalog/blob/development/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml
# Copied from branch fix/LWLP-2376-remove-dead-radas-umb-host-param at the
# commit created in Task 1 of docs/superpowers/plans/2026-10-02-slan-cuan-integrity-tests.md.
# Update this header's commit reference once that PR merges to development.
# See tests/integrity/README.md for how to refresh this fixture and what a
# test failure here means (real break vs. stale fixture).
```

- [ ] **Step 2: Write the failing test**

```python
"""Layer E: the slan-cuan-release Pipeline (release-service-catalog) must
only pass params a Task declares, and must supply every param a Task
requires. Runs offline against a vendored, pinned fixture -- see
tests/integrity/README.md for how to refresh it and what a failure means."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.integrity._yaml_helpers import load_task_yaml

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "release-service-catalog"
    / "pipelines"
    / "managed"
    / "slan-cuan-release"
    / "slan-cuan-release.yaml"
)


def _load_pipeline_fixture() -> dict:
    return yaml.safe_load(FIXTURE_PATH.read_text())


def _slan_cuan_task_filename(pipeline_task: dict) -> str | None:
    """Return the tekton/tasks/*.yaml filename this pipeline task step
    resolves to, or None if it's not a slan-cuan task (e.g. collect-data,
    verify-conforma -- these use a different taskRef shape entirely)."""
    task_ref_params = pipeline_task.get("taskRef", {}).get("params", [])
    path_in_repo = next(
        (p["value"] for p in task_ref_params if p["name"] == "pathInRepo"),
        None,
    )
    if path_in_repo is None or not path_in_repo.startswith("tekton/tasks/"):
        return None
    return path_in_repo.removeprefix("tekton/tasks/")


def _slan_cuan_pipeline_tasks() -> list[tuple[str, str]]:
    """Return [(pipeline_task_name, tekton_task_filename), ...] for every
    pipeline task that maps to a local tekton/tasks/*.yaml file."""
    pipeline = _load_pipeline_fixture()
    result = []
    for task in pipeline["spec"]["tasks"]:
        filename = _slan_cuan_task_filename(task)
        if filename is not None:
            result.append((task["name"], filename))
    return result


def test_exactly_four_pipeline_tasks_map_to_local_slan_cuan_tasks() -> None:
    """Pin: the fixture has 9 pipeline tasks total; only 4 (extract, sign,
    generate-security-metadata, publish) reference a local Task file.
    register is not currently wired into this pipeline at all."""
    mapped = _slan_cuan_pipeline_tasks()
    assert sorted(name for name, _ in mapped) == [
        "extract",
        "generate-security-metadata",
        "publish",
        "sign",
    ]


@pytest.mark.parametrize(
    "pipeline_task_name,task_filename", _slan_cuan_pipeline_tasks()
)
def test_pipeline_only_passes_params_the_task_declares(
    pipeline_task_name: str, task_filename: str
) -> None:
    """Every param the Pipeline supplies to a slan-cuan task must be
    declared on that Task -- an undeclared param is silently stray."""
    pipeline = _load_pipeline_fixture()
    pipeline_task = next(
        t for t in pipeline["spec"]["tasks"] if t["name"] == pipeline_task_name
    )
    supplied = {p["name"] for p in pipeline_task.get("params", [])}

    task_doc = load_task_yaml(task_filename)
    declared = {p["name"] for p in task_doc["spec"]["params"]}

    undeclared = supplied - declared
    assert undeclared == set(), (
        f"pipeline task '{pipeline_task_name}' passes param(s) {undeclared} "
        f"that {task_filename} does not declare in spec.params -- stray or "
        f"renamed param"
    )


@pytest.mark.parametrize(
    "pipeline_task_name,task_filename", _slan_cuan_pipeline_tasks()
)
def test_pipeline_supplies_every_required_task_param(
    pipeline_task_name: str, task_filename: str
) -> None:
    """Every Task param without a default must be supplied by the
    Pipeline, or the real pipeline run fails immediately."""
    pipeline = _load_pipeline_fixture()
    pipeline_task = next(
        t for t in pipeline["spec"]["tasks"] if t["name"] == pipeline_task_name
    )
    supplied = {p["name"] for p in pipeline_task.get("params", [])}

    task_doc = load_task_yaml(task_filename)
    required = {
        p["name"] for p in task_doc["spec"]["params"] if "default" not in p
    }

    missing = required - supplied
    assert missing == set(), (
        f"{task_filename} requires param(s) {missing} (no default) that "
        f"pipeline task '{pipeline_task_name}' does not supply -- this "
        f"would fail at pipeline-run time"
    )
```

- [ ] **Step 3: Run tests to verify the task-filtering pin fails first**

Temporarily change `_slan_cuan_task_filename` to `return path_in_repo` (without the `tekton/tasks/` prefix check or `removeprefix`) and run:
```bash
.venv/bin/python -m pytest tests/integrity/pipeline_contract_test.py::test_exactly_four_pipeline_tasks_map_to_local_slan_cuan_tasks -v
```
Expected: FAILS or errors (non-slan-cuan tasks like `collect-data` would either be wrongly included, or a later `TEKTON_TASKS_DIR / filename` lookup would raise `FileNotFoundError` for a path like `stepactions/...` that was never filtered out). Revert the temporary change.

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest tests/integrity/pipeline_contract_test.py -v
```
Expected: 9 passed (1 pin + 4 tasks x 2 parametrized tests).

- [ ] **Step 5: Lint and format**

```bash
.venv/bin/ruff check --fix tests/integrity/
.venv/bin/ruff format tests/integrity/
```

- [ ] **Step 6: Commit**

```bash
git add tests/integrity/fixtures/ tests/integrity/pipeline_contract_test.py
git commit -m "test(LWLP-2376): add Layer E cross-repo pipeline param contract test

Vendors a pinned copy of release-service-catalog's slan-cuan-release.yaml
(post RADAS_UMB_HOST cleanup) and verifies, offline, that the Pipeline only
passes params each slan-cuan Task declares and supplies every param a Task
requires. See tests/integrity/README.md for the fixture-staleness tradeoff.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 8: `tests/integrity/README.md`

**Files:**
- Create: `tests/integrity/README.md`

**Interfaces:**
- None (documentation only).

- [ ] **Step 1: Write the doc**

```markdown
# Integrity Tests

This suite verifies that slan-cuan's CLI still satisfies the contracts the
`slan-cuan-release` Tekton pipeline and its Tasks depend on, so an internal
refactor (like LWLP-2376) can't silently break them. See the design spec:
`docs/superpowers/specs/2026-10-02-slan-cuan-integrity-tests-design.md`.

All checks are generic and data-driven off the real `tekton/tasks/*.yaml`
files and the real `slan_cuan.cli.main` click object -- never a hand-written
table of expected options -- so adding or changing a task/option is
automatically covered without anyone remembering to add a matching
assertion.

## Layers and files

- **`cli_task_yaml_test.py`** (Layers A/B) -- for every Task YAML, the run
  step's subcommand must be a registered CLI command, and every
  `SLAN_CUAN_*` env var must resolve to a real option. This drives click's
  actual `Context`/`Parameter.resolve_envvar_value()` -- never reimplements
  click's auto-envvar naming rule -- by monkeypatching a sentinel value into
  `os.environ` and checking which parameter (group-level or
  subcommand-level) picks it up. Also checks the inverse: every required
  (no-default) option must have a wired env var somewhere in the Task.
- **`output_contract_test.py`** (Layer C) -- a few Task steps read CLI
  output paths directly via raw shell instead of another CLI call (e.g.
  `extract`'s `prepare-source-data` step hardcodes `extract-result.json`,
  `metadata`, `attachments`). These get an explicit test per occurrence,
  checked against the real constant/dirname, not a duplicated literal.
- **`tekton_results_test.py`** (Layer D) -- AST-parses each CLI command's
  callback for literal `write_tekton_result(..., "NAME", ...)` calls and
  asserts every name is declared in the Task's `results:`. Scoped per
  function (not per module), since `generate_security_metadata.py` hosts
  two commands.
- **`pipeline_contract_test.py`** (Layer E) -- cross-repo: see below.

## `pipeline_contract_test.py` caveats

This is the one layer that reaches outside this repo, into
`release-service-catalog`'s `slan-cuan-release.yaml` pipeline. There's no
live fetch in the blocking test suite -- it runs against a **pinned,
vendored snapshot** at
`fixtures/release-service-catalog/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml`.

**What this means for a legitimate change:** if someone adds a param, renames
one, or rewires a task in `release-service-catalog`'s pipeline, this suite
will **not** see it until the fixture is refreshed. It is not watching that
repo live.

**How to refresh the fixture:** copy the current
`pipelines/managed/slan-cuan-release/slan-cuan-release.yaml` from
`release-service-catalog` over the vendored path above, and update the
header comment with the new source commit/revision.

**How to tell a real break from a stale fixture**, when
`pipeline_contract_test.py` fails:
- If the failure appears after a change to this repo's own
  `tekton/tasks/*.yaml` `params:` -- that's a real contract break. Fix the
  Task or the (separately vendored) fixture to match, whichever is wrong.
- If the failure appears with no related change in this repo -- the fixture
  is stale, most likely because `release-service-catalog` changed first.
  Refresh the fixture (see above) rather than "fixing" working code.

**Freshness check:** `scripts/check_pipeline_fixture_freshness.py` runs on
a weekly schedule (non-blocking -- never gates a PR) specifically to catch
staleness before it causes confusion. Its failure means "refresh the
fixture," not "a contract broke."

**Known gap, out of scope:** several params are wired through
`collect-task-params`'s positional `extractedValues[N]` array in the real
pipeline (e.g. `PULP_URL: $(tasks.collect-task-params.results.extractedValues[0])`),
whose correctness depends on index alignment with a separate
`keysToExtract` JSON list elsewhere in the same pipeline file. Verifying
that alignment would mean modeling `collect-task-params`'s own behavior,
which belongs to `release-service-catalog`, not slan-cuan's contract. Not
covered here.
```

- [ ] **Step 2: Commit**

```bash
git add tests/integrity/README.md
git commit -m "docs(LWLP-2376): document the integrity test suite and fixture caveats

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 9: Freshness-check script

**Files:**
- Create: `scripts/check_pipeline_fixture_freshness.py`

**Interfaces:**
- Produces: a standalone script, `python3 scripts/check_pipeline_fixture_freshness.py`, exit code 0 (fixture current) or 1 (drifted, with a diff printed).

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""Check whether the vendored release-service-catalog pipeline fixture
used by tests/integrity/pipeline_contract_test.py has drifted from the
live file on GitHub.

Non-blocking by design: run on a schedule (see
.github/workflows/pipeline-fixture-freshness.yml), never as part of the
PR-blocking test suite. A failure here means "refresh the fixture," not
"a contract broke" -- see tests/integrity/README.md.
"""

from __future__ import annotations

import difflib
import sys
import urllib.request
from pathlib import Path

LIVE_URL = (
    "https://raw.githubusercontent.com/konflux-lightwell/"
    "release-service-catalog/development/pipelines/managed/"
    "slan-cuan-release/slan-cuan-release.yaml"
)

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "tests"
    / "integrity"
    / "fixtures"
    / "release-service-catalog"
    / "pipelines"
    / "managed"
    / "slan-cuan-release"
    / "slan-cuan-release.yaml"
)


def _strip_header_comment(text: str) -> str:
    """Drop this repo's own vendoring header comment before diffing,
    since it legitimately differs from the live file by design."""
    lines = text.splitlines(keepends=True)
    first_doc_start = next(
        i for i, line in enumerate(lines) if line.startswith("---")
    )
    return "".join(lines[first_doc_start:])


def main() -> int:
    """Fetch the live pipeline YAML and diff it against the vendored copy."""
    with urllib.request.urlopen(LIVE_URL, timeout=30) as response:  # noqa: S310
        live_content = response.read().decode("utf-8")

    vendored_content = _strip_header_comment(FIXTURE_PATH.read_text())

    diff = list(
        difflib.unified_diff(
            vendored_content.splitlines(keepends=True),
            live_content.splitlines(keepends=True),
            fromfile="vendored fixture",
            tofile="live release-service-catalog@development",
        )
    )
    if diff:
        print("Vendored pipeline fixture has drifted from the live file:")
        print("".join(diff))
        print(
            "\nRefresh the fixture -- see tests/integrity/README.md "
            "('pipeline_contract_test.py caveats')."
        )
        return 1

    print("Vendored pipeline fixture is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it against the current (already up-to-date, post-Task-1-merge) state**

This requires network access and Task 1's PR to be merged to `development` first to show a clean pass; until then it will correctly report drift (the live file still has the old `RADAS_UMB_HOST` wiring the vendored copy no longer has). Run it now to confirm it *detects* that expected, known drift:

```bash
python3 scripts/check_pipeline_fixture_freshness.py
```
Expected: exit code 1, diff showing the `radas-umb-host` / `RADAS_UMB_HOST` lines as the only difference (proving the script correctly detects a real, known-cause drift rather than false-passing).

- [ ] **Step 3: Lint and format**

```bash
.venv/bin/ruff check --fix scripts/check_pipeline_fixture_freshness.py
.venv/bin/ruff format scripts/check_pipeline_fixture_freshness.py
```

- [ ] **Step 4: Commit**

```bash
chmod +x scripts/check_pipeline_fixture_freshness.py
git add scripts/check_pipeline_fixture_freshness.py
git commit -m "feat(LWLP-2376): add non-blocking pipeline fixture freshness check

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 10: Scheduled freshness workflow + final full-suite verification

**Files:**
- Create: `.github/workflows/pipeline-fixture-freshness.yml`

**Interfaces:**
- None (CI wiring only).

- [ ] **Step 1: Write the workflow**

```yaml
name: Pipeline Fixture Freshness

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch: {}

jobs:
  check-freshness:
    name: Check vendored pipeline fixture
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python3 scripts/check_pipeline_fixture_freshness.py
```

- [ ] **Step 2: Validate the workflow YAML**

```bash
.venv/bin/python -c "import yaml; yaml.safe_load(open('.github/workflows/pipeline-fixture-freshness.yml'))" && echo "valid YAML"
```
Expected: `valid YAML`.

- [ ] **Step 3: Confirm it never blocks a PR**

Run: `grep -n "^on:" -A 4 .github/workflows/pipeline-fixture-freshness.yml`
Expected: only `schedule` and `workflow_dispatch` triggers -- no `push` or `pull_request`.

- [ ] **Step 4: Run the full new suite plus the existing suite together**

```bash
.venv/bin/python -m pytest tests/ -v
```
Expected: all tests pass, including every existing test (`tests/cli_test.py`, `tests/tasks/`, etc.) alongside all of `tests/integrity/`.

- [ ] **Step 5: Full lint/format pass across everything touched in this plan**

```bash
.venv/bin/ruff check --fix . && .venv/bin/ruff format .
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/pipeline-fixture-freshness.yml
git commit -m "ci(LWLP-2376): add weekly pipeline fixture freshness workflow

Scheduled-only (plus manual workflow_dispatch) -- never blocks a PR. Its
failure means the vendored pipeline_contract_test.py fixture needs
refreshing, not that a contract broke. See tests/integrity/README.md.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Push the branch**

```bash
git push -u origin docs/LWLP-2376-integrity-tests-design
```

- [ ] **Step 8: Ask the user before opening the PR**

Stop here and ask the user to confirm before running `gh pr create` (or opening an MR, per this repo's own convention) for this `slan-cuan` branch, per this workspace's standing rule against creating MRs/PRs without asking first.
