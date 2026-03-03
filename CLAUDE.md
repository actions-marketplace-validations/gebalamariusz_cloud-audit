# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run CLI
cloud-audit scan --provider aws --profile <name> --regions eu-central-1
cloud-audit version

# Tests
pytest -v
pytest tests/test_models.py -v              # single file
pytest tests/test_models.py::test_name -v   # single test

# Lint
ruff check src/ tests/
ruff format --check src/ tests/

# Type check
mypy src/

# Docker
docker build -t cloud-audit .
docker run cloud-audit version
```

## Architecture

```
src/cloud_audit/
├── cli.py              # Typer CLI entry point (scan, version commands)
├── models.py           # Pydantic models: Finding, CheckResult, ScanSummary, ScanReport
├── scanner.py          # Orchestrator: runs checks with Rich progress bar → ScanReport
├── providers/
│   ├── base.py         # BaseProvider ABC (get_account_id, get_checks, get_provider_name)
│   └── aws/
│       ├── provider.py # AWSProvider: boto3 session, region handling, check loading
│       └── checks/     # One module per AWS service (iam, s3, ec2, vpc, rds, eip)
└── reports/
    ├── html.py         # Jinja2 renderer
    └── templates/      # report.html.j2 (self-contained dark-mode HTML)
```

### Pipeline flow

`CLI (cli.py)` → `Scanner (scanner.py)` → `Provider.get_checks()` → execute each check → aggregate into `ScanReport` → `_print_summary()` + optional HTML/JSON output.

### Check registration pattern

Each check module in `providers/aws/checks/` exports a `get_checks(provider)` function that returns `list[partial(check_fn, provider)]` with `.category` attribute attached to each partial for filtering.

### Global vs. regional checks

- **Global** (single API call): IAM, S3
- **Regional** (loops `provider.regions`): EC2, RDS, VPC, EIP

### Health score

Starts at 100, subtracts per finding: CRITICAL=20, HIGH=10, MEDIUM=5, LOW=2. Floor at 0.

### Error handling

- Each check is wrapped in try/except — errors populate `CheckResult.error` without halting the scan.
- CLI detects `all_errored` state (e.g., expired credentials) and shows "SCAN FAILED" panel with fix suggestions instead of a misleading score.

## Adding a new check

1. Create or edit a module in `src/cloud_audit/providers/aws/checks/`.
2. Write a function `check_something(provider: AWSProvider) -> CheckResult`.
3. Add it to the module's `get_checks()` return list with `.category` set.
4. Register the module in `AWSProvider._CHECK_MODULES` list in `provider.py`.
5. Update `README.md` checks table.

## Adding a new provider

1. Create `src/cloud_audit/providers/<name>/provider.py` implementing `BaseProvider`.
2. Add the provider import to `cli.py`'s `scan()` command.

## Key conventions

- Python 3.10+ compatibility required (no `type` aliases, no `X | Y` in runtime annotations — use `from __future__ import annotations`).
- Pydantic v2 models — immutable by default.
- Ruff for linting (line-length=120, strict security rules enabled).
- `S101` (assert) is ignored in ruff config for test compatibility.
