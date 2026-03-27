# Contributing

See [CONTRIBUTING.md](https://github.com/gebalamariusz/cloud-audit/blob/main/CONTRIBUTING.md) in the repository for detailed guidelines on:

- Adding a new check
- Adding a compliance framework mapping
- Reporting bugs
- Submitting pull requests

## Development Setup

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"

pytest -v                          # tests
ruff check src/ tests/             # lint
ruff format --check src/ tests/    # format
mypy src/                          # type check
```

## Adding a New Check

1. Create or edit a module in `src/cloud_audit/providers/aws/checks/`
2. Write a function returning `CheckResult`
3. Register it in the module's `get_checks()` with `make_check()`
4. Add the module to `_CHECK_MODULES` in `provider.py` (if new)
5. Write tests
6. Update the check list in README and docs

## Adding a Compliance Framework

1. Create a JSON mapping file in `src/cloud_audit/compliance/frameworks/`
2. Follow the schema from `cis_aws_v3.json`
3. Map check IDs to framework controls
4. Add evidence templates and manual steps
5. Add attack chain mappings
