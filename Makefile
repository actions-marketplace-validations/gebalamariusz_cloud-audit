.PHONY: install lint format format-check typecheck test test-cov security all clean

install:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

format-check:
	ruff format --check src/ tests/

typecheck:
	mypy src/

test:
	pytest -v --tb=short

test-cov:
	pytest -v --tb=short --cov=cloud_audit --cov-report=term-missing --cov-report=html

security:
	pip-audit --strict

all: lint format-check typecheck test

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache htmlcov .coverage dist build *.egg-info
