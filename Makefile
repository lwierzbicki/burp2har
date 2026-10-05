.PHONY: setup format lint typecheck test build clean help

VENV   ?= .venv
PYTHON ?= $(VENV)/bin/python3
PKG    ?= burp2har
ARGS   ?=

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

setup:  ## Create venv and install the package + dev deps (editable)
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

format:  ## Auto-format and auto-fix
	$(PYTHON) -m ruff format src/ tests/
	$(PYTHON) -m ruff check --fix src/ tests/

lint:  ## Lint (no changes)
	$(PYTHON) -m ruff check src/ tests/

typecheck:  ## Static type check
	$(PYTHON) -m mypy src/$(PKG)/

test:  ## Run tests with coverage
	$(PYTHON) -m pytest tests/ $(ARGS)

build:  ## Build sdist + wheel
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build

clean:  ## Remove build + cache artifacts
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
