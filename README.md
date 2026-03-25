# pyImprov

Implementation of the [Improv-wifi](https://www.improv-wifi.com/) protocol in Python 3.10+

## Installation

pyImprov is available through PyPI:

```bash
pip install pyImprov
```

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Install dependencies (creates .venv automatically)
uv sync

# Run the example
uv run python example.py

# Run tests
uv run pytest -v

# Lint
uv run ruff check .

# Format
uv run black .
```

### Pre-commit hooks

Ruff and Black run automatically on every commit via pre-commit:

```bash
uv run pre-commit install
```
