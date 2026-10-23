.PHONY: install check lint format typecheck test audit schemas vectors readme-art demo

install:
	uv sync --frozen --all-extras

check: lint typecheck test

lint:
	uv run ruff check src tests scripts examples
	uv run ruff format --check src tests scripts examples

format:
	uv run ruff format src tests scripts examples
	uv run ruff check --fix src tests scripts examples

typecheck:
	uv run mypy

test:
	uv run pytest -q

audit:
	uv run pip-audit --skip-editable --progress-spinner off

schemas:
	uv run oat schema --out protocol/schemas/v0.1

vectors:
	uv run python scripts/make_test_vectors.py

readme-art:
	uv run python scripts/make_readme_terminal.py

demo:
	uv run oat demo --out oat-demo-$$(date +%s)
