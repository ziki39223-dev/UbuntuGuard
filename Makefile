.PHONY: install dev test lint typecheck

install:
	python3 -m pip install -e .

dev:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest

lint:
	ruff check src tests

typecheck:
	mypy src
