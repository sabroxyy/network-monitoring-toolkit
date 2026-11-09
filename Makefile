.PHONY: install fmt lint type test test-unit check docker run-example

install:
	pip install -e '.[dev,api]'
	pre-commit install || true

fmt:
	python -m ruff format src tests examples
	python -m ruff check --fix src tests examples

lint:
	python -m ruff format --check src tests examples
	python -m ruff check src tests examples

type:
	python -m mypy

test-unit:
	python -m pytest -m "not integration"

test:
	python -m pytest --cov

check: lint type test

docker:
	docker build -t netmon:dev .

run-example:
	python examples/minimal_scan.py
