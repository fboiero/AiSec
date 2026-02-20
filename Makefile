.PHONY: install dev lint format typecheck test test-unit test-integration clean build docker

install:
	pip install -e .

dev:
	pip install -e ".[dev,all]"

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/aisec/ --ignore-missing-imports

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-cov:
	pytest tests/ --cov=aisec --cov-report=html -v

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +

build:
	python -m build

docker:
	docker build -t aisec:latest .
