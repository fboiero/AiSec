# Contributing to AiSec

Thank you for your interest in contributing to AiSec! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/AiSec.git
   cd AiSec
   ```
3. Install in development mode:
   ```bash
   pip install -e ".[dev,all]"
   ```
4. Create a branch for your changes:
   ```bash
   git checkout -b feature/my-feature
   ```

## Development Workflow

### Running Tests

```bash
pytest                      # run all tests
pytest tests/unit/          # run unit tests only
pytest -x                   # stop on first failure
pytest --cov=aisec          # with coverage report
```

### Code Quality

```bash
ruff check src/ tests/      # lint
ruff format src/ tests/     # format
mypy src/aisec/             # type check
```

### Pre-commit Hooks

We recommend using pre-commit hooks:

```bash
pre-commit install
```

## Contribution Types

### Bug Reports

- Use the [bug report template](https://github.com/fboiero/AiSec/issues/new?template=bug_report.md)
- Include steps to reproduce, expected vs actual behavior, and environment details

### Feature Requests

- Use the [feature request template](https://github.com/fboiero/AiSec/issues/new?template=feature_request.md)
- Describe the use case and proposed solution

### Code Contributions

1. Ensure your code follows the existing style (enforced by ruff)
2. Add tests for new functionality
3. Update documentation if needed
4. Keep commits focused and write clear commit messages

### Adding a New Analysis Agent

1. Create a new file in `src/aisec/agents/`
2. Inherit from `BaseAgent` and implement `analyze()`
3. Register the agent in `src/aisec/agents/registry.py`
4. Add corresponding tests in `tests/unit/agents/`
5. Map findings to the appropriate OWASP/NIST framework categories

### Adding a New Compliance Framework

1. Create a new file in `src/aisec/frameworks/compliance/`
2. Define the checklist items and evaluation logic
3. Register in the compliance framework registry
4. Add the framework to the report templates

## Pull Request Process

1. Update the README.md if your changes affect the public API
2. Ensure all tests pass and linting is clean
3. Write a clear PR description explaining what and why
4. Reference any related issues

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing to AiSec, you agree that your contributions will be licensed under the Apache License 2.0.
