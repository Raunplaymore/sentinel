# Contributing to Sentinel

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/raunplaymore/sentinel.git
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR.

## Project Structure

```
sentinel_mac/core.py    All core logic (collector, alerts, notifier, daemon)
tests/                  Unit tests (pytest)
config.yaml             Config template
install.sh              macOS installer with launchd
```

## Making Changes

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Add or update tests as needed
4. Ensure all tests pass
5. Submit a pull request

## Code Style

- Follow existing patterns in the codebase
- Keep functions focused and concise
- Add docstrings for public classes and methods
- Use type hints where practical

## Reporting Issues

- Use [GitHub Issues](https://github.com/raunplaymore/sentinel/issues)
- Include your macOS version and Python version
- Include relevant log output from `logs/sentinel.log`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
