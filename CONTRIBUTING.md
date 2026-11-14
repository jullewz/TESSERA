# Contributing to Tessera

Thanks for your interest in improving Tessera. This guide explains how to propose changes.

## Ground rules

- Be respectful. The [Code of Conduct](CODE_OF_CONDUCT.md) applies everywhere.
- Report security vulnerabilities privately, see [SECURITY.md](SECURITY.md). Do not open public issues for them.
- Open an issue before large changes so the design can be discussed first.

## Development setup

```bash
git clone https://github.com/jullewz/tessera.git
cd tessera
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Before you open a pull request

Run the same checks as CI:

```bash
python -m pytest
ruff check .
ruff format --check .
mypy
```

All four must pass on your platform. CI also runs them on Linux, macOS and Windows.

## Coding standards

- **No runtime dependencies.** Tessera runs on locked-down servers. Use the standard library.
- **Type everything.** `mypy --strict` must pass.
- **Keep the CLI thin.** Logic belongs in `engine.py` and the core modules, the CLI parses and renders.
- **Never abort a scan on one bad file.** Record the error on the entry and continue.
- **Never use a shell.** Hooks and subprocesses run with `shell=False`.
- **Think cross-platform.** Use `os.path`/`pathlib`, guard POSIX-only behaviour, test with the `posix_only` marker.
- **Test what you change.** Bug fixes come with a regression test. New features come with unit tests and, where
  relevant, an end-to-end test in `tests/test_cli.py`.

## Commit messages

Use short, imperative subjects (`Add BLAKE3 support`, `Fix junction handling on Windows`) and explain the reason in
the body when it is not obvious.

## Adding a risk heuristic

1. Add a function to `src/tessera/risk.py` returning `(Severity, reason)` or `None`.
2. Register it in `HEURISTICS`.
3. Add tests to `tests/test_risk.py` covering both the firing and the non-firing case.
4. Document it in `docs/risk-heuristics.md`.

## Adding a report format

1. Create `src/tessera/reporters/<name>.py` exposing `render(report, style) -> str`.
2. Register it in `FORMATS` and `_MODULES` in `src/tessera/reporters/__init__.py`.
3. Add it to the parametrised test in `tests/test_reporters.py`.

## Releasing

Maintainer steps are in [docs/releasing.md](docs/releasing.md).
