"""Regression tests for the runtime dependency surface (v0.10.3).

A v0.10 Track A regression shipped `from packaging.version import Version`
in `sentinel_mac/updater/version.py` without adding `packaging` to
`[project] dependencies` in `pyproject.toml`. PyPI installs via
`pipx install sentinel-mac` got a minimal venv with no transitive
`packaging` dependency, so `sentinel update --check` / `--apply` from
a clean install raised ModuleNotFoundError on every invocation.

These tests fail-fast on that shape of bug — any module the production
code imports unconditionally must be importable from a process that
loads the package.
"""

from __future__ import annotations


def test_packaging_is_importable() -> None:
    """`packaging` is used by `sentinel_mac/updater/version.py` for PEP 440
    Version comparison; it must be in [project] dependencies, not relied on
    as a transitive import from setuptools/pip (which a minimal pipx venv
    does NOT have)."""
    import packaging.version  # noqa: F401


def test_updater_version_module_imports_clean() -> None:
    """End-to-end: importing the consumer module that triggered the v0.10.x
    bug must not raise. Catches `from packaging.X import Y` style imports
    that the bare `import packaging` test above would miss if the upstream
    package's submodule layout changed."""
    from sentinel_mac.updater.version import is_update_available  # noqa: F401


def test_runtime_deps_match_pyproject() -> None:
    """The set of imports we explicitly assert below MUST be in
    `[project] dependencies`. If you add a runtime import to production
    code, add the package here AND to pyproject.toml — keeping the two in
    sync is the whole point of this test.

    Skipped on Python < 3.11 because `tomllib` is stdlib only there.
    The packaging-importable test above still runs everywhere; this one
    is the additional fail-fast guardrail."""
    import sys
    from pathlib import Path

    if sys.version_info < (3, 11):
        import pytest
        pytest.skip("tomllib requires Python 3.11+")
    import tomllib  # noqa: I001 — guarded by version check above

    repo_root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text())
    declared = pyproject["project"]["dependencies"]
    declared_names = {
        # split on first PEP 508 marker char
        dep.split("=", 1)[0].split("<", 1)[0].split(">", 1)[0]
            .split("!", 1)[0].split("~", 1)[0].split("[", 1)[0].strip()
        for dep in declared
    }

    # Hand-curated list of packages production code imports unconditionally.
    # When a new runtime import lands, append here AND to pyproject.toml.
    must_be_declared = {
        "packaging",  # updater/version.py — added 2026-05-05 / v0.10.3
        "psutil",     # collectors/system.py, collectors/net_tracker.py
        "pyyaml",     # core.py via `import yaml`
        "requests",   # notifier.py, updater/version.py
        "watchdog",   # collectors/fs_watcher.py
    }

    missing = must_be_declared - declared_names
    assert not missing, (
        f"runtime imports not declared in pyproject.toml dependencies: {missing}. "
        "Add them to `[project] dependencies` so PyPI installs (pipx/pip-venv) "
        "get them."
    )
