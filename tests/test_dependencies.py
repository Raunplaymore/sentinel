"""Regression tests for the runtime dependency surface.

These tests fail-fast on the shape of bug where production code imports
a package that is NOT declared in `[project] dependencies`. PyPI installs
(via `pipx install sentinel-mac` or `pip install sentinel-mac` into a
fresh venv) get only the declared deps — anything missed makes the
package crash on the user's machine even though dev/CI green.

History of bugs caught (or that would have been caught) by this file:

- v0.10.3 (PR #46): `packaging` added to `updater/version.py` without
  declaration. Hidden by transitive setuptools/pip in dev venvs.
- v0.11.1: `rumps` + `ruamel.yaml` were `[optional-dependencies] app`,
  but `[project.scripts] sentinel-app` was unconditional. PyPI users
  running `sentinel-app` got ModuleNotFoundError.

The hand-curated `must_be_declared` set is a backstop. The AST scanner
test (`test_all_top_level_imports_declared`) is the real guardrail —
it walks the whole `sentinel_mac/` tree and catches missing
declarations automatically.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Mapping of `import-name` (what code writes) → `pypi-name` (what
# pyproject.toml declares). Only needed when they differ.
_IMPORT_TO_PYPI: dict[str, str] = {
    "yaml": "pyyaml",
}

# Namespace packages where the PyPI distribution name is the first TWO
# dotted segments, not the first one. `import ruamel.yaml` is provided
# by the `ruamel.yaml` PyPI distribution, not by a `ruamel` package.
_NAMESPACE_PACKAGES: set[str] = {"ruamel"}


def test_packaging_is_importable() -> None:
    """`packaging` is used by `sentinel_mac/updater/version.py` for PEP 440
    Version comparison; it must be in [project] dependencies, not relied on
    as a transitive import from setuptools/pip (which a minimal pipx venv
    does NOT have)."""
    import packaging.version  # noqa: F401


def test_rumps_is_importable() -> None:
    """`rumps` powers the menu bar app. Was `[optional-dependencies] app`
    through v0.11.0, but `[project.scripts] sentinel-app` is unconditional,
    so users running `sentinel-app` after a default `pipx install
    sentinel-mac` got ModuleNotFoundError. Promoted to required in v0.11.1."""
    import rumps  # noqa: F401


def test_ruamel_yaml_is_importable() -> None:
    """`ruamel.yaml` is used by `menubar_app.py` for round-trip YAML editing
    (preserves comments + key order when toggling Settings checkboxes).
    Same v0.11.1 promotion story as rumps."""
    import ruamel.yaml  # noqa: F401


def test_updater_version_module_imports_clean() -> None:
    """End-to-end: importing the consumer module that triggered the v0.10.x
    bug must not raise. Catches `from packaging.X import Y` style imports
    that the bare `import packaging` test above would miss if the upstream
    package's submodule layout changed."""
    from sentinel_mac.updater.version import is_update_available  # noqa: F401


def test_menubar_app_module_imports_clean() -> None:
    """End-to-end: the v0.11.1 bug was a clean `import sentinel_mac.menubar_app`
    failing because rumps/ruamel.yaml were not declared as runtime deps.
    With both declared this import must succeed."""
    import sentinel_mac.menubar_app  # noqa: F401


def test_all_top_level_imports_declared() -> None:
    """AST scanner — the real fail-fast guardrail.

    Walk every `.py` under `sentinel_mac/`, collect every `import X` and
    `from X import Y` (absolute imports only), strip out stdlib +
    self-package + obvious typing helpers, and assert every remaining
    top-level module appears in `pyproject.toml` `[project] dependencies`.

    Catches the v0.10.3 and v0.11.1 bug shapes automatically — no
    hand-curated list to keep in sync.

    Skipped on Python < 3.11 because `tomllib` is stdlib only there;
    the explicit-import tests above still run everywhere.
    """
    if sys.version_info < (3, 11):
        import pytest
        pytest.skip("tomllib requires Python 3.11+")
    import tomllib  # noqa: I001 — guarded by version check

    repo_root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text())
    declared_specs = pyproject["project"]["dependencies"]
    declared = {_pep508_name(spec) for spec in declared_specs}

    src_root = repo_root / "sentinel_mac"
    raw_imports = _scan_top_level_imports(src_root)

    # Map each imported module to its PyPI distribution candidate, then
    # filter stdlib + self-package.
    stdlib = set(sys.stdlib_module_names)
    external: set[str] = set()
    for module in raw_imports:
        top = module.split(".", 1)[0]
        if top == "sentinel_mac":
            continue
        if top in stdlib:
            continue
        dist = _module_to_dist(module)
        external.add(_IMPORT_TO_PYPI.get(dist, dist))

    missing = external - declared
    assert not missing, (
        f"top-level imports not declared in pyproject.toml [project] dependencies: "
        f"{sorted(missing)}.\n"
        "Either add them to `[project] dependencies` (so PyPI installs get them) "
        "or move them behind `if TYPE_CHECKING:` (so they don't run at import time)."
    )


def test_runtime_deps_match_pyproject() -> None:
    """Hand-curated backstop to the AST scanner above.

    The AST scanner is the real guardrail; this list is here so a
    breakage in the scanner (e.g. AST format change) still leaves a
    minimum baseline assertion. Update BOTH lists when adding new
    runtime imports.

    Skipped on Python < 3.11 (tomllib)."""
    if sys.version_info < (3, 11):
        import pytest
        pytest.skip("tomllib requires Python 3.11+")
    import tomllib  # noqa: I001

    repo_root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text())
    declared = {_pep508_name(spec) for spec in pyproject["project"]["dependencies"]}

    must_be_declared = {
        "packaging",     # updater/version.py — added 2026-05-05 / v0.10.3
        "psutil",        # collectors/system.py, collectors/net_tracker.py
        "pyyaml",        # core.py via `import yaml`
        "requests",      # notifier.py, updater/version.py
        "rumps",         # menubar_app.py — promoted to required v0.11.1
        "ruamel.yaml",   # menubar_app.py — promoted to required v0.11.1
        "watchdog",      # collectors/fs_watcher.py
    }

    missing = must_be_declared - declared
    assert not missing, (
        f"runtime imports not declared in pyproject.toml dependencies: {missing}. "
        "Add them to `[project] dependencies` so PyPI installs (pipx/pip-venv) "
        "get them."
    )


# ── helpers ────────────────────────────────────────────────────────────────


def _pep508_name(spec: str) -> str:
    """Extract package name from a PEP 508 dependency string.

    `packaging>=21,<26` → `packaging`
    `ruamel.yaml>=0.18,<1` → `ruamel.yaml`
    """
    return (
        spec.split("=", 1)[0].split("<", 1)[0].split(">", 1)[0]
            .split("!", 1)[0].split("~", 1)[0].split("[", 1)[0]
            .split(";", 1)[0].strip()
    )


def _scan_top_level_imports(root: Path) -> set[str]:
    """Walk every `.py` under root and return the set of dotted module
    names referenced by `import X.Y.Z` and `from X.Y.Z import W`.

    Only absolute imports are counted (relative imports are intra-package).
    Full dotted name is preserved so `_module_to_dist` can pick the right
    distribution form (e.g. `ruamel.yaml` vs plain `ruamel`).
    """
    found: set[str] = set()
    for path in root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name)
            elif (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module
            ):
                found.add(node.module)
    return found


def _module_to_dist(module: str) -> str:
    """Map an imported module name to its likely PyPI distribution name.

    For ordinary packages the top-level segment is the distribution
    (`packaging.version` → `packaging`). For namespace packages listed
    in `_NAMESPACE_PACKAGES`, the first TWO segments form the
    distribution (`ruamel.yaml` → `ruamel.yaml`).
    """
    parts = module.split(".")
    if parts[0] in _NAMESPACE_PACKAGES and len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]
