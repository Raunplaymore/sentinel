"""Install method detection for self-update (ADR 0010 §D1)."""

import os
import sys
from enum import Enum
from pathlib import Path
from typing import Optional


class InstallMethod(Enum):
    """Detected install method for sentinel-mac."""

    EDITABLE = "editable"
    PIPX = "pipx"
    HOMEBREW = "homebrew"
    PIP_VENV = "pip_venv"
    SYSTEM_UNSAFE = "system_unsafe"


def get_source_root() -> Optional[Path]:
    """Resolve source root by walking up from sentinel_mac.__file__ to find pyproject.toml.

    Returns None if not found.
    """
    import sentinel_mac

    file_path = Path(sentinel_mac.__file__)
    for parent in file_path.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return None


def detect_install_method() -> InstallMethod:
    """Detect install method using path heuristics only (no subprocess).

    Returns the detected InstallMethod enum value.

    Priority (first match wins):
    1. EDITABLE: .egg-link, __editable__, or pyproject.toml in source tree
    2. PIPX: sys.executable contains /.local/pipx/venvs/ or PIPX_HOME env set
    3. HOMEBREW: sys.executable starts with /opt/homebrew/ or /usr/local/Cellar/
    4. PIP_VENV: sys.executable contains /.venv/ or /venv/
    5. SYSTEM_UNSAFE: /usr/bin/python3 or /usr/local/bin/python3 (not in venv)
    """
    import sentinel_mac

    sentinel_file = str(Path(sentinel_mac.__file__))
    executable = sys.executable

    # Check EDITABLE: three signals
    # 1. .egg-link (older PEP 660)
    if ".egg-link" in sentinel_file:
        return InstallMethod.EDITABLE
    # 2. __editable__ (modern PEP 660)
    if "__editable__" in sentinel_file:
        return InstallMethod.EDITABLE
    # 3. pyproject.toml exists in source tree
    if get_source_root() is not None:
        return InstallMethod.EDITABLE

    # Check PIPX
    pipx_home = os.environ.get("PIPX_HOME", "")
    if "/.local/pipx/venvs/" in executable or (
        pipx_home and executable.startswith(pipx_home)
    ):
        return InstallMethod.PIPX

    # Check HOMEBREW
    if executable.startswith("/opt/homebrew/") or executable.startswith(
        "/usr/local/Cellar/"
    ):
        return InstallMethod.HOMEBREW

    # Check PIP_VENV
    if "/.venv/" in executable or "/venv/" in executable:
        return InstallMethod.PIP_VENV

    # Check SYSTEM_UNSAFE
    if executable in ("/usr/bin/python3", "/usr/local/bin/python3"):
        return InstallMethod.SYSTEM_UNSAFE

    # Fallback to PIP_VENV as safest guess (most common real-world scenario)
    return InstallMethod.PIP_VENV
