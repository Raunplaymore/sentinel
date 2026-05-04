"""Version detection and comparison for self-update (ADR 0010 §D2)."""

import importlib.metadata
from typing import Optional

import requests
from packaging.version import Version

# PyPI JSON API endpoint for sentinel-mac
PYPI_JSON_URL = "https://pypi.org/pypi/sentinel-mac/json"

# User-Agent for identifying update-check traffic
USER_AGENT_TEMPLATE = "sentinel-mac/{version} (update-check)"


def get_running_version() -> str:
    """Get the currently running sentinel-mac version.

    Returns version string, e.g. "0.9.0".
    """
    return importlib.metadata.version("sentinel-mac")


def fetch_latest_pypi_version(timeout: float = 5.0) -> Optional[str]:
    """Fetch the latest version from PyPI.

    Args:
        timeout: HTTP request timeout in seconds. Defaults to 5.0.

    Returns:
        Version string (e.g. "0.10.0") or None on error/timeout.
    """
    running = get_running_version()
    headers = {"User-Agent": USER_AGENT_TEMPLATE.format(version=running)}

    try:
        response = requests.get(PYPI_JSON_URL, timeout=timeout, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("info", {}).get("version")
    except (requests.exceptions.RequestException, ValueError):
        return None


def is_update_available(running: str, latest: str) -> bool:
    """Check if an update is available.

    Args:
        running: Running version string, e.g. "0.9.0".
        latest: Latest available version string, e.g. "0.10.0".

    Returns:
        True if latest > running, False otherwise.
    """
    try:
        return Version(latest) > Version(running)
    except Exception:
        # Unparseable versions — assume no update available
        return False
