"""Helper functions for `sentinel uninstall` command (ADR 0011 Track B §D6)."""

import subprocess
from pathlib import Path


def unload_launchagent(plist_path: Path) -> tuple[bool, str]:
    """Unload LaunchAgent using launchctl.

    Tries modern `bootout` first, falls back to `unload` for older macOS.
    If the LaunchAgent is not loaded, returns success (idempotent).

    Args:
        plist_path: Path to the .plist file.

    Returns:
        (success: bool, log_message: str)
    """
    # Try modern bootout first
    try:
        result = subprocess.run(
            ["launchctl", "bootout", f"gui/{__import__('os').getuid()}", str(plist_path)],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if result.returncode == 0:
            return True, "launchctl bootout succeeded"

        # If bootout fails, try classic unload
        result = subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if result.returncode == 0:
            return True, "launchctl unload succeeded"

        # Both failed — but if error is "No such process", it's OK (already unloaded)
        if "No such process" in result.stderr or "not loaded" in result.stderr:
            return True, "LaunchAgent not loaded (already unloaded)"

        error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
        return False, f"launchctl unload failed: {error_msg}"

    except subprocess.TimeoutExpired:
        return False, "launchctl timed out"
    except Exception as e:
        return False, f"launchctl failed: {e}"


def remove_plist(plist_path: Path) -> bool:
    """Delete the plist file.

    If the file does not exist, returns True (idempotent — already cleaned up).

    Args:
        plist_path: Path to the .plist file.

    Returns:
        True if deleted or already absent, False on error.
    """
    if not plist_path.exists():
        return True

    try:
        plist_path.unlink()
        return True
    except Exception:
        return False


def collect_purge_targets(data_dir: Path, config_path: Path) -> list[Path]:
    """Collect all paths to delete in --purge mode.

    Includes:
    - config_path
    - events/*.jsonl files
    - updater/skipped_versions.txt

    The data_dir itself is NOT included (may contain user files).

    Args:
        data_dir: Path to data directory (e.g., ~/.local/share/sentinel).
        config_path: Path to config file (e.g., ~/.config/sentinel/config.yaml).

    Returns:
        List of paths to delete.
    """
    targets: list[Path] = []

    # Add config if it exists
    if config_path.exists():
        targets.append(config_path)

    # Add all event files
    events_dir = data_dir / "events"
    if events_dir.exists():
        for event_file in events_dir.glob("*.jsonl"):
            targets.append(event_file)

    # Add skipped_versions.txt
    skipped_versions = data_dir / "updater" / "skipped_versions.txt"
    if skipped_versions.exists():
        targets.append(skipped_versions)

    return targets


def remove_paths(paths: list[Path]) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Delete a list of paths.

    Args:
        paths: List of paths to delete.

    Returns:
        (removed: list of successfully deleted paths,
         errors: list of (path, reason) tuples for failures)
    """
    removed: list[Path] = []
    errors: list[tuple[Path, str]] = []

    for path in paths:
        try:
            if path.is_dir():
                import shutil
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(path)
        except Exception as e:
            errors.append((path, str(e)))

    return removed, errors
