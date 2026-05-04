"""CLI entry point for `sentinel update` command (ADR 0010 Track A)."""

import argparse
import json
from datetime import datetime, timezone
from typing import Any, Optional

from sentinel_mac.updater.detect import (
    InstallMethod,
    detect_install_method,
    get_source_root,
)
from sentinel_mac.updater.version import (
    fetch_latest_pypi_version,
    get_running_version,
    is_update_available,
)


def _make_json_envelope(
    kind: str,
    running: str,
    latest: Optional[str] = None,
    message: Optional[str] = None,
) -> dict[str, Any]:
    """Create ADR 0004 §D2 versioned JSON envelope.

    Args:
        kind: Envelope kind, e.g. "update_check".
        running: Running version.
        latest: Latest available version (optional).
        message: Message to include in data (optional).

    Returns:
        JSON-serializable dict.
    """
    data: dict[str, Any] = {"running": running}
    if latest is not None:
        data["latest"] = latest
    if message is not None:
        data["message"] = message

    return {
        "version": 1,
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


def cmd_update(args: argparse.Namespace) -> int:
    """Handle `sentinel update` subcommand.

    Args:
        args: Parsed arguments from argparse.

    Returns:
        Exit code (0 = success, 1 = error, 2 = update available, 3 = unsupported method).
    """
    running = get_running_version()

    # Determine if --apply or --check (default is --check)
    apply_mode = args.apply if hasattr(args, "apply") and args.apply else False

    if apply_mode:
        # Track B placeholder
        print("--apply not implemented yet (Track B); use --check")
        return 1

    # --check mode (or default)
    method = detect_install_method()

    # Early-exit for unsupported methods
    if method == InstallMethod.EDITABLE:
        source_root = get_source_root()
        source_root_str = str(source_root) if source_root else "<source_root>"
        message = (
            "sentinel-mac is installed in editable/development mode.\n"
            "Automatic update is disabled for this configuration.\n"
            "\n"
            "To update your source checkout:\n"
            f"  git -C {source_root_str} pull\n"
            "  pip install -e .    # if pyproject.toml dependencies changed"
        )
        if args.json:
            print(json.dumps(_make_json_envelope("update_check", running, message=message)))
        else:
            print(message)
        return 3

    if method == InstallMethod.SYSTEM_UNSAFE:
        message = (
            "sentinel-mac appears to be installed under the system Python\n"
            "(/usr/bin/python3). Automatic update is not supported for this\n"
            "configuration because write access requires sudo, which sentinel\n"
            "will never request.\n"
            "\n"
            "To update manually:\n"
            "  sudo pip install --upgrade sentinel-mac\n"
            "  launchctl unload ~/Library/LaunchAgents/com.sentinel.agent.plist\n"
            "  launchctl load  ~/Library/LaunchAgents/com.sentinel.agent.plist"
        )
        if args.json:
            print(json.dumps(_make_json_envelope("update_check", running, message=message)))
        else:
            print(message)
        return 3

    if method == InstallMethod.HOMEBREW:
        message = (
            "sentinel-mac appears to be managed by Homebrew.\n"
            "Automatic update via Homebrew is planned for v0.11.\n"
            "\n"
            "To update now:\n"
            "  brew upgrade sentinel-mac"
        )
        if args.json:
            print(json.dumps(_make_json_envelope("update_check", running, message=message)))
        else:
            print(message)
        return 3

    # Fetch latest version from PyPI
    latest = fetch_latest_pypi_version(timeout=5.0)

    if latest is None:
        message = "warning: could not reach PyPI (timeout)"
        if args.json:
            print(json.dumps(_make_json_envelope("update_check", running, message=message)))
        else:
            print(message)
        return 0

    # Check if update available
    if not is_update_available(running, latest):
        message = f"sentinel-mac {running} is up to date."
        if args.json:
            print(json.dumps(_make_json_envelope("update_check", running, latest=latest)))
        else:
            print(message)
        return 0

    # Update available
    message = f"sentinel-mac {running} → {latest} available\nrun: sentinel update --apply"
    if args.json:
        print(json.dumps(_make_json_envelope("update_check", running, latest=latest)))
    else:
        print(message)
    return 2


def dispatch(argv: list[str]) -> int:
    """Main dispatch entry for `sentinel update` subcommand.

    Args:
        argv: Command-line arguments (excluding the 'update' keyword).

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        prog="sentinel update",
        description="Check for and apply sentinel-mac updates (ADR 0010)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check for new version (default if no flag given)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply update (Track B — not yet implemented)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (used with --apply)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output (ADR 0004 §D2 versioned envelope)",
    )

    args = parser.parse_args(argv)

    # Normalize: --check is default if neither --apply nor explicit --check
    if not args.apply:
        args.check = True

    return cmd_update(args)
