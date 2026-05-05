"""CLI entry point for `sentinel uninstall` command (ADR 0011 Track B §D6)."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sentinel_mac.core import PLIST_NAME, resolve_config_path, resolve_data_dir
from sentinel_mac.installer.uninstall import (
    collect_purge_targets,
    remove_paths,
    remove_plist,
    unload_launchagent,
)


def _plist_path() -> Path:
    """Return path to the LaunchAgent plist."""
    return Path.home() / "Library" / "LaunchAgents" / f"{PLIST_NAME}.plist"


def _make_json_envelope(
    kind: str,
    message: Optional[str] = None,
    mode: Optional[str] = None,
    result: Optional[str] = None,
    removed_artifacts: Optional[list[str]] = None,
    preserved_artifacts: Optional[list[str]] = None,
    error: Optional[str] = None,
) -> dict[str, Any]:
    """Create ADR 0004 §D2 versioned JSON envelope for uninstall command.

    Args:
        kind: Envelope kind, e.g. "uninstall" or "uninstall_error".
        message: Plain text message (optional).
        mode: "standard" or "purge" (optional).
        result: "success", "not_installed", "cancelled", "failure" (optional).
        removed_artifacts: List of deleted paths (optional).
        preserved_artifacts: List of preserved paths (optional).
        error: Error message (optional).

    Returns:
        JSON-serializable dict.
    """
    data: dict[str, Any] = {}
    if message is not None:
        data["message"] = message
    if mode is not None:
        data["mode"] = mode
    if result is not None:
        data["result"] = result
    if removed_artifacts is not None:
        data["removed_artifacts"] = removed_artifacts
    if preserved_artifacts is not None:
        data["preserved_artifacts"] = preserved_artifacts
    if error is not None:
        data["error"] = error

    return {
        "version": 1,
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


def cmd_uninstall(args: argparse.Namespace) -> int:
    """Handle `sentinel uninstall` subcommand (ADR 0011 §D6 sequence).

    Args:
        args: Parsed arguments from argparse.

    Returns:
        Exit code (0 = success, 1 = error, 2 = not installed).
    """
    plist_path = _plist_path()
    config_path = resolve_config_path() or (Path.home() / ".config" / "sentinel" / "config.yaml")
    data_dir = resolve_data_dir()

    # Step 1: Detect not-installed state
    plist_exists = plist_path.exists()
    config_exists = config_path.exists()

    if not plist_exists and not config_exists:
        # Not installed
        if args.json:
            print(json.dumps(_make_json_envelope(
                "uninstall",
                result="not_installed",
                mode="standard" if not args.purge else "purge",
            )))
        else:
            print("Sentinel is not installed.")
        return 2

    mode = "purge" if args.purge else "standard"

    # Step 2: Confirmation prompt (unless --yes)
    if not args.yes:
        if not sys.stdin.isatty():
            print(
                "warning: sentinel uninstall requires interactive confirmation",
                file=sys.stderr,
            )
            print(
                "run with --yes to skip confirmation (use in cron/CI only)",
                file=sys.stderr,
            )
            if args.json:
                print(json.dumps(_make_json_envelope(
                    "uninstall",
                    result="cancelled",
                    mode=mode,
                )))
            return 1

        # Show prompt
        if args.purge:
            prompt = (
                "Sentinel will: stop daemon → remove LaunchAgent plist "
                "+ config + event history. THIS WILL DELETE YOUR EVENT LOG. "
                "Proceed? [y/N]: "
            )
        else:
            prompt = (
                "Sentinel will: stop daemon → remove LaunchAgent plist. "
                "Config and event history are preserved. Proceed? [y/N]: "
            )

        response = input(prompt).strip().lower()
        if response not in ("y", "yes"):
            if args.json:
                print(json.dumps(_make_json_envelope(
                    "uninstall",
                    result="cancelled",
                    mode=mode,
                )))
            else:
                print("Cancelled.")
            return 1

    removed_artifacts: list[str] = []
    preserved_artifacts: list[str] = []

    try:
        # Step 3: Unload LaunchAgent
        if plist_exists:
            success, log_message = unload_launchagent(plist_path)
            if not success:
                raise RuntimeError(f"Failed to unload LaunchAgent: {log_message}")

        # Step 4: Delete plist
        if plist_exists:
            if remove_plist(plist_path):
                removed_artifacts.append(str(plist_path))
            else:
                raise RuntimeError(f"Failed to delete plist: {plist_path}")

        # Step 5 (optional): --purge mode
        if args.purge:
            purge_targets = collect_purge_targets(data_dir, config_path)
            deleted, errors = remove_paths(purge_targets)
            for path in deleted:
                removed_artifacts.append(str(path))
            if errors:
                error_msg = "; ".join(f"{p}: {e}" for p, e in errors)
                raise RuntimeError(f"Failed to delete some purge targets: {error_msg}")
        else:
            # Standard mode: preserve config and data dir
            if config_exists:
                preserved_artifacts.append(str(config_path))
            if data_dir.exists():
                preserved_artifacts.append(str(data_dir))

        # Step 6: Output
        if args.json:
            print(json.dumps(_make_json_envelope(
                "uninstall",
                result="success",
                mode=mode,
                removed_artifacts=removed_artifacts,
                preserved_artifacts=preserved_artifacts,
            )))
        else:
            print(f"Sentinel uninstalled ({mode} mode).")
            if removed_artifacts:
                print("Removed:")
                for artifact in removed_artifacts:
                    print(f"  - {artifact}")
            if preserved_artifacts:
                print("Preserved:")
                for artifact in preserved_artifacts:
                    print(f"  - {artifact}")

        return 0

    except Exception as e:
        error_message = str(e)
        if args.json:
            print(json.dumps(_make_json_envelope(
                "uninstall_error",
                result="failure",
                mode=mode,
                error=error_message,
            )))
        else:
            print(f"error: {error_message}", file=sys.stderr)
        return 1


def dispatch(argv: list[str]) -> int:
    """Main dispatch entry for `sentinel uninstall` subcommand.

    Args:
        argv: Command-line arguments (excluding the 'uninstall' keyword).

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        prog="sentinel uninstall",
        description="Uninstall Sentinel LaunchAgent daemon (ADR 0011 Track B §D6)",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="Delete config and event history (default: preserve both)",
    )
    parser.add_argument(
        "--keep-launchagent",
        action="store_true",
        help="Skip unload/delete of plist; package can be separately removed via pipx",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (for cron/CI use)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output (ADR 0004 §D2 versioned envelope, kind=uninstall)",
    )

    args = parser.parse_args(argv)

    # Note: --keep-launchagent is parsed but currently not used (reserved for future).
    # Current implementation always removes plist. This allows the flag to be
    # documented in ADR D6 without affecting this MVP.

    return cmd_uninstall(args)
