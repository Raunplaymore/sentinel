"""CLI entry point for `sentinel install` command (ADR 0011 Track A)."""

import argparse
import contextlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sentinel_mac.core import PLIST_NAME, resolve_config_path, resolve_data_dir
from sentinel_mac.installer.config_init import ensure_config
from sentinel_mac.installer.plist import (
    existing_plist_install_method,
    generate_plist,
    plist_path,
    write_plist,
)
from sentinel_mac.installer.verify import build_install_summary, check_daemon_running
from sentinel_mac.updater.detect import InstallMethod, detect_install_method


def _make_json_envelope(
    kind: str,
    message: Optional[str] = None,
    config_path: Optional[str] = None,
    data_dir: Optional[str] = None,
    daemon_pid: Optional[int] = None,
) -> dict[str, Any]:
    """Create ADR 0004 §D2 versioned JSON envelope for install command.

    Args:
        kind: Envelope kind, e.g. "install" or "install_error".
        message: Error or success message (optional).
        config_path: Absolute path to config (optional).
        data_dir: Absolute path to data dir (optional).
        daemon_pid: PID of running daemon (optional).

    Returns:
        JSON-serializable dict.
    """
    data: dict[str, Any] = {}
    if message is not None:
        data["message"] = message
    if config_path is not None:
        data["config_path"] = config_path
    if data_dir is not None:
        data["data_dir"] = data_dir
    if daemon_pid is not None:
        data["daemon_pid"] = daemon_pid

    return {
        "version": 1,
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


def cmd_install(args: argparse.Namespace) -> int:
    """Handle `sentinel install` subcommand (ADR 0011 §D2 sequence).

    Implements the strict 7-step install sequence with idempotency,
    conflict detection, and rollback.

    Args:
        args: Parsed arguments from argparse.

    Returns:
        Exit code (0 = success, 1 = error, 2 = already installed, 3 = unsupported method).
    """
    # Step 1: Detect install method (ADR 0011 §D3)
    method = detect_install_method()

    if method == InstallMethod.EDITABLE:
        message = (
            "sentinel-mac is installed in editable/development mode.\n"
            "For development, use install.sh; sentinel install is for operational installs."
        )
        if args.json:
            print(json.dumps(_make_json_envelope("install_error", message=message)))
        else:
            print(message)
        return 3

    if method == InstallMethod.SYSTEM_UNSAFE:
        message = (
            "sentinel-mac appears to be installed under the system Python\n"
            "(/usr/bin/python3). Installation via sentinel install is not supported\n"
            "because write access requires sudo, which sentinel will never request.\n"
            "\n"
            "To install manually:\n"
            "  sudo pip install --upgrade sentinel-mac\n"
            "  launchctl load ~/Library/LaunchAgents/com.sentinel.agent.plist"
        )
        if args.json:
            print(json.dumps(_make_json_envelope("install_error", message=message)))
        else:
            print(message)
        return 3

    if method == InstallMethod.HOMEBREW:
        message = (
            "sentinel-mac appears to be managed by Homebrew.\n"
            "Homebrew formula is planned for v0.12. For now, use:\n"
            "  pipx install sentinel-mac && sentinel install"
        )
        if args.json:
            print(json.dumps(_make_json_envelope("install_error", message=message)))
        else:
            print(message)
        return 3

    # Resolve paths (steps 2-3)
    config_path = resolve_config_path() or (Path.home() / ".config" / "sentinel" / "config.yaml")
    data_dir = resolve_data_dir()

    # Check idempotency before prompting (ADR 0011 §D4)
    plist = plist_path()
    config_exists = config_path.exists()
    plist_exists = plist.exists()

    # Detect if daemon is running
    daemon_running, daemon_pid = check_daemon_running(PLIST_NAME, timeout=5.0)

    # Step 4: Conflict detection (ADR 0011 §D5)
    if plist_exists and not args.force:
        existing_method = existing_plist_install_method(plist)
        if existing_method in ("pip-venv", "editable"):
            # Conflict: dev install detected
            current_binary = str(Path(sys.executable).parent / "sentinel")
            warning = (
                f"warning: existing LaunchAgent points to a dev .venv:\n"
                f"  current plist: {existing_method} install\n"
                f"  this install:  {current_binary}\n"
                f"\n"
                f"To migrate from dev install to operational install, run:\n"
                f"  sentinel install --force\n"
                f"This will back up the existing plist and replace it."
            )
            if args.json:
                print(json.dumps(_make_json_envelope("install_error", message=warning)))
            else:
                print(warning)
            return 1

    # Idempotency: all artifacts exist and healthy
    if config_exists and plist_exists and daemon_running and not args.force:
        message = (
            "Sentinel is already installed and running. "
            "Use --force to reinstall."
        )
        if args.json:
            print(json.dumps(_make_json_envelope("install", message=message)))
        else:
            print(message)
        return 2

    # Step 5: Confirmation prompt (unless --yes or non-interactive)
    if not args.yes:
        if not sys.stdin.isatty():
            print("warning: sentinel install requires interactive confirmation", file=sys.stderr)
            print("run with --yes to skip confirmation (use in cron/CI only)", file=sys.stderr)
            return 1

        # Show what will be done (unless --json)
        if not args.json:
            print("\nSentinel install will:")
            if not config_exists or args.force:
                print("  - Create config.yaml at", config_path)
            if not plist_exists or args.force:
                print("  - Create LaunchAgent plist")
            if not daemon_running or args.force:
                print("  - Register and start the daemon")

        response = input("\nProceed? (y/n) > ").strip().lower()
        if response not in ("y", "yes"):
            if not args.json:
                print("Cancelled.")
            return 1

    # Track what was created for rollback
    created_paths: list[Path] = []
    backup_plist: Optional[Path] = None

    try:
        # Step 2: Config initialization (ADR 0011 §D2 step 2)
        if not args.no_launchagent:
            config_created = ensure_config(config_path, force=args.force)
            if config_created:
                created_paths.append(config_path)

        # Step 3: Data dir mkdir (ADR 0011 §D2 step 3)
        data_dir.mkdir(parents=True, exist_ok=True)

        # Step 4: Plist generation and write (ADR 0011 §D2 step 4)
        if not args.no_launchagent:
            binary_path = Path(sys.executable).parent / "sentinel"

            # Backup existing plist if --force
            if plist_exists and args.force:
                backup_plist = plist.parent / f"{plist.name}.bak"
                shutil.copy2(plist, backup_plist)

            # Generate and write plist
            plist_content = generate_plist(binary_path, data_dir)
            write_plist(plist_content, plist)
            if not plist_exists:
                created_paths.append(plist)

        # Step 5: launchctl load (ADR 0011 §D2 step 5)
        if not args.no_launchagent:
            # Unload first if --force and already loaded
            if args.force and daemon_running:
                try:
                    subprocess.run(
                        ["launchctl", "unload", str(plist)],
                        capture_output=True,
                        timeout=5.0,
                    )
                except Exception as e:
                    raise RuntimeError(f"Failed to unload LaunchAgent: {e}") from e

            # Load plist
            try:
                result = subprocess.run(
                    ["launchctl", "load", str(plist)],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                if result.returncode != 0:
                    error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                    raise RuntimeError(f"launchctl load failed: {error_msg}")
            except subprocess.TimeoutExpired as e:
                raise RuntimeError("launchctl load timed out") from e
            except Exception as e:
                raise RuntimeError(f"Failed to load LaunchAgent: {e}") from e

        # Step 6: Daemon liveness check (ADR 0011 §D2 step 6)
        if not args.no_launchagent:
            # Sleep briefly to allow daemon to start
            time.sleep(2)

            # Check if daemon is running
            daemon_running, daemon_pid = check_daemon_running(PLIST_NAME, timeout=5.0)
            if not daemon_running:
                raise RuntimeError(
                    "Daemon did not start after launchctl load.\n"
                    "Run `sentinel doctor` for diagnosis and manual recovery steps."
                )

        # Step 7: Post-install banner (ADR 0011 §D2 step 7, D8)
        if not args.no_launchagent:
            # Verify again to get fresh PID
            daemon_running, daemon_pid = check_daemon_running(PLIST_NAME, timeout=5.0)

        banner = build_install_summary(
            config_path,
            data_dir,
            daemon_pid,
            no_launchagent=args.no_launchagent,
        )

        if args.json:
            print(json.dumps(_make_json_envelope(
                "install",
                config_path=str(config_path),
                data_dir=str(data_dir),
                daemon_pid=daemon_pid,
            )))
        else:
            print(banner)

        return 0

    except Exception as e:
        # Rollback: delete newly created artifacts
        error_message = str(e)

        for path in reversed(created_paths):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except Exception:
                pass

        # Restore backup plist if exists
        if backup_plist and backup_plist.exists():
            with contextlib.suppress(Exception):
                shutil.move(str(backup_plist), str(plist))

        if args.json:
            print(json.dumps(_make_json_envelope("install_error", message=error_message)))
        else:
            print(f"error: {error_message}", file=sys.stderr)

        return 1


def dispatch(argv: list[str]) -> int:
    """Main dispatch entry for `sentinel install` subcommand.

    Args:
        argv: Command-line arguments (excluding the 'install' keyword).

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        prog="sentinel install",
        description="Install Sentinel as a persistent LaunchAgent daemon (ADR 0011 Track A)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall even if already installed; backs up existing plist",
    )
    parser.add_argument(
        "--no-launchagent",
        action="store_true",
        help="Create config only; do not register LaunchAgent (CLI-only users)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (for cron/CI use)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output (ADR 0004 §D2 versioned envelope, kind=install)",
    )

    args = parser.parse_args(argv)
    return cmd_install(args)
