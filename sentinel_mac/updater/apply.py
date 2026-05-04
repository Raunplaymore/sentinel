"""Apply update sequence (ADR 0010 §D3 Track B)."""

import fcntl
import importlib.metadata
import os
import subprocess
import sys
import time
from io import TextIOBase
from pathlib import Path
from typing import Optional

from sentinel_mac.updater.detect import InstallMethod


def run_upgrade(
    method: InstallMethod, new_version: Optional[str] = None
) -> subprocess.CompletedProcess[str]:
    """Install or upgrade sentinel-mac via the appropriate method.

    Args:
        method: InstallMethod enum value (PIPX or PIP_VENV).
        new_version: Version string to pin (for rollback). If provided,
                     upgrade command uses ==new_version. Otherwise upgrades
                     to latest.

    Returns:
        subprocess.CompletedProcess with returncode, stdout, stderr.

    Raises:
        FileNotFoundError: If pipx is not found on PATH.
        RuntimeError: For unsupported install methods.
    """
    if method == InstallMethod.PIPX:
        # pipx must be on PATH
        cmd: list[str] = ["pipx"]
        try:
            subprocess.run(
                [cmd[0], "--version"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except FileNotFoundError as e:
            raise FileNotFoundError("pipx not found on PATH") from e

        if new_version:
            cmd.extend(["install", "--force", f"sentinel-mac=={new_version}"])
        else:
            cmd.extend(["upgrade", "sentinel-mac"])

        return subprocess.run(cmd, timeout=120, capture_output=True, text=True)

    if method == InstallMethod.PIP_VENV:
        # Use sys.executable (venv python) for pip
        cmd = [sys.executable, "-m", "pip", "install"]
        if new_version:
            cmd.append(f"sentinel-mac=={new_version}")
        else:
            cmd.extend(["--upgrade", "sentinel-mac"])

        return subprocess.run(cmd, timeout=120, capture_output=True, text=True)

    raise RuntimeError(f"Unsupported install method for upgrade: {method}")


def stop_daemon(plist_path: Path) -> bool:
    """Stop the sentinel daemon via launchctl unload.

    Args:
        plist_path: Path to the LaunchAgent plist file.

    Returns:
        True if launchctl unload succeeded or plist not found (warning),
        False if launchctl unload failed.
    """
    if not plist_path.exists():
        print(
            f"warning: LaunchAgent plist not found: {plist_path}",
            file=sys.stderr,
        )
        return False

    result = subprocess.run(
        ["launchctl", "unload", str(plist_path)],
        timeout=5,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"error: launchctl unload failed: {result.stderr.strip()}",
            file=sys.stderr,
        )
        return False
    return True


def start_daemon(plist_path: Path) -> bool:
    """Start the sentinel daemon via launchctl load.

    Args:
        plist_path: Path to the LaunchAgent plist file.

    Returns:
        True if launchctl load succeeded, False otherwise.
    """
    if not plist_path.exists():
        print(
            f"warning: LaunchAgent plist not found: {plist_path}",
            file=sys.stderr,
        )
        return False

    result = subprocess.run(
        ["launchctl", "load", str(plist_path)],
        timeout=5,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"error: launchctl load failed: {result.stderr.strip()}",
            file=sys.stderr,
        )
        return False
    return True


def verify_running_version(expected: str) -> bool:
    """Verify that sentinel --version outputs the expected version.

    Args:
        expected: Expected version string (e.g. "0.10.0").

    Returns:
        True if first line of sentinel --version starts with
        f"sentinel-mac {expected}", False otherwise.
    """
    # Sleep 2 seconds to allow daemon to fully start
    time.sleep(2)

    result = subprocess.run(
        ["sentinel", "--version"],
        timeout=5,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return False

    first_line = result.stdout.strip().split("\n")[0]
    expected_prefix = f"sentinel-mac {expected}"
    return first_line.startswith(expected_prefix)


def acquire_update_lock(data_dir: Path) -> Optional[TextIOBase]:
    """Acquire exclusive lock on <data_dir>/updater.lock.

    Uses fcntl.flock(LOCK_EX | LOCK_NB). If already locked, returns None
    and does not raise; caller checks for None.

    Args:
        data_dir: Data directory path.

    Returns:
        Open file object if lock acquired, None if already locked.
    """
    lock_path = data_dir / "updater.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    # Open without context manager since we need to hold the file open
    # while maintaining the lock across the update sequence
    lock_fp: TextIOBase = open(lock_path, "w")  # noqa: SIM115
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        # Already locked by another process
        lock_fp.close()
        return None

    # Write our PID to the lockfile
    lock_fp.write(str(os.getpid()))
    lock_fp.flush()
    return lock_fp


def release_update_lock(lock_fp: Optional[TextIOBase], lock_path: Path) -> None:
    """Release exclusive lock and clean up lockfile.

    Args:
        lock_fp: File object returned by acquire_update_lock.
        lock_path: Path to lockfile.
    """
    if lock_fp is None:
        return

    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
        lock_fp.close()
        lock_path.unlink(missing_ok=True)
    except (OSError, AttributeError):
        # Already released or invalid object; ignore
        pass


def apply_update(
    method: InstallMethod,
    target_version: str,
    *,
    yes: bool,
    emit_json: bool,
    data_dir: Path,
    plist_path: Path,
) -> int:
    """Execute the full update sequence: lock → stop → install → start → verify → rollback-on-fail.

    Args:
        method: InstallMethod enum value (PIPX or PIP_VENV).
        target_version: New version to install (e.g. "0.10.0").
        yes: If True, skip confirmation prompt.
        emit_json: If True, emit ADR 0004 envelope to stdout.
        data_dir: Data directory for lockfile.
        plist_path: Path to LaunchAgent plist.

    Returns:
        Exit code: 0 (success), 1 (error/locked/cancelled), etc.
    """
    lock_fp: Optional[TextIOBase] = None
    lock_path = data_dir / "updater.lock"
    old_version: Optional[str] = None
    steps_completed: list[str] = []

    try:
        # Step 1: Acquire lock
        lock_fp = acquire_update_lock(data_dir)
        if lock_fp is None:
            # Already locked — read existing PID
            try:
                existing_pid = lock_path.read_text().strip()
            except (OSError, FileNotFoundError):
                existing_pid = "unknown"

            if emit_json:
                # JSON output to stdout
                import json
                from datetime import datetime, timezone

                envelope = {
                    "version": 1,
                    "kind": "update_apply",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "result": "locked",
                        "error": f"another sentinel update is in progress (PID {existing_pid})",
                    },
                }
                print(json.dumps(envelope))
            else:
                print(
                    f"another sentinel update is in progress (PID {existing_pid})",
                    file=sys.stderr,
                )

            return 1

        # Record old version for rollback
        old_version = importlib.metadata.version("sentinel-mac")

        # Step 2: Confirmation prompt (unless --yes)
        if not yes:
            if not sys.stdin.isatty():
                if emit_json:
                    import json
                    from datetime import datetime, timezone

                    envelope = {
                        "version": 1,
                        "kind": "update_apply",
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "data": {
                            "from_version": old_version,
                            "to_version": target_version,
                            "install_method": method.value,
                            "result": "cancelled",
                            "error": "non-interactive invocation without --yes",
                        },
                    }
                    print(json.dumps(envelope))
                else:
                    print(
                        "warning: cannot prompt in non-interactive mode. use --yes",
                        file=sys.stderr,
                    )
                return 1

            prompt_msg = (
                f"Sentinel will: stop daemon → install {target_version} "
                f"via {method.value} → restart. Proceed? [y/N]: "
            )
            try:
                response = input(prompt_msg).strip().lower()
                if response not in ("y", "yes"):
                    if emit_json:
                        import json
                        from datetime import datetime, timezone

                        envelope = {
                            "version": 1,
                            "kind": "update_apply",
                            "generated_at": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "data": {
                                "from_version": old_version,
                                "to_version": target_version,
                                "install_method": method.value,
                                "result": "cancelled",
                            },
                        }
                        print(json.dumps(envelope))
                    else:
                        print("cancelled", file=sys.stderr)
                    return 1
            except EOFError:
                if emit_json:
                    import json
                    from datetime import datetime, timezone

                    envelope = {
                        "version": 1,
                        "kind": "update_apply",
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "data": {
                            "from_version": old_version,
                            "to_version": target_version,
                            "install_method": method.value,
                            "result": "cancelled",
                        },
                    }
                    print(json.dumps(envelope))
                else:
                    print("cancelled", file=sys.stderr)
                return 1

        # Step 3: Stop daemon
        if stop_daemon(plist_path) and plist_path.exists():
            steps_completed.append("stop_daemon")

        # Step 4: Run upgrade subprocess
        try:
            result = run_upgrade(method)
            if result.returncode != 0:
                # Upgrade failed → attempt rollback
                steps_completed.append("upgrade_failed")

                if old_version:
                    print(
                        f"Upgrade failed. Attempting rollback to {old_version}...",
                        file=sys.stderr,
                    )
                    rollback_result = run_upgrade(method, new_version=old_version)
                    if rollback_result.returncode == 0:
                        steps_completed.append("rollback_succeeded")
                    else:
                        steps_completed.append("rollback_failed")
                        print(
                            f"Rollback failed. Manual recovery:\n"
                            f"  {method.value} install sentinel-mac=={old_version}",
                            file=sys.stderr,
                        )

                if emit_json:
                    import json
                    from datetime import datetime, timezone

                    envelope = {
                        "version": 1,
                        "kind": "update_apply",
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "data": {
                            "from_version": old_version,
                            "to_version": target_version,
                            "install_method": method.value,
                            "result": "failure",
                            "steps_completed": steps_completed,
                            "error": result.stderr.strip() if result.stderr else "unknown",
                        },
                    }
                    print(json.dumps(envelope))

                return 1
        except (FileNotFoundError, RuntimeError) as e:
            if emit_json:
                import json
                from datetime import datetime, timezone

                envelope = {
                    "version": 1,
                    "kind": "update_apply",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "from_version": old_version,
                        "to_version": target_version,
                        "install_method": method.value,
                        "result": "failure",
                        "steps_completed": steps_completed,
                        "error": str(e),
                    },
                }
                print(json.dumps(envelope))
            else:
                print(f"error: {e}", file=sys.stderr)
            return 1

        steps_completed.append("upgrade_succeeded")

        # Step 5: Start daemon
        if start_daemon(plist_path) and plist_path.exists():
            steps_completed.append("start_daemon")

        # Step 6: Verify
        if verify_running_version(target_version):
            steps_completed.append("verify_succeeded")

            if emit_json:
                import json
                from datetime import datetime, timezone

                envelope = {
                    "version": 1,
                    "kind": "update_apply",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "from_version": old_version,
                        "to_version": target_version,
                        "install_method": method.value,
                        "result": "success",
                        "steps_completed": steps_completed,
                    },
                }
                print(json.dumps(envelope))
            else:
                print(f"sentinel-mac updated to {target_version}")

            return 0
        else:
            # Verify failed — version mismatch
            steps_completed.append("verify_failed")

            if emit_json:
                import json
                from datetime import datetime, timezone

                envelope = {
                    "version": 1,
                    "kind": "update_apply",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "from_version": old_version,
                        "to_version": target_version,
                        "install_method": method.value,
                        "result": "failure",
                        "steps_completed": steps_completed,
                        "error": f"version mismatch after update (expected {target_version})",
                    },
                }
                print(json.dumps(envelope))
            else:
                print(
                    f"error: version mismatch after update (expected {target_version})",
                    file=sys.stderr,
                )

            return 1

    finally:
        if lock_fp is not None:
            release_update_lock(lock_fp, lock_path)
