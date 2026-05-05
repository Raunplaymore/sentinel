"""Verification and summary for sentinel install (ADR 0011 §D2 steps 6-7).

Checks daemon liveness and builds post-install banner.
"""

import subprocess
from pathlib import Path
from typing import Optional, Tuple


def check_daemon_running(plist_name: str = "com.sentinel.agent", timeout: float = 5.0) -> Tuple[bool, Optional[int]]:
    """Check if LaunchAgent daemon is running via launchctl list.

    Used by ADR 0011 §D2 step 6 daemon liveness check.

    Args:
        plist_name: Label of the LaunchAgent (e.g., 'com.sentinel.agent').
        timeout: Subprocess timeout in seconds.

    Returns:
        Tuple of (is_running: bool, pid: Optional[int])
        - is_running=True if daemon is in launchctl list
        - pid=the PID if running, None otherwise
    """
    try:
        result = subprocess.run(
            ["launchctl", "list", plist_name],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            # Parse output: first line is PID (or "-" if running without PID)
            lines = result.stdout.strip().split("\n")
            if lines:
                first_line = lines[0].strip()
                if first_line == "-":
                    # Running but no PID
                    return True, None
                try:
                    pid = int(first_line)
                    return True, pid
                except ValueError:
                    # Not a PID, but daemon is listed
                    return True, None
        return False, None
    except subprocess.TimeoutExpired:
        return False, None
    except Exception:
        return False, None


def build_install_summary(
    config_path: Path,
    data_dir: Path,
    daemon_pid: Optional[int],
    no_launchagent: bool = False,
) -> str:
    """Build post-install banner (ADR 0011 §D8).

    Args:
        config_path: Absolute path to config.yaml.
        data_dir: Absolute path to data directory.
        daemon_pid: PID of running daemon, or None.
        no_launchagent: If True, show "not started" message.

    Returns:
        Formatted banner string.
    """
    # Format paths for display (~ expansion for readability)
    home = Path.home()
    try:
        config_display = "~/" + str(config_path.relative_to(home))
    except ValueError:
        config_display = str(config_path)

    try:
        data_display = "~/" + str(data_dir.relative_to(home))
    except ValueError:
        data_display = str(data_dir)

    if no_launchagent:
        daemon_line = "daemon:    not started (--no-launchagent; start manually)"
    elif daemon_pid:
        daemon_line = f"daemon:    running (PID {daemon_pid})"
    else:
        daemon_line = "daemon:    not running (check logs)"

    banner = f"""Sentinel installed.

  config:    {config_display}
  data dir:  {data_display}
  {daemon_line}

Next steps:
  - Notification channels are off by default. Edit config.yaml to enable ntfy/Slack/Telegram.
  - Claude Code hook is not installed. Run `sentinel hooks install` to enable.
  - macOS may prompt for Full Disk Access on first event. Allow it in:
      System Settings > Privacy & Security > Full Disk Access
"""
    return banner.rstrip() + "\n"
