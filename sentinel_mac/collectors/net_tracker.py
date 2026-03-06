"""Sentinel — Per-Process Network Connection Tracker.

Tracks outbound network connections from AI processes using psutil.
Compares against an allowlist and flags unknown/suspicious hosts.
"""

import fnmatch
import logging
import queue
import socket
from datetime import datetime
from typing import Optional

import psutil

from sentinel_mac.models import SecurityEvent
from sentinel_mac.collectors.system import MacOSCollector

logger = logging.getLogger(__name__)

# Well-known ports that are generally safe
_STANDARD_PORTS = {80, 443, 8080, 8443, 22, 53}


class NetTracker:
    """Polls network connections and emits SecurityEvents for AI processes.

    Unlike FSWatcher (event-driven), NetTracker is polling-based and runs
    in the main loop alongside system metric collection.
    """

    AI_PROCESS_NAMES = MacOSCollector.AI_PROCESS_NAMES
    AI_CMDLINE_KEYWORDS = MacOSCollector.AI_CMDLINE_KEYWORDS
    GENERIC_PROCESS_NAMES = MacOSCollector.GENERIC_PROCESS_NAMES

    def __init__(self, config: dict, event_queue: queue.Queue):
        sec_config = config.get("security", {}).get("net_tracker", {})

        self._event_queue = event_queue
        self._alert_on_unknown = sec_config.get("alert_on_unknown", True)

        # Allowlist patterns (supports wildcards like *.github.com)
        self._allowlist = sec_config.get("allowlist", [
            "api.anthropic.com",
            "api.openai.com",
            "*.github.com",
            "*.githubusercontent.com",
            "pypi.org",
            "files.pythonhosted.org",
            "registry.npmjs.org",
            "ntfy.sh",
            "*.amazonaws.com",
            "*.cloudfront.net",
            "*.google.com",
            "*.googleapis.com",
        ])

        # Track seen connections to avoid duplicate alerts
        # Key: (pid, remote_ip, remote_port)
        self._seen_connections: dict[tuple, float] = {}
        self._seen_ttl = 300  # seconds — forget after 5 min

        # Reverse DNS cache: ip -> hostname
        self._dns_cache: dict[str, str] = {}

    def poll(self):
        """Scan current network connections and emit events for AI processes.

        Called from the main daemon loop each check interval.
        """
        now_ts = datetime.now()
        now_epoch = now_ts.timestamp()

        # Prune stale seen connections
        self._seen_connections = {
            k: v for k, v in self._seen_connections.items()
            if now_epoch - v < self._seen_ttl
        }

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as e:
            logger.debug(f"NetTracker: cannot read connections: {e}")
            return

        for conn in connections:
            if not conn.raddr or not conn.pid:
                continue

            # Only care about established outbound connections
            if conn.status != "ESTABLISHED":
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid

            # Skip if we've already seen this connection recently
            conn_key = (pid, remote_ip, remote_port)
            if conn_key in self._seen_connections:
                continue

            # Check if this is an AI process
            proc_name = self._get_process_name(pid)
            if not self._is_ai_process(proc_name, pid):
                continue

            # Resolve hostname
            hostname = self._resolve_hostname(remote_ip)
            display_host = hostname if hostname != remote_ip else remote_ip

            # Check allowlist
            is_allowed = self._is_allowed(hostname, remote_ip)

            # Check non-standard port
            is_nonstandard_port = remote_port not in _STANDARD_PORTS

            # Mark as seen
            self._seen_connections[conn_key] = now_epoch

            # Emit event if interesting
            if not is_allowed or is_nonstandard_port:
                detail = {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "hostname": display_host,
                    "allowed": is_allowed,
                    "nonstandard_port": is_nonstandard_port,
                }

                event = SecurityEvent(
                    timestamp=now_ts,
                    source="net_tracker",
                    actor_pid=pid,
                    actor_name=proc_name,
                    event_type="net_connect",
                    target=f"{display_host}:{remote_port}",
                    detail=detail,
                )

                try:
                    self._event_queue.put_nowait(event)
                except queue.Full:
                    logger.warning("NetTracker: event queue full, dropping event")

    def _get_process_name(self, pid: int) -> str:
        """Get process name by PID."""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def _get_process_cmdline(self, pid: int) -> str:
        """Get command line of a process by PID."""
        try:
            proc = psutil.Process(pid)
            return " ".join(proc.cmdline()).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return ""

    def _is_ai_process(self, name: str, pid: int) -> bool:
        """Check if a process is an AI agent."""
        if name == "unknown":
            return False

        lower_name = name.lower()

        if lower_name in self.AI_PROCESS_NAMES:
            return True

        if lower_name in self.GENERIC_PROCESS_NAMES:
            cmdline = self._get_process_cmdline(pid)
            if any(kw in cmdline for kw in self.AI_CMDLINE_KEYWORDS):
                return True

        return False

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup with caching."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]

        # Skip localhost
        if ip.startswith("127.") or ip == "::1":
            self._dns_cache[ip] = "localhost"
            return "localhost"

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            self._dns_cache[ip] = ip
            return ip

    def _is_allowed(self, hostname: str, ip: str) -> bool:
        """Check if a hostname/IP matches the allowlist."""
        for pattern in self._allowlist:
            if fnmatch.fnmatch(hostname, pattern):
                return True
            if fnmatch.fnmatch(ip, pattern):
                return True
        # Localhost is always allowed
        if ip.startswith("127.") or ip == "::1" or hostname == "localhost":
            return True
        return False
