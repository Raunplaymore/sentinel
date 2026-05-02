"""Sentinel — AI Agent Log Parser.

Parses Claude Code, Cursor, and VS Code Continue session logs in real-time
to detect high-risk tool invocations (Bash commands, file writes, etc.)
and MCP prompt injection attempts.

Key design decision (user requirement):
  When log files cannot be found, emit an explicit WARNING instead of
  silently failing. This handles path changes across agent updates.
"""

import glob
import json
import logging
import os
import queue
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from sentinel_mac.models import SecurityEvent
from sentinel_mac.collectors.context import HostContext, TrustLevel
from sentinel_mac.collectors.typosquatting import (
    check_typosquatting,
    extract_pip_packages,
    extract_npm_packages,
)

logger = logging.getLogger(__name__)

# ── Sensitive file path detection ─────────────────────────────────────────────
# Prefix-based: directories where any access is sensitive
_SENSITIVE_PREFIXES: list[str] = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.zshrc"),
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.gitconfig"),
    "/etc/",
    "/usr/local/bin/",
]

# Pattern-based: specific filenames sensitive regardless of directory
_SENSITIVE_FILENAME_RE = re.compile(
    r"(?:^|/)"
    r"(?:"
    r"\.env(?:\.[^/]*)?"              # .env, .env.local, .env.production, …
    r"|\.secrets?"                    # .secret, .secrets
    r"|credentials?"                  # credentials, credential
    r"|id_(?:rsa|dsa|ecdsa|ed25519)"  # SSH private keys
    r"|[^/]+\.pem"                    # *.pem
    r"|[^/]+\.key"                    # *.key
    r"|[^/]+\.p12"                    # *.p12 (PKCS12)
    r"|[^/]+\.pfx"                    # *.pfx
    r"|\.netrc"                       # ~/.netrc (stores auth tokens)
    r")"
    r"$",
    re.IGNORECASE,
)


def _is_sensitive_path(file_path: str) -> bool:
    """Return True if file_path targets a known-sensitive location or filename."""
    expanded = os.path.expanduser(file_path)
    for prefix in _SENSITIVE_PREFIXES:
        if expanded.startswith(prefix):
            return True
    return bool(_SENSITIVE_FILENAME_RE.search(expanded))


# High-risk command patterns (compiled for performance)
HIGH_RISK_PATTERNS = [
    (re.compile(r"curl\s+.*\|\s*(?:ba)?sh"), "pipe to shell"),
    (re.compile(r"wget\s+.*\|\s*(?:ba)?sh"), "pipe to shell"),
    (re.compile(r"chmod\s+\+x"), "make executable"),
    (re.compile(r"ssh\s+"), "SSH connection"),
    (re.compile(r"scp\s+"), "SCP file transfer"),
    (re.compile(r"rm\s+-rf\s+[~/]"), "dangerous recursive delete"),
    (re.compile(r"rm\s+-rf\s+/"), "dangerous recursive delete"),
    (re.compile(r"eval\s*\("), "dynamic eval"),
    (re.compile(r"base64\s+(-d|--decode)"), "base64 decode (encoding bypass)"),
    (re.compile(r"nc\s+-l"), "netcat listener"),
    (re.compile(r"python3?\s+-c\s+.*import\s+(socket|subprocess|os\.system)"), "inline code execution"),
    (re.compile(r"pip\s+install\s+(?!-r\s)(?!--upgrade\s+pip)"), "arbitrary package install"),
    (re.compile(r"npm\s+install\s+(?!--save-dev)(?!-D)"), "arbitrary package install"),
    (re.compile(r"brew\s+install"), "homebrew package install"),
]

# ── ADR 0001 D4: host-trust downgrade whitelist ─────────────────────────
# ONLY these high-risk reasons may have their severity downgraded by host
# trust signals (known_hosts / frequency learning). Every other reason is
# blocked from downgrade so an attacker cannot launder dangerous patterns
# (pipe-to-shell, rm -rf, eval, base64 -d, nc -l, inline code exec,
# package installs) by inflating the apparent trust of an associated host.
#
# The strings below MUST match HIGH_RISK_PATTERNS reason values exactly.
# See docs/decisions/0001-host-context.md (D4).
_TRUST_DOWNGRADABLE_REASONS: frozenset[str] = frozenset({
    "SSH connection",
    "SCP file transfer",
})

# Compiled once: pull the host token out of an SSH/SCP command line.
# Matches `ssh user@host`, `ssh host`, `ssh -p 22 host`, `scp file user@host:/path`.
# `user@` and `host:` separators are stripped; flags (-p, -i, -o ...) are
# skipped so the first non-flag positional argument is treated as the host.
_SSH_FLAG_RE = re.compile(r"^-")
_SSH_SCP_HOST_RE = re.compile(
    r"(?:^|[\s'\"])"          # start of string or whitespace
    r"(?:(?:ssh|scp))"        # ssh/scp leader (lowercased input)
    r"\b"
)


def _extract_ssh_host(command: str) -> Optional[str]:
    """Extract the remote hostname from an ssh/scp command line.

    Returns the bare hostname (lowercased, stripped of ``user@`` and any
    trailing ``:path``) or ``None`` if no plausible host token is found.

    Conservative parser — when in doubt, returns ``None`` so the caller
    falls back to default (high-risk) treatment rather than wrongly
    downgrading on a malformed line.
    """
    if not command:
        return None

    tokens = command.strip().split()
    if not tokens:
        return None

    leader = tokens[0].lower()
    if leader not in ("ssh", "scp"):
        return None

    # Walk remaining tokens, skipping flags and their arguments.
    # Recognized flag-with-argument forms: -p PORT, -i KEYFILE, -o OPT,
    # -l LOGIN, -F CONFIG, -J JUMP, -L/-R/-D PORTSPEC, -b BINDADDR.
    flags_with_arg = {"-p", "-i", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-e", "-m", "-Q", "-S", "-W", "-w"}

    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if _SSH_FLAG_RE.match(tok):
            # Combined `-pPORT` or `-oFOO=bar` — skip just this token.
            if len(tok) > 2 and tok[1] in {"p", "i", "o", "l", "F", "J", "L", "R", "D", "b", "c", "e", "m"}:
                i += 1
                continue
            if tok in flags_with_arg:
                i += 2  # consume flag + its argument
                continue
            i += 1
            continue

        # First non-flag token is the host (for scp it might be a local
        # filename, but we still try to extract a host from the *next*
        # token if this looks like a path).
        candidate = tok
        # scp source/destination form: try to find the user@host:/path
        # token; pick the first token containing ':' (host:path) or '@'.
        if leader == "scp" and ":" not in candidate and "@" not in candidate:
            # local file — keep scanning for a remote spec.
            i += 1
            continue

        # Strip user@
        if "@" in candidate:
            candidate = candidate.split("@", 1)[1]
        # Strip :path (scp)
        if ":" in candidate:
            candidate = candidate.split(":", 1)[0]
        # Strip [host]:port brackets if present
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:].split("]", 1)[0]

        candidate = candidate.strip().lower()
        if not candidate:
            return None
        return candidate

    return None


# MCP injection patterns — detect prompt injection in MCP tool responses
MCP_INJECTION_PATTERNS = [
    (re.compile(r"<system>|</system>", re.IGNORECASE), "system tag injection"),
    (re.compile(r"ignore\s+(previous|all|above)\s+instructions", re.IGNORECASE), "instruction override"),
    (re.compile(r"you\s+are\s+now\s+", re.IGNORECASE), "role hijacking"),
    (re.compile(r"(?:act|behave)\s+as\s+(?:if|a)\s+", re.IGNORECASE), "role hijacking"),
    (re.compile(r"do\s+not\s+tell\s+(?:the\s+)?user", re.IGNORECASE), "concealment attempt"),
    (re.compile(r"<\s*(?:img|script|iframe)\s+", re.IGNORECASE), "HTML/script injection"),
    (re.compile(r"(?:IMPORTANT|CRITICAL|URGENT):\s*(?:ignore|override|forget)", re.IGNORECASE), "urgency manipulation"),
    (re.compile(r"new\s+instructions?:\s*", re.IGNORECASE), "instruction injection"),
    (re.compile(r"(?:system|admin)\s*(?:prompt|message)\s*:", re.IGNORECASE), "fake system prompt"),
    (re.compile(r"<\|(?:im_start|im_end|endoftext)\|>", re.IGNORECASE), "token boundary injection"),
]

# Known Claude Code log locations
CLAUDE_CODE_LOG_DIRS = [
    "~/.claude/projects",
]

# Cursor log locations
CURSOR_LOG_DIRS = [
    "~/Library/Application Support/Cursor/User/workspaceStorage",
]


class AgentLogParser:
    """Parses AI agent session logs for security-relevant events.

    Runs a tail-f style reader in a background thread. New JSONL entries
    are parsed, filtered for tool_use events, and checked against
    high-risk patterns. Matching events are pushed to the shared queue.
    """

    def __init__(
        self,
        config: dict,
        event_queue: queue.Queue,
        host_ctx: Optional[HostContext] = None,
    ):
        sec_config = config.get("security", {}).get("agent_logs", {})

        self._event_queue = event_queue
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Host context — when None, build a disabled instance so calls are
        # cheap no-ops and existing tests keep working.
        if host_ctx is None:
            host_ctx = HostContext(
                enabled=False,
                cache_path=Path("/dev/null"),
            )
        self._host_ctx: HostContext = host_ctx

        # Configured parsers
        self._parsers = sec_config.get("parsers", [
            {"type": "claude_code", "log_dir": "~/.claude/projects"},
        ])

        # Per-rule toggles. All default ON (matches the parser's prior
        # behavior). Disabling a rule short-circuits its detection path so
        # the corresponding events are never queued.
        rules_config = sec_config.get("rules", {}) or {}
        self._rule_bash = bool(rules_config.get("bash", True))
        self._rule_sensitive_file = bool(rules_config.get("sensitive_file", True))
        self._rule_web_fetch = bool(rules_config.get("web_fetch", True))
        self._rule_mcp = bool(rules_config.get("mcp", True))
        self._rule_typosquatting = bool(rules_config.get("typosquatting", True))

        # Track file positions for tail-f style reading
        # Key: file path, Value: last read position
        self._file_positions: dict[str, int] = {}

        # Track which log files we've already warned about
        self._warned_paths: set[str] = set()

    def start(self):
        """Start the log parser in a background thread."""
        if self._running:
            return

        # Validate log directories exist — explicit warning per user requirement
        found_any = False
        for parser_config in self._parsers:
            log_dir = os.path.expanduser(parser_config.get("log_dir", ""))
            parser_type = parser_config.get("type", "unknown")

            if not os.path.isdir(log_dir):
                logger.warning(
                    f"AgentLogParser: {parser_type} log directory NOT FOUND: {log_dir} "
                    f"— this agent's activity will NOT be monitored. "
                    f"The path may have changed after an update. "
                    f"Check config: security.agent_logs.parsers"
                )
            else:
                found_any = True
                logger.info(f"AgentLogParser: monitoring {parser_type} logs at {log_dir}")

        if not found_any:
            logger.warning(
                "AgentLogParser: NO valid log directories found — "
                "agent log monitoring is DISABLED. "
                "Update security.agent_logs.parsers in config.yaml "
                "with correct paths for your AI tools."
            )
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("AgentLogParser: started")

    def stop(self):
        """Stop the parser thread."""
        if self._running:
            self._running = False
            if self._thread:
                self._thread.join(timeout=5)
            logger.info("AgentLogParser: stopped")

    def _run_loop(self):
        """Main loop: find new log entries every few seconds."""
        while self._running:
            try:
                for parser_config in self._parsers:
                    parser_type = parser_config.get("type", "unknown")
                    log_dir = os.path.expanduser(parser_config.get("log_dir", ""))

                    if parser_type == "claude_code":
                        self._scan_claude_code_logs(log_dir)
                    elif parser_type == "cursor":
                        self._scan_cursor_logs(log_dir)
            except Exception as e:
                logger.error(f"AgentLogParser error: {e}", exc_info=True)

            time.sleep(3)  # Poll every 3 seconds

    def _scan_claude_code_logs(self, base_dir: str):
        """Scan Claude Code JSONL session logs for new entries."""
        if not os.path.isdir(base_dir):
            return

        # Find all session JSONL files (not subagent files)
        pattern = os.path.join(base_dir, "*", "*.jsonl")
        log_files = glob.glob(pattern)

        for log_file in log_files:
            # Skip subagent logs (they're in subdirectories)
            if "/subagents/" in log_file:
                continue
            self._tail_jsonl(log_file, "claude_code")

    def _tail_jsonl(self, file_path: str, agent_type: str):
        """Read new lines from a JSONL file since last position."""
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            return

        last_pos = self._file_positions.get(file_path, 0)

        # If file is new to us, start from the end (don't parse history)
        if file_path not in self._file_positions:
            self._file_positions[file_path] = file_size
            return

        # No new data
        if file_size <= last_pos:
            return

        try:
            with open(file_path, "r") as f:
                f.seek(last_pos)
                new_data = f.read()
                self._file_positions[file_path] = f.tell()

            for line in new_data.strip().splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    self._process_claude_code_entry(entry)
                except json.JSONDecodeError:
                    continue

        except OSError as e:
            logger.debug(f"AgentLogParser: cannot read {file_path}: {e}")

    def _process_claude_code_entry(self, entry: dict):
        """Process a single Claude Code JSONL entry."""
        entry_type = entry.get("type", "")

        # Check tool_result for MCP injection
        if entry_type == "tool_result":
            if self._rule_mcp:
                self._check_mcp_tool_result(entry)
            return

        # Only interested in assistant messages with tool_use
        if entry_type != "assistant":
            return

        message = entry.get("message", {})
        content = message.get("content", [])

        if not isinstance(content, list):
            return

        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") != "tool_use":
                continue

            tool_name = block.get("name", "")
            tool_input = block.get("input", {})
            timestamp_str = entry.get("timestamp", "")

            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now()

            # Track MCP tool calls
            if tool_name.startswith("mcp__") and self._rule_mcp:
                self._handle_mcp_tool_call(tool_name, tool_input, timestamp)

            self._evaluate_tool_call(tool_name, tool_input, timestamp, entry)

    def _evaluate_tool_call(self, tool_name: str, tool_input: dict,
                            timestamp: datetime, entry: dict):
        """Check a tool call for security-relevant patterns."""
        events = []

        if tool_name == "Bash":
            command = tool_input.get("command", "")
            if self._rule_bash:
                events.extend(self._check_bash_command(command, timestamp, entry))
            if self._rule_typosquatting:
                events.extend(self._check_typosquatting(command, timestamp))

        elif tool_name in ("Write", "Edit"):
            if self._rule_sensitive_file:
                file_path = tool_input.get("file_path", "")
                events.extend(self._check_file_write(file_path, tool_name, timestamp))

        elif tool_name == "Read":
            if self._rule_sensitive_file:
                file_path = tool_input.get("file_path", "")
                events.extend(self._check_file_read(file_path, timestamp))

        elif tool_name == "WebFetch" and self._rule_web_fetch:
            url = tool_input.get("url", "")
            events.append(SecurityEvent(
                timestamp=timestamp,
                source="agent_log",
                actor_pid=0,
                actor_name="claude_code",
                event_type="agent_tool_use",
                target=url,
                detail={
                    "tool": "WebFetch",
                    "url": url,
                    "risk_reason": "external URL fetch",
                },
            ))

        for event in events:
            try:
                self._event_queue.put_nowait(event)
            except queue.Full:
                logger.warning("AgentLogParser: event queue full, dropping event")

    def _check_bash_command(self, command: str, timestamp: datetime,
                            entry: dict) -> list[SecurityEvent]:
        """Check a bash command against high-risk patterns.

        ADR 0001 D4: only patterns whose ``reason`` is in
        ``_TRUST_DOWNGRADABLE_REASONS`` (currently SSH/SCP) may have their
        severity downgraded by host trust signals. All other reasons are
        emitted with ``high_risk=True`` regardless of host context — this
        prevents an attacker from laundering pipe-to-shell, rm -rf, eval,
        base64 -d, nc -l, inline code execution, or arbitrary package
        installs by inflating an associated host's trust score.
        """
        events = []
        command_lower = command.lower()

        for pattern, reason in HIGH_RISK_PATTERNS:
            if not pattern.search(command_lower):
                continue

            detail: dict = {
                "tool": "Bash",
                "command": command[:500],
                "risk_reason": reason,
                "high_risk": True,
            }

            # ADR D4 enforcement: host-trust downgrade is restricted to a
            # frozen whitelist of reasons. Categories outside it skip the
            # context lookup entirely so trust signals can never weaken
            # the alert.
            if reason in _TRUST_DOWNGRADABLE_REASONS:
                host = _extract_ssh_host(command)
                if host:
                    self._host_ctx.observe(host)
                    trust = self._host_ctx.classify(host)
                    detail["trust_level"] = trust.value
                    if trust in (TrustLevel.LEARNED, TrustLevel.KNOWN):
                        detail["high_risk"] = False
                        detail["downgrade_reason"] = (
                            f"host trust={trust.value}"
                        )

            events.append(SecurityEvent(
                timestamp=timestamp,
                source="agent_log",
                actor_pid=0,
                actor_name="claude_code",
                event_type="agent_command",
                target=command[:200],  # Truncate for readability
                detail=detail,
            ))
            break  # One match is enough

        return events

    def _check_typosquatting(self, command: str,
                             timestamp: datetime) -> list[SecurityEvent]:
        """Check pip/npm install commands for typosquatted package names."""
        events = []

        packages = extract_pip_packages(command)
        if packages:
            ecosystem = "pip"
        else:
            packages = extract_npm_packages(command)
            if not packages:
                return events
            ecosystem = "npm"

        for pkg in packages:
            result = check_typosquatting(pkg, ecosystem)
            if result is None:
                continue

            events.append(SecurityEvent(
                timestamp=timestamp,
                source="agent_log",
                actor_pid=0,
                actor_name="claude_code",
                event_type="typosquatting_suspect",
                target=pkg,
                detail={
                    "tool": "Bash",
                    "command": command[:500],
                    "ecosystem": ecosystem,
                    "similar_to": result["similar_to"],
                    "edit_distance": result["edit_distance"],
                    "confidence": result["confidence"],
                    "risk_reason": (
                        f"typosquatting suspect: '{pkg}' "
                        f"looks like '{result['similar_to']}' "
                        f"(edit distance {result['edit_distance']})"
                    ),
                    "high_risk": result["confidence"] == "high",
                },
            ))

        return events

    def _check_file_write(self, file_path: str, tool_name: str,
                          timestamp: datetime) -> list[SecurityEvent]:
        """Check if a file write/edit targets a sensitive location."""
        if not _is_sensitive_path(file_path):
            return []
        return [SecurityEvent(
            timestamp=timestamp,
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="agent_tool_use",
            target=file_path,
            detail={
                "tool": tool_name,
                "file_path": file_path,
                "risk_reason": "write to sensitive file",
                "high_risk": True,
            },
        )]

    def _check_file_read(self, file_path: str,
                         timestamp: datetime) -> list[SecurityEvent]:
        """Check if a file read targets a sensitive location."""
        if not _is_sensitive_path(file_path):
            return []
        return [SecurityEvent(
            timestamp=timestamp,
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="agent_tool_use",
            target=file_path,
            detail={
                "tool": "Read",
                "file_path": file_path,
                "risk_reason": "read of sensitive file",
                "high_risk": True,
            },
        )]

    def _handle_mcp_tool_call(self, tool_name: str, tool_input: dict,
                              timestamp: datetime):
        """Log MCP tool calls as informational events."""
        # Parse mcp__serverName__toolName
        parts = tool_name.split("__")
        server_name = parts[1] if len(parts) >= 3 else "unknown"
        method_name = parts[2] if len(parts) >= 3 else tool_name

        event = SecurityEvent(
            timestamp=timestamp,
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="mcp_tool_call",
            target=f"{server_name}/{method_name}",
            detail={
                "tool": tool_name,
                "server": server_name,
                "method": method_name,
                "input_keys": list(tool_input.keys()) if isinstance(tool_input, dict) else [],
                "risk_reason": "MCP tool invocation",
            },
        )
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("AgentLogParser: event queue full, dropping MCP event")

    def _check_mcp_tool_result(self, entry: dict):
        """Check MCP tool_result responses for prompt injection patterns."""
        timestamp_str = entry.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.now()

        # Get the tool result content
        content = entry.get("content", "")
        tool_use_id = entry.get("tool_use_id", "")

        # Flatten content if it's a list of blocks
        if isinstance(content, list):
            text_parts = []
            for block in content:
                if isinstance(block, dict):
                    text_parts.append(block.get("text", ""))
                elif isinstance(block, str):
                    text_parts.append(block)
            content = " ".join(text_parts)

        if not isinstance(content, str) or not content:
            return

        # Check against injection patterns
        for pattern, reason in MCP_INJECTION_PATTERNS:
            if pattern.search(content):
                event = SecurityEvent(
                    timestamp=timestamp,
                    source="agent_log",
                    actor_pid=0,
                    actor_name="claude_code",
                    event_type="mcp_injection_suspect",
                    target=tool_use_id or "unknown_tool",
                    detail={
                        "tool_use_id": tool_use_id,
                        "risk_reason": f"MCP injection: {reason}",
                        "matched_pattern": reason,
                        "content_preview": content[:300],
                        "high_risk": True,
                    },
                )
                try:
                    self._event_queue.put_nowait(event)
                except queue.Full:
                    logger.warning("AgentLogParser: event queue full, dropping injection event")
                break  # One match is enough

    def _scan_cursor_logs(self, base_dir: str):
        """Scan Cursor workspace storage for AI conversation logs."""
        if not os.path.isdir(base_dir):
            return

        # Cursor stores conversation data in workspaceStorage subdirs
        # Look for files that contain AI conversation data
        for workspace_dir in Path(base_dir).iterdir():
            if not workspace_dir.is_dir():
                continue
            # Look for conversation/chat files
            for pattern in ["*.jsonl", "*.json"]:
                for log_file in workspace_dir.glob(pattern):
                    file_str = str(log_file)
                    # Skip files that don't look like AI conversation logs
                    name_lower = log_file.name.lower()
                    if not any(kw in name_lower for kw in ["chat", "conversation", "ai", "composer"]):
                        continue
                    self._tail_jsonl(file_str, "cursor")

    def parse_line(self, line: str):
        """Parse a single JSONL line. Public method for testing."""
        try:
            entry = json.loads(line)
            self._process_claude_code_entry(entry)
        except json.JSONDecodeError:
            pass
