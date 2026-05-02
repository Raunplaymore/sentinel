"""Sentinel — Alert Engine."""

import re
import logging
from datetime import datetime
from collections import deque
from pathlib import Path
from typing import Optional

from sentinel_mac.models import SystemMetrics, Alert, SecurityEvent

logger = logging.getLogger(__name__)


# ── ADR 0007 D6 — Forensic context [ctx] block ────────────────────────
# Append a short 4-line block (Project / Session / Where / What) to the
# Alert message so a single notification answers "who/where/what" without
# the user grepping the JSONL audit log.
#
# Privacy boundary (D7): `git.remote` is intentionally NOT surfaced in
# the user-visible alert text — it stays in the audit log only.

# macOS Notification Center truncates around ~250 chars; the `What:`
# line is the longest and most variable, so we cap it here. cwd gets
# `~/` substitution under HOME for the same reason.
_CTX_COMMAND_MAX_CHARS = 80


def _format_ctx_block(detail: dict) -> str:
    """ADR 0007 D6 — render the ``[ctx]`` block for an Alert message.

    Reads the ``session`` (D2) and ``project_meta`` (D3) sub-dicts from
    ``detail`` (both nullable, both may be missing on event types
    without enrichment such as MacOSCollector system-thermal alerts).

    Returns the empty string when neither block has anything to show —
    callers append unconditionally so it's safe to use ``message + ctx``.

    Output shape (each line indented 3 spaces to match the existing
    notification body convention):

        \\n
           Project: <name> (<branch> @ <head>)
           Session: <model> #<id8> (CC <version>)
           Where:   <cwd>
           What:    <command>

    Per ADR D7 the audit log keeps git.remote; this helper omits it.
    """
    if not isinstance(detail, dict):
        return ""

    session = detail.get("session") or {}
    project = detail.get("project_meta")

    lines: list[str] = []

    # Project line: name (branch @ head) | name (branch) | name
    if isinstance(project, dict):
        name = project.get("name")
        git = project.get("git") or {}
        branch = git.get("branch") if isinstance(git, dict) else None
        head = git.get("head") if isinstance(git, dict) else None
        if name and branch and head:
            lines.append(f"   Project: {name} ({branch} @ {head})")
        elif name and branch:
            lines.append(f"   Project: {name} ({branch})")
        elif name:
            lines.append(f"   Project: {name}")

    # Session line: model #shortid (CC version) | model #shortid | model | #shortid
    if isinstance(session, dict):
        sid = session.get("id")
        model = session.get("model")
        version = session.get("version")
        short_sid = (sid or "")[:8] if isinstance(sid, str) else ""
        if model and short_sid and version:
            lines.append(f"   Session: {model} #{short_sid} (CC {version})")
        elif model and short_sid:
            lines.append(f"   Session: {model} #{short_sid}")
        elif model:
            lines.append(f"   Session: {model}")
        elif short_sid:
            lines.append(f"   Session: #{short_sid}")

        cwd = session.get("cwd")
        if isinstance(cwd, str) and cwd:
            # macOS truncation guard: ~/ substitution under HOME (D6).
            try:
                home = str(Path.home())
                if home and cwd.startswith(home):
                    cwd = "~" + cwd[len(home):]
            except Exception:
                pass
            lines.append(f"   Where:   {cwd}")

    # What line: command (truncated to 80 chars per D6 macOS-tightened cap).
    command = detail.get("command")
    if isinstance(command, str) and command:
        if len(command) > _CTX_COMMAND_MAX_CHARS:
            command = command[: _CTX_COMMAND_MAX_CHARS - 1] + "…"
        lines.append(f"   What:    {command}")

    if not lines:
        return ""
    return "\n\n" + "\n".join(lines)


class AlertEngine:
    """Evaluates composite conditions and generates smart alerts."""

    def __init__(self, config: dict):
        self.config = config
        self.thresholds = config.get("thresholds", {})
        self._cooldowns: dict[str, datetime] = {}
        self._cooldown_minutes = config.get("cooldown_minutes", 10)
        self._history: deque = deque(maxlen=30)
        self._session_start: Optional[datetime] = None
        self._idle_start: Optional[datetime] = None
        self._custom_rules = self._compile_custom_rules(config)

    def evaluate(self, m: SystemMetrics) -> list[Alert]:
        self._history.append(m)
        alerts = []

        # -- Battery Alerts --
        if m.battery_percent is not None:
            if not m.battery_plugged:
                if m.battery_percent <= self.thresholds.get("battery_critical", 10):
                    alerts.append(Alert(
                        level="critical", category="battery_critical",
                        title="\U0001faab Battery Critical",
                        message=f"Battery at {m.battery_percent}% \u2014 plug in now!\n"
                               f"{'~' + str(m.battery_minutes_left) + ' min remaining' if m.battery_minutes_left else ''}",
                        emoji="\U0001f534", priority=5
                    ))
                elif m.battery_percent <= self.thresholds.get("battery_warning", 20):
                    time_msg = f"\n~{m.battery_minutes_left} min remaining" if m.battery_minutes_left else ""
                    ai_msg = f"\n{len(m.ai_processes)} AI process(es) running" if m.ai_processes else ""
                    alerts.append(Alert(
                        level="warning", category="battery_warning",
                        title="\U0001f50b Battery Low",
                        message=f"Battery {m.battery_percent}%, not charging{time_msg}{ai_msg}",
                        emoji="\U0001f7e0", priority=4
                    ))

                # Rapid drain detection (time-based: %/hour)
                if len(self._history) >= 3:
                    oldest = self._history[0]
                    elapsed_hours = (m.timestamp - oldest.timestamp).total_seconds() / 3600
                    if (elapsed_hours > 0.01
                            and oldest.battery_percent is not None
                            and m.battery_percent is not None):
                        drain_total = oldest.battery_percent - m.battery_percent
                        drain_per_hour = drain_total / elapsed_hours
                        threshold = self.thresholds.get("battery_drain_rate", 10)
                        if drain_per_hour > threshold:
                            alerts.append(Alert(
                                level="warning", category="battery_drain",
                                title="\u26a1 Rapid Battery Drain",
                                message=f"Drain rate: {drain_per_hour:.1f}%/hr\n"
                                       f"({drain_total:.1f}% lost in {elapsed_hours * 60:.0f} min)\n"
                                       f"AI CPU usage: {m.ai_cpu_total:.0f}%",
                                emoji="\U0001f7e0", priority=4
                            ))

        # -- Thermal Alerts --
        if m.cpu_temp is not None:
            if m.cpu_temp >= self.thresholds.get("temp_critical", 95):
                alerts.append(Alert(
                    level="critical", category="temp_critical",
                    title="\U0001f321\ufe0f CPU Overheating!",
                    message=f"CPU temp {m.cpu_temp}\u00b0C \u2014 throttling active\n"
                           f"Thermal: {m.thermal_pressure}\n"
                           f"{'Fan ' + str(m.fan_speed_rpm) + ' RPM' if m.fan_speed_rpm else ''}",
                    emoji="\U0001f534", priority=5
                ))
            elif m.cpu_temp >= self.thresholds.get("temp_warning", 85):
                alerts.append(Alert(
                    level="warning", category="temp_warning",
                    title="\U0001f321\ufe0f CPU Temperature High",
                    message=f"CPU {m.cpu_temp}\u00b0C | Fan {m.fan_speed_rpm or '?'} RPM\n"
                           f"CPU usage {m.cpu_percent}%",
                    emoji="\U0001f7e0", priority=3
                ))

        elif m.thermal_pressure in ("critical", "serious"):
            alerts.append(Alert(
                level="warning", category="thermal_pressure",
                title="\U0001f321\ufe0f System Throttling Detected",
                message=f"Thermal pressure: {m.thermal_pressure}\n"
                       f"CPU {m.cpu_percent}% | Memory {m.memory_percent}%",
                emoji="\U0001f7e0", priority=4
            ))

        # -- Memory Alerts --
        if m.memory_percent >= self.thresholds.get("memory_critical", 90):
            alerts.append(Alert(
                level="warning", category="memory_high",
                title="\U0001f4be Memory Critical",
                message=f"Memory at {m.memory_percent}% ({m.memory_used_gb}GB)\n"
                       f"AI processes using {m.ai_memory_total_mb:.0f}MB",
                emoji="\U0001f7e0", priority=4
            ))

        # -- Security Posture --
        disabled_controls = []
        if m.firewall_enabled is False:
            disabled_controls.append("Firewall")
        if m.gatekeeper_enabled is False:
            disabled_controls.append("Gatekeeper")
        if m.filevault_enabled is False:
            disabled_controls.append("FileVault")

        if disabled_controls:
            alerts.append(Alert(
                level="warning", category="security_posture",
                title="\U0001f6e1\ufe0f Security Posture Risk",
                message=f"Disabled protections: {', '.join(disabled_controls)}\n"
                       f"Re-enable them to reduce security exposure.",
                emoji="\U0001f7e0", priority=4
            ))

        # -- AI Process Alerts --
        if m.ai_processes:
            if self._session_start is None:
                self._session_start = m.timestamp
                self._idle_start = None

            if len(self._history) >= 5:
                recent = list(self._history)[-5:]
                avg_cpu = sum(h.ai_cpu_total for h in recent) / len(recent)
                avg_net = sum(h.net_sent_mb + h.net_recv_mb for h in recent) / len(recent)
                if avg_cpu > 50 and avg_net < 0.1:
                    alerts.append(Alert(
                        level="warning", category="stuck_process",
                        title="\U0001f504 Suspected Stuck Process",
                        message=f"AI process using {avg_cpu:.0f}% CPU\n"
                               f"but near-zero network I/O \u2014 possible infinite loop",
                        emoji="\U0001f7e0", priority=4
                    ))

        else:
            if self._session_start:
                duration = (m.timestamp - self._session_start).total_seconds() / 60
                if duration > 5:
                    alerts.append(Alert(
                        level="info", category="session_end",
                        title="\u2705 AI Session Ended",
                        message=f"Session duration: {duration:.0f} min",
                        emoji="\u2705", priority=2
                    ))
                self._session_start = None

            self._idle_start = self._idle_start or m.timestamp

        # -- Night Watch --
        hour = m.timestamp.hour
        if (0 <= hour <= 6) and m.ai_processes and not m.battery_plugged:
            alerts.append(Alert(
                level="warning", category="night_watch",
                title="\U0001f319 Unattended Night Session",
                message=f"{hour}:00 AM \u2014 AI session active + battery {m.battery_percent}%\n"
                       f"Charger not connected",
                emoji="\U0001f7e1", priority=4
            ))

        # -- Disk Alert --
        disk_threshold = self.thresholds.get("disk_critical", 90)
        if m.disk_percent >= disk_threshold:
            alerts.append(Alert(
                level="warning", category="disk_high",
                title="\U0001f4bf Disk Space Low",
                message=f"Disk usage at {m.disk_percent}%\n"
                       f"Remaining: {m.disk_free_gb}GB",
                emoji="\U0001f7e0", priority=4
            ))

        # -- Network Spike --
        total_mb = m.net_sent_mb + m.net_recv_mb
        net_threshold = self.thresholds.get("network_spike_mb", 100)
        if total_mb > net_threshold:
            alerts.append(Alert(
                level="info", category="network_spike",
                title="\U0001f4e1 Network Traffic Spike",
                message=f"This interval: \u2191{m.net_sent_mb:.1f}MB \u2193{m.net_recv_mb:.1f}MB\n"
                       f"Total {total_mb:.1f}MB",
                emoji="\U0001f7e1", priority=3
            ))

        return self._apply_cooldowns(alerts, now=m.timestamp)

    def evaluate_security_event(self, event: SecurityEvent) -> list[Alert]:
        """Convert a SecurityEvent into alerts based on risk rules."""
        if event.source == "net_tracker":
            alerts = self._evaluate_net_event(event)
        elif event.source == "agent_log":
            alerts = self._evaluate_agent_log_event(event)
        else:
            alerts = self._evaluate_fs_event(event)

        # ADR 0001: host-trust downgrade. Built-in alerts get one severity
        # step removed (warning -> info, critical -> warning) when the
        # collector marked the event as trustable. BLOCKED hosts are
        # explicitly exempt — even if `downgrade` was set upstream we
        # never weaken an alert against a user-blocklisted host. Custom
        # user rules below are intentionally NOT downgraded so user
        # intent always wins.
        alerts = self._apply_trust_downgrade(alerts, event)

        # Apply custom rules on top of built-in rules
        if self._custom_rules:
            custom_alerts = self._evaluate_custom_rules(event)
            alerts.extend(self._apply_cooldowns(custom_alerts, now=event.timestamp))

        # ADR 0007 D6 — append the [ctx] block to every alert message
        # produced from a SecurityEvent. The block is best-effort: when
        # neither `session` nor `project_meta` carry usable fields the
        # helper returns "" and the message is unchanged. Strict addition
        # to existing message text — preserves substring-based regression
        # tests (e.g., `assert "Risk: pipe to shell" in alert.message`).
        ctx_block = _format_ctx_block(event.detail)
        if ctx_block:
            for alert in alerts:
                alert.message = alert.message + ctx_block

        return alerts

    @staticmethod
    def _apply_trust_downgrade(
        alerts: list[Alert], event: SecurityEvent,
    ) -> list[Alert]:
        """Downgrade alert severity by one step when host trust signals it.

        Reads two optional fields populated by collectors:
            event.detail["downgrade"]    — bool, requested downgrade
            event.detail["trust_level"]  — "unknown"/"learned"/"known"/"blocked"

        BLOCKED takes precedence — a blocklisted host always preserves
        original severity, even if downgrade=True somehow leaked through.
        """
        if not alerts:
            return alerts
        if not event.detail.get("downgrade", False):
            return alerts
        if event.detail.get("trust_level") == "blocked":
            return alerts

        step = {"critical": "warning", "warning": "info", "info": "info"}
        for alert in alerts:
            alert.level = step.get(alert.level, alert.level)
        return alerts

    def _evaluate_fs_event(self, event: SecurityEvent) -> list[Alert]:
        """Evaluate file system security events."""
        alerts = []

        is_sensitive = event.detail.get("sensitive", False)
        is_executable = event.detail.get("executable", False)
        is_ai = event.detail.get("ai_process", False)
        actor = event.actor_name if event.actor_name != "unknown" else "Unknown process"

        # Bulk change alert
        if event.event_type == "bulk_change":
            count = event.detail.get("count", 0)
            project = event.detail.get("project", "")
            top_dirs = event.detail.get("top_directories", [])
            suspect = event.detail.get("suspect_process", "")
            suspect_pid = event.detail.get("suspect_pid", 0)

            msg_lines = [f"{count} file operations in a short window."]
            if project:
                msg_lines.append(f"Project: {project}")
            if suspect:
                msg_lines.append(f"Suspect process: {suspect} (PID {suspect_pid})")
            if top_dirs:
                msg_lines.append(f"Top dirs: {', '.join(top_dirs[:3])}")

            alerts.append(Alert(
                level="warning", category="fs_bulk_change",
                title="\U0001f4c1 Bulk File Changes Detected",
                message="\n".join(msg_lines),
                emoji="\U0001f7e0", priority=4
            ))
            return self._apply_cooldowns(alerts, now=event.timestamp)

        # Critical: AI process accessing sensitive files
        if is_sensitive and is_ai:
            event.risk_score = 0.9
            alerts.append(Alert(
                level="critical", category="fs_sensitive_ai",
                title="\U0001f6a8 AI Agent Accessed Sensitive File",
                message=f"{actor} (PID {event.actor_pid}) {event.event_type}: {event.target}",
                emoji="\U0001f534", priority=5
            ))
        # Warning: any process accessing sensitive files
        elif is_sensitive:
            event.risk_score = 0.7
            alerts.append(Alert(
                level="warning", category="fs_sensitive",
                title="\U0001f6e1\ufe0f Sensitive File Accessed",
                message=f"{actor} {event.event_type}: {event.target}",
                emoji="\U0001f7e0", priority=4
            ))
        # Warning: executable file created
        elif is_executable:
            event.risk_score = 0.6
            alerts.append(Alert(
                level="warning", category="fs_executable",
                title="\u26a0\ufe0f Executable File Created",
                message=f"{actor} created executable: {event.target}",
                emoji="\U0001f7e0", priority=4
            ))
        # Info: AI process modifying files (non-sensitive)
        elif is_ai:
            event.risk_score = 0.3
            alerts.append(Alert(
                level="info", category="fs_ai_activity",
                title="\U0001f4dd AI File Activity",
                message=f"{actor} {event.event_type}: {event.target}",
                emoji="\U0001f7e1", priority=2
            ))

        return self._apply_cooldowns(alerts, now=event.timestamp)

    def _evaluate_net_event(self, event: SecurityEvent) -> list[Alert]:
        """Evaluate network security events."""
        alerts = []
        actor = event.actor_name
        is_allowed = event.detail.get("allowed", True)
        is_nonstandard = event.detail.get("nonstandard_port", False)
        hostname = event.detail.get("hostname", event.target)
        port = event.detail.get("remote_port", 0)

        if not is_allowed and is_nonstandard:
            # Unknown host + non-standard port = highest risk
            event.risk_score = 0.9
            alerts.append(Alert(
                level="critical", category="net_unknown_suspicious",
                title="\U0001f6a8 Suspicious AI Network Connection",
                message=f"{actor} (PID {event.actor_pid}) connected to\n"
                       f"{hostname}:{port}\n"
                       f"Unknown host + non-standard port",
                emoji="\U0001f534", priority=5
            ))
        elif not is_allowed:
            # Unknown host on standard port
            event.risk_score = 0.7
            alerts.append(Alert(
                level="warning", category="net_unknown_host",
                title="\U0001f310 AI Connected to Unknown Host",
                message=f"{actor} (PID {event.actor_pid}) connected to\n"
                       f"{hostname}:{port}\n"
                       f"Host not in allowlist",
                emoji="\U0001f7e0", priority=4
            ))
        elif is_nonstandard:
            # Known host but non-standard port
            event.risk_score = 0.4
            alerts.append(Alert(
                level="info", category="net_nonstandard_port",
                title="\U0001f50c AI Using Non-Standard Port",
                message=f"{actor} connected to {hostname}:{port}",
                emoji="\U0001f7e1", priority=3
            ))

        return self._apply_cooldowns(alerts, now=event.timestamp)

    def _evaluate_agent_log_event(self, event: SecurityEvent) -> list[Alert]:
        """Evaluate agent log events (tool calls from Claude Code, Cursor, etc.)."""
        alerts = []
        actor = event.actor_name
        tool = event.detail.get("tool", "")
        risk_reason = event.detail.get("risk_reason", "")
        is_high_risk = event.detail.get("high_risk", False)

        if is_high_risk and event.event_type == "agent_command":
            # High-risk bash command
            event.risk_score = 0.9
            command = event.detail.get("command", event.target)
            alerts.append(Alert(
                level="critical", category="agent_high_risk_command",
                title="\U0001f6a8 High-Risk AI Command Detected",
                message=f"{actor} executed: {event.target}\n"
                       f"Risk: {risk_reason}",
                emoji="\U0001f534", priority=5
            ))
        elif is_high_risk and event.event_type == "agent_tool_use":
            # High-risk tool use (e.g. write to sensitive path)
            event.risk_score = 0.8
            alerts.append(Alert(
                level="warning", category="agent_sensitive_write",
                title="\U0001f6e1\ufe0f AI Writing to Sensitive Path",
                message=f"{actor} {tool}: {event.target}\n"
                       f"Risk: {risk_reason}",
                emoji="\U0001f7e0", priority=4
            ))
        elif event.event_type == "mcp_injection_suspect":
            # MCP prompt injection detected — critical
            event.risk_score = 0.95
            matched = event.detail.get("matched_pattern", "unknown")
            preview = event.detail.get("content_preview", "")[:150]
            alerts.append(Alert(
                level="critical", category="mcp_injection",
                title="\U0001f6a8 MCP Prompt Injection Detected",
                message=f"Suspicious content in MCP response:\n"
                       f"Pattern: {matched}\n"
                       f"Preview: {preview}...",
                emoji="\U0001f534", priority=5
            ))
        elif event.event_type == "mcp_tool_call":
            # MCP tool invocation — informational
            event.risk_score = 0.2
            server = event.detail.get("server", "unknown")
            method = event.detail.get("method", "unknown")
            alerts.append(Alert(
                level="info", category="mcp_tool_call",
                title="\U0001f50c MCP Tool Invocation",
                message=f"{actor} called {server}/{method}",
                emoji="\U0001f7e1", priority=2
            ))
        elif event.event_type == "typosquatting_suspect":
            similar_to = event.detail.get("similar_to", "?")
            confidence = event.detail.get("confidence", "medium")
            ecosystem = event.detail.get("ecosystem", "")
            # NOTE (v0.8 defect fix): collector
            # (agent_log_parser._check_typosquatting) now sets risk_score
            # before the JSONL audit write so audit-log severity matches
            # the alert. We re-assert the same mapping here idempotently
            # for backward compatibility — engine remains the source of
            # the alert level, collector is the source of the persisted
            # score, and the two stay in lockstep.
            event.risk_score = 0.9 if confidence == "high" else 0.6
            level = "critical" if confidence == "high" else "warning"
            alerts.append(Alert(
                level=level, category="typosquatting_suspect",
                title="\U0001f4e6 Typosquatting Suspect Package",
                message=(
                    f"{actor} installing '{event.target}' via {ecosystem}\n"
                    f"Looks like '{similar_to}' — possible typosquat or hallucination"
                ),
                emoji="\U0001f7e0", priority=4
            ))
        elif event.event_type == "agent_tool_use" and tool == "WebFetch":
            # URL fetch — informational
            event.risk_score = 0.3
            alerts.append(Alert(
                level="info", category="agent_web_fetch",
                title="\U0001f310 AI Fetching External URL",
                message=f"{actor} fetching: {event.target}",
                emoji="\U0001f7e1", priority=2
            ))
        elif event.event_type == "agent_download":
            # ADR 0002 §D5 — agent_log_parser already set risk_score per
            # the severity matrix (sensitive path → 0.9, BLOCKED/UNKNOWN
            # host → 0.5, KNOWN/LEARNED host → 0.2). The engine does NOT
            # re-score; it only maps the score to an Alert level so the
            # macOS notification channel actually fires.
            score = event.risk_score
            source_url = event.detail.get("source_url", event.target)
            output_path = event.detail.get("output_path") or "(unknown path)"
            downloader = event.detail.get("downloader", "?")
            if score >= 0.8:
                # critical — sensitive output_path
                alerts.append(Alert(
                    level="critical", category="agent_download_sensitive",
                    title="\U0001f6a8 AI Downloading to Sensitive Path",
                    message=f"{actor} via {downloader}\n"
                           f"From: {source_url}\n"
                           f"To:   {output_path}",
                    emoji="\U0001f534", priority=5
                ))
            elif score >= 0.5:
                # warning — BLOCKED or UNKNOWN host
                trust = event.detail.get("trust_level", "unknown")
                alerts.append(Alert(
                    level="warning", category="agent_download_untrusted",
                    title="\U0001f4e5 AI Download from Untrusted Host",
                    message=f"{actor} via {downloader} (host trust: {trust})\n"
                           f"From: {source_url}\n"
                           f"To:   {output_path}",
                    emoji="\U0001f7e0", priority=4
                ))
            else:
                # info — KNOWN/LEARNED host
                alerts.append(Alert(
                    level="info", category="agent_download",
                    title="\U0001f4e5 AI Download",
                    message=f"{actor} via {downloader}\n"
                           f"From: {source_url}\n"
                           f"To:   {output_path}",
                    emoji="\U0001f7e1", priority=2
                ))

        return self._apply_cooldowns(alerts, now=event.timestamp)

    @staticmethod
    def _compile_custom_rules(config: dict) -> list:
        """Compile user-defined custom rules from config."""
        rules = []
        raw = config.get("security", {}).get("custom_rules", [])
        for r in raw:
            name = r.get("name", "Unnamed rule")
            pattern = r.get("pattern", "")
            source = r.get("source", "all")
            level = r.get("level", "warning")
            if level not in ("critical", "warning", "info"):
                level = "warning"
            if not pattern:
                continue
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                rules.append({
                    "name": name,
                    "pattern": compiled,
                    "source": source,
                    "level": level,
                })
            except re.error as e:
                logger.warning("Invalid custom rule regex '{}': {}".format(name, e))
        if rules:
            logger.info("Loaded {} custom rule(s)".format(len(rules)))
        return rules

    def _evaluate_custom_rules(self, event: SecurityEvent) -> list[Alert]:
        """Match event against user-defined custom rules."""
        alerts = []
        # Build text to match against: target + detail values
        match_text = event.target or ""
        for v in event.detail.values():
            if isinstance(v, str):
                match_text += " " + v

        for rule in self._custom_rules:
            # Filter by source if specified
            if rule["source"] != "all" and rule["source"] != event.source:
                continue
            if rule["pattern"].search(match_text):
                level = rule["level"]
                risk = {"critical": 0.9, "warning": 0.7, "info": 0.3}.get(level, 0.7)
                event.risk_score = max(event.risk_score, risk)
                emoji = {"critical": "\U0001f534", "warning": "\U0001f7e0", "info": "\U0001f7e1"}.get(level, "\U0001f7e0")
                alerts.append(Alert(
                    level=level,
                    category="custom_{}".format(rule["name"].lower().replace(" ", "_")),
                    title="\U0001f6a8 Custom Rule: {}".format(rule["name"]),
                    message="Matched: {}\nTarget: {}".format(rule["pattern"].pattern, event.target or "N/A"),
                    emoji=emoji,
                    priority=5 if level == "critical" else 4 if level == "warning" else 2,
                ))
        return alerts

    def _apply_cooldowns(self, alerts: list[Alert], now: Optional[datetime] = None) -> list[Alert]:
        """Prevent alert spam by enforcing cooldown per category."""
        now = now or datetime.now()
        filtered = []
        for alert in alerts:
            last = self._cooldowns.get(alert.category)
            cooldown = self._cooldown_minutes
            if alert.level == "critical":
                cooldown = max(2, cooldown // 3)

            if last is None or (now - last).total_seconds() > cooldown * 60:
                filtered.append(alert)
                self._cooldowns[alert.category] = now
        return filtered
