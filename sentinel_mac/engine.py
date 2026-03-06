"""Sentinel — Alert Engine."""

from datetime import datetime
from collections import deque
from typing import Optional

from sentinel_mac.models import SystemMetrics, Alert, SecurityEvent


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

            if self._session_start:
                duration = (m.timestamp - self._session_start).total_seconds() / 3600
                session_limit = self.thresholds.get("session_hours_warning", 3)
                if duration >= session_limit:
                    top = m.ai_processes[0]
                    alerts.append(Alert(
                        level="info", category="long_session",
                        title="\u23f0 Long AI Session",
                        message=f"AI session running for {duration:.1f}h\n"
                               f"Top: {top['name']} (CPU {top['cpu']}%, MEM {top['mem_mb']}MB)",
                        emoji="\U0001f7e1", priority=3
                    ))

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
            return self._evaluate_net_event(event)
        if event.source == "agent_log":
            return self._evaluate_agent_log_event(event)
        return self._evaluate_fs_event(event)

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
            alerts.append(Alert(
                level="warning", category="fs_bulk_change",
                title="\U0001f4c1 Bulk File Changes Detected",
                message=f"{count} file operations in a short window.\n"
                       f"Possible automated mass modification.",
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
        elif event.event_type == "agent_tool_use" and tool == "WebFetch":
            # URL fetch — informational
            event.risk_score = 0.3
            alerts.append(Alert(
                level="info", category="agent_web_fetch",
                title="\U0001f310 AI Fetching External URL",
                message=f"{actor} fetching: {event.target}",
                emoji="\U0001f7e1", priority=2
            ))

        return self._apply_cooldowns(alerts, now=event.timestamp)

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
