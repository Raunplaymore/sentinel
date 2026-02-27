"""Tests for AlertEngine logic."""
import pytest
from datetime import datetime, timedelta

from sentinel_mac.core import (
    DEFAULT_CONFIG,
    SystemMetrics,
    Alert,
    AlertEngine,
)


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

    def test_long_session_alert(self):
        engine = AlertEngine(DEFAULT_CONFIG)
        now = datetime.now()
        ai_procs = [{"pid": 1, "name": "ollama", "cpu": 50.0, "mem_mb": 1000}]

        # First call starts session
        m1 = make_metrics(timestamp=now, ai_processes=ai_procs, ai_cpu_total=50.0)
        engine.evaluate(m1)

        # 4 hours later
        m2 = make_metrics(
            timestamp=now + timedelta(hours=4),
            ai_processes=ai_procs,
            ai_cpu_total=50.0,
        )
        alerts = engine.evaluate(m2)
        assert any(a.category == "long_session" for a in alerts)

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
