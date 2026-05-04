"""Tests for NetTracker and network security event evaluation."""
import queue
from datetime import datetime
from unittest.mock import MagicMock, patch

from sentinel_mac.collectors.context import HostContext
from sentinel_mac.collectors.net_tracker import NetTracker
from sentinel_mac.core import DEFAULT_CONFIG
from sentinel_mac.engine import AlertEngine
from sentinel_mac.models import SecurityEvent

# ─── NetTracker unit tests ───


class TestNetTrackerAllowlist:
    """Tests for allowlist matching."""

    def _make_tracker(self, **overrides):
        config = {
            "security": {
                "net_tracker": {
                    "allowlist": [
                        "api.anthropic.com",
                        "*.github.com",
                        "pypi.org",
                    ],
                    **overrides,
                }
            }
        }
        q = queue.Queue(maxsize=100)
        return NetTracker(config, q), q

    def test_exact_match_allowed(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_allowed("api.anthropic.com", "1.2.3.4") is True

    def test_wildcard_match_allowed(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_allowed("api.github.com", "1.2.3.4") is True
        assert tracker._is_allowed("raw.github.com", "1.2.3.4") is True

    def test_unknown_host_not_allowed(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_allowed("evil-server.ru", "5.6.7.8") is False

    def test_localhost_always_allowed(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_allowed("localhost", "127.0.0.1") is True

    def test_loopback_ip_always_allowed(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_allowed("127.0.0.1", "127.0.0.1") is True


class TestNetTrackerAIDetection:
    """Tests for AI process identification."""

    def _make_tracker(self):
        config = {"security": {"net_tracker": {}}}
        q = queue.Queue(maxsize=100)
        return NetTracker(config, q), q

    def test_known_ai_process(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_ai_process("ollama", 1234) is True

    def test_unknown_process(self):
        tracker, _ = self._make_tracker()
        assert tracker._is_ai_process("unknown", 0) is False

    def test_generic_with_ai_cmdline(self):
        tracker, _ = self._make_tracker()
        with patch.object(tracker, "_get_process_cmdline", return_value="node claude-code"):
            assert tracker._is_ai_process("node", 1234) is True

    def test_generic_without_ai_cmdline(self):
        tracker, _ = self._make_tracker()
        with patch.object(tracker, "_get_process_cmdline", return_value="node server.js"):
            assert tracker._is_ai_process("node", 1234) is False


class TestNetTrackerDNS:
    """Tests for reverse DNS resolution."""

    def _make_tracker(self):
        config = {"security": {"net_tracker": {}}}
        q = queue.Queue(maxsize=100)
        return NetTracker(config, q), q

    def test_localhost_resolution(self):
        tracker, _ = self._make_tracker()
        assert tracker._resolve_hostname("127.0.0.1") == "localhost"

    def test_cache_hit(self):
        tracker, _ = self._make_tracker()
        tracker._dns_cache["1.2.3.4"] = "cached.example.com"
        assert tracker._resolve_hostname("1.2.3.4") == "cached.example.com"

    def test_failed_resolution_returns_ip(self):
        tracker, _ = self._make_tracker()
        with patch("socket.gethostbyaddr", side_effect=OSError("no DNS")):
            result = tracker._resolve_hostname("10.99.99.99")
            assert result == "10.99.99.99"


class TestNetTrackerPoll:
    """Tests for the poll() method."""

    def _make_tracker(self):
        config = {
            "security": {
                "net_tracker": {
                    "allowlist": ["api.anthropic.com"],
                }
            }
        }
        q = queue.Queue(maxsize=100)
        return NetTracker(config, q), q

    def _make_connection(self, pid, remote_ip, remote_port, status="ESTABLISHED"):
        conn = MagicMock()
        conn.pid = pid
        conn.status = status
        raddr = MagicMock()
        raddr.ip = remote_ip
        raddr.port = remote_port
        conn.raddr = raddr
        return conn

    def test_emits_event_for_unknown_host(self):
        tracker, q = self._make_tracker()
        conn = self._make_connection(1234, "5.6.7.8", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname", return_value="evil.example.com"):
            tracker.poll()

        assert not q.empty()
        event = q.get_nowait()
        assert event.source == "net_tracker"
        assert event.event_type == "net_connect"
        assert event.detail["allowed"] is False

    def test_no_event_for_allowed_host(self):
        tracker, q = self._make_tracker()
        conn = self._make_connection(1234, "1.2.3.4", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname", return_value="api.anthropic.com"):
            tracker.poll()

        # Allowed host on standard port — no event
        assert q.empty()

    def test_event_for_nonstandard_port_on_allowed_host(self):
        tracker, q = self._make_tracker()
        conn = self._make_connection(1234, "1.2.3.4", 4444)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname", return_value="api.anthropic.com"):
            tracker.poll()

        assert not q.empty()
        event = q.get_nowait()
        assert event.detail["nonstandard_port"] is True

    def test_no_duplicate_events(self):
        tracker, q = self._make_tracker()
        conn = self._make_connection(1234, "5.6.7.8", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname", return_value="evil.example.com"):
            tracker.poll()
            tracker.poll()  # Second poll — same connection

        # Should only get one event
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        assert len(events) == 1

    def test_skips_non_ai_processes(self):
        tracker, q = self._make_tracker()
        conn = self._make_connection(1234, "5.6.7.8", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="safari"), \
             patch.object(tracker, "_is_ai_process", return_value=False):
            tracker.poll()

        assert q.empty()

    def test_skips_non_established(self):
        tracker, q = self._make_tracker()
        conn = self._make_connection(1234, "5.6.7.8", 443, status="SYN_SENT")

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"):
            tracker.poll()

        assert q.empty()


# ─── AlertEngine network event evaluation tests ───


class TestNetworkEventAlerts:
    """Tests for AlertEngine._evaluate_net_event."""

    def setup_method(self):
        self.engine = AlertEngine(DEFAULT_CONFIG)

    def _make_event(self, **kwargs):
        defaults = {
            "timestamp": datetime.now(),
            "source": "net_tracker",
            "actor_pid": 1234,
            "actor_name": "ollama",
            "event_type": "net_connect",
            "target": "evil.example.com:443",
            "detail": {
                "remote_ip": "5.6.7.8",
                "remote_port": 443,
                "hostname": "evil.example.com",
                "allowed": False,
                "nonstandard_port": False,
            },
        }
        defaults.update(kwargs)
        return SecurityEvent(**defaults)

    def test_unknown_host_standard_port_warning(self):
        event = self._make_event()
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "warning"
        assert alerts[0].category == "net_unknown_host"

    def test_unknown_host_nonstandard_port_critical(self):
        event = self._make_event(
            detail={
                "remote_ip": "5.6.7.8",
                "remote_port": 4444,
                "hostname": "evil.example.com",
                "allowed": False,
                "nonstandard_port": True,
            }
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "critical"
        assert alerts[0].category == "net_unknown_suspicious"

    def test_allowed_host_nonstandard_port_info(self):
        event = self._make_event(
            detail={
                "remote_ip": "1.2.3.4",
                "remote_port": 9999,
                "hostname": "api.anthropic.com",
                "allowed": True,
                "nonstandard_port": True,
            }
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "info"
        assert alerts[0].category == "net_nonstandard_port"

    def test_allowed_host_standard_port_no_alert(self):
        event = self._make_event(
            detail={
                "remote_ip": "1.2.3.4",
                "remote_port": 443,
                "hostname": "api.anthropic.com",
                "allowed": True,
                "nonstandard_port": False,
            }
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 0

    def test_net_event_cooldown(self):
        event = self._make_event()
        alerts1 = self.engine.evaluate_security_event(event)
        alerts2 = self.engine.evaluate_security_event(event)
        assert len(alerts1) == 1
        assert len(alerts2) == 0  # Suppressed by cooldown


# ─── NetTracker × HostContext integration tests (v0.6) ───


class TestNetTrackerWithContext:
    """Integration: NetTracker emits trust_level + downgrade in event detail.

    Disabled context must preserve prior behavior exactly (regression
    guard). Enabled context must populate trust_level and set the
    downgrade flag for KNOWN/LEARNED hosts only — never for BLOCKED.
    """

    def _make_connection(self, pid, remote_ip, remote_port,
                         status="ESTABLISHED"):
        conn = MagicMock()
        conn.pid = pid
        conn.status = status
        raddr = MagicMock()
        raddr.ip = remote_ip
        raddr.port = remote_port
        conn.raddr = raddr
        return conn

    def _make_tracker(self, host_ctx=None):
        config = {
            "security": {
                "net_tracker": {
                    "allowlist": ["api.anthropic.com"],
                }
            }
        }
        q = queue.Queue(maxsize=100)
        return NetTracker(config, q, host_ctx=host_ctx), q

    def test_disabled_context_default_trust_unknown(self, tmp_path):
        """No host_ctx kwarg → disabled HostContext, trust=unknown, downgrade=False."""
        tracker, q = self._make_tracker(host_ctx=None)
        conn = self._make_connection(1234, "5.6.7.8", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname",
                          return_value="evil.example.com"):
            tracker.poll()

        event = q.get_nowait()
        assert event.detail["trust_level"] == "unknown"
        assert event.detail["downgrade"] is False

    def test_known_host_marks_downgrade(self, tmp_path):
        """known_hosts match → trust=known, downgrade=True."""
        kh = tmp_path / "known_hosts"
        kh.write_text(
            "bastion.example.com ssh-ed25519 AAAA...\n",
            encoding="utf-8",
        )
        ctx = HostContext(
            enabled=True,
            cache_path=tmp_path / "ctx.jsonl",
            known_hosts_path=kh,
        )
        ctx.load()

        tracker, q = self._make_tracker(host_ctx=ctx)
        conn = self._make_connection(1234, "5.6.7.8", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname",
                          return_value="bastion.example.com"):
            tracker.poll()

        # Note: bastion is in allowlist=False (only anthropic is) and on
        # standard port 443 — so allowed=False, nonstandard_port=False.
        # That means an event IS emitted (unknown host, standard port).
        event = q.get_nowait()
        assert event.detail["trust_level"] == "known"
        assert event.detail["downgrade"] is True

    def test_blocked_host_no_downgrade(self, tmp_path):
        """blocklist match → trust=blocked, downgrade=False (never weaken)."""
        ctx = HostContext(
            enabled=True,
            cache_path=tmp_path / "ctx.jsonl",
            known_hosts_path=None,
            blocklist=["evil.example.com"],
        )
        ctx.load()

        tracker, q = self._make_tracker(host_ctx=ctx)
        conn = self._make_connection(1234, "5.6.7.8", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname",
                          return_value="evil.example.com"):
            tracker.poll()

        event = q.get_nowait()
        assert event.detail["trust_level"] == "blocked"
        assert event.detail["downgrade"] is False

    def test_observe_called_even_for_allowed_host(self, tmp_path):
        """observe() runs regardless of allowlist — frequency learns globally."""
        ctx = HostContext(
            enabled=True,
            cache_path=tmp_path / "ctx.jsonl",
            known_hosts_path=None,
            auto_trust_after_seen=2,
            dedup_window_seconds=0,
        )
        ctx.load()

        tracker, q = self._make_tracker(host_ctx=ctx)
        # api.anthropic.com IS in the allowlist — no event will fire,
        # but observe() still runs.
        conn = self._make_connection(1234, "1.2.3.4", 443)

        with patch("psutil.net_connections", return_value=[conn]), \
             patch.object(tracker, "_get_process_name", return_value="ollama"), \
             patch.object(tracker, "_resolve_hostname",
                          return_value="api.anthropic.com"):
            tracker.poll()

        # Even though no event was queued (allowed, standard port), the
        # observation was recorded.
        assert ctx.seen_count("api.anthropic.com") == 1

    def test_engine_downgrades_warning_for_known_host(self, tmp_path):
        """End-to-end: net event w/ trust=known + downgrade=True → info."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = SecurityEvent(
            timestamp=datetime.now(),
            source="net_tracker",
            actor_pid=1234,
            actor_name="ollama",
            event_type="net_connect",
            target="bastion.example.com:443",
            detail={
                "remote_ip": "5.6.7.8",
                "remote_port": 443,
                "hostname": "bastion.example.com",
                "allowed": False,         # would normally → "warning"
                "nonstandard_port": False,
                "trust_level": "known",
                "downgrade": True,
            },
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        # Original level was "warning"; downgrade → "info".
        assert alerts[0].level == "info"

    def test_engine_blocked_keeps_critical(self, tmp_path):
        """trust=blocked + downgrade=True is treated as no downgrade."""
        engine = AlertEngine(DEFAULT_CONFIG)
        event = SecurityEvent(
            timestamp=datetime.now(),
            source="net_tracker",
            actor_pid=1234,
            actor_name="ollama",
            event_type="net_connect",
            target="evil.example.com:4444",
            detail={
                "remote_ip": "5.6.7.8",
                "remote_port": 4444,
                "hostname": "evil.example.com",
                "allowed": False,
                "nonstandard_port": True,
                # Even with downgrade=True the BLOCKED short-circuit must
                # keep the alert at critical.
                "trust_level": "blocked",
                "downgrade": True,
            },
        )
        alerts = engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "critical"
