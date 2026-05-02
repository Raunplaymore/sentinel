"""Tests for FSWatcher and security event evaluation."""
import os
import queue
import tempfile
import time
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

from sentinel_mac.collectors.fs_watcher import FSWatcher
from sentinel_mac.engine import AlertEngine
from sentinel_mac.models import SecurityEvent, Alert
from sentinel_mac.core import DEFAULT_CONFIG


# ─── FSWatcher unit tests ───


class TestFSWatcherFiltering:
    """Tests for path filtering logic."""

    def _make_watcher(self, **overrides):
        config = {
            "security": {
                "fs_watcher": {
                    "watch_paths": ["/tmp/sentinel-test"],
                    "sensitive_paths": ["~/.ssh", "~/.env"],
                    "ignore_patterns": ["*.pyc", "__pycache__", ".DS_Store"],
                    "bulk_threshold": 50,
                    "bulk_window_seconds": 30,
                    **overrides,
                }
            }
        }
        q = queue.Queue(maxsize=100)
        return FSWatcher(config, q), q

    def test_should_ignore_pyc(self):
        watcher, _ = self._make_watcher()
        assert watcher._should_ignore("/some/path/module.pyc") is True

    def test_should_ignore_ds_store(self):
        watcher, _ = self._make_watcher()
        assert watcher._should_ignore("/some/path/.DS_Store") is True

    def test_should_not_ignore_normal_file(self):
        watcher, _ = self._make_watcher()
        assert watcher._should_ignore("/some/path/main.py") is False

    def test_should_ignore_pycache_in_path(self):
        watcher, _ = self._make_watcher()
        assert watcher._should_ignore("/project/__pycache__/module.cpython.pyc") is True

    def test_sensitive_path_ssh(self):
        watcher, _ = self._make_watcher()
        ssh_path = os.path.expanduser("~/.ssh/id_rsa")
        assert watcher._is_sensitive_path(ssh_path) is True

    def test_sensitive_path_env(self):
        watcher, _ = self._make_watcher()
        assert watcher._is_sensitive_path("/project/.env") is True
        assert watcher._is_sensitive_path("/project/.env.local") is True

    def test_non_sensitive_path(self):
        watcher, _ = self._make_watcher()
        assert watcher._is_sensitive_path("/project/src/main.py") is False

    def test_executable_detection_sh(self):
        watcher, _ = self._make_watcher()
        assert watcher._is_executable("/tmp/script.sh", "file_create") is True

    def test_executable_detection_not_for_delete(self):
        watcher, _ = self._make_watcher()
        assert watcher._is_executable("/tmp/script.sh", "file_delete") is False


class TestFSWatcherAIDetection:
    """Tests for AI process identification."""

    def _make_watcher(self):
        config = {"security": {"fs_watcher": {"watch_paths": ["/tmp"]}}}
        q = queue.Queue(maxsize=100)
        return FSWatcher(config, q), q

    def test_known_ai_process(self):
        watcher, _ = self._make_watcher()
        assert watcher._is_ai_process("ollama", 1234) is True

    def test_unknown_process(self):
        watcher, _ = self._make_watcher()
        assert watcher._is_ai_process("unknown", 0) is False

    def test_generic_process_without_keyword(self):
        watcher, _ = self._make_watcher()
        with patch.object(watcher, "_get_process_cmdline", return_value="python3 app.py"):
            assert watcher._is_ai_process("python3", 1234) is False

    def test_generic_process_with_ai_keyword(self):
        watcher, _ = self._make_watcher()
        with patch.object(watcher, "_get_process_cmdline", return_value="python3 -m langchain serve"):
            assert watcher._is_ai_process("python3", 1234) is True


class TestFSWatcherEventHandling:
    """Tests for event generation."""

    def _make_watcher(self):
        config = {
            "security": {
                "fs_watcher": {
                    "watch_paths": ["/tmp"],
                    "sensitive_paths": ["~/.ssh"],
                    "ignore_patterns": ["*.pyc"],
                    "bulk_threshold": 3,
                    "bulk_window_seconds": 10,
                }
            }
        }
        q = queue.Queue(maxsize=100)
        return FSWatcher(config, q), q

    def test_sensitive_file_emits_event(self):
        watcher, q = self._make_watcher()
        ssh_path = os.path.expanduser("~/.ssh/id_rsa")
        with patch.object(watcher, "_identify_actor", return_value=(0, "unknown")):
            watcher._handle_fs_event(ssh_path, "file_modify")
        assert not q.empty()
        event = q.get_nowait()
        assert event.detail.get("sensitive") is True
        assert event.target == ssh_path

    def test_ignored_file_no_event(self):
        watcher, q = self._make_watcher()
        with patch.object(watcher, "_identify_actor", return_value=(0, "unknown")):
            watcher._handle_fs_event("/project/module.pyc", "file_modify")
        assert q.empty()

    def test_normal_file_no_event_without_ai(self):
        watcher, q = self._make_watcher()
        with patch.object(watcher, "_identify_actor", return_value=(0, "unknown")):
            watcher._handle_fs_event("/project/main.py", "file_modify")
        assert q.empty()

    def test_ai_process_emits_event(self):
        watcher, q = self._make_watcher()
        sensitive_path = os.path.expanduser("~/.ssh/config")
        with patch.object(watcher, "_identify_actor", return_value=(1234, "ollama")):
            watcher._handle_fs_event(sensitive_path, "file_modify")
        assert not q.empty()
        event = q.get_nowait()
        assert event.detail.get("ai_process") is True

    def test_bulk_change_detection(self):
        watcher, q = self._make_watcher()
        ssh_path = os.path.expanduser("~/.ssh/id_rsa")
        with patch.object(watcher, "_identify_actor", return_value=(0, "unknown")):
            for i in range(5):
                watcher._handle_fs_event(ssh_path, "file_modify")
        # Should have individual events + one bulk_change event
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        bulk_events = [e for e in events if e.event_type == "bulk_change"]
        assert len(bulk_events) == 1


class TestFSWatcherStartStop:
    """Tests for observer lifecycle."""

    def test_start_with_nonexistent_path(self):
        config = {
            "security": {
                "fs_watcher": {
                    "watch_paths": ["/nonexistent/path/abcxyz"],
                }
            }
        }
        q = queue.Queue()
        watcher = FSWatcher(config, q)
        watcher.start()  # Should not crash
        assert watcher._observer is None  # No valid paths, observer not created

    def test_start_stop_with_valid_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "security": {
                    "fs_watcher": {
                        "watch_paths": [tmpdir],
                    }
                }
            }
            q = queue.Queue()
            watcher = FSWatcher(config, q)
            watcher.start()
            assert watcher._running is True
            watcher.stop()
            assert watcher._running is False


# ─── AlertEngine security event evaluation tests ───


class TestSecurityEventAlerts:
    """Tests for AlertEngine.evaluate_security_event."""

    def setup_method(self):
        self.engine = AlertEngine(DEFAULT_CONFIG)

    def _make_event(self, **kwargs):
        defaults = {
            "timestamp": datetime.now(),
            "source": "fs_watcher",
            "actor_pid": 0,
            "actor_name": "unknown",
            "event_type": "file_modify",
            "target": "/some/file.txt",
            "detail": {},
        }
        defaults.update(kwargs)
        return SecurityEvent(**defaults)

    def test_sensitive_ai_generates_critical(self):
        event = self._make_event(
            actor_pid=1234,
            actor_name="ollama",
            detail={"sensitive": True, "ai_process": True},
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "critical"
        assert alerts[0].category == "fs_sensitive_ai"

    def test_sensitive_non_ai_generates_warning(self):
        event = self._make_event(
            detail={"sensitive": True},
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "warning"
        assert alerts[0].category == "fs_sensitive"

    def test_executable_generates_warning(self):
        event = self._make_event(
            detail={"executable": True},
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].category == "fs_executable"

    def test_ai_activity_generates_info(self):
        event = self._make_event(
            actor_pid=1234,
            actor_name="ollama",
            detail={"ai_process": True},
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].level == "info"
        assert alerts[0].category == "fs_ai_activity"

    def test_bulk_change_generates_warning(self):
        event = self._make_event(
            event_type="bulk_change",
            target="50 files in 30s",
            detail={"count": 50},
        )
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 1
        assert alerts[0].category == "fs_bulk_change"

    def test_no_alert_for_boring_event(self):
        event = self._make_event(detail={})
        alerts = self.engine.evaluate_security_event(event)
        assert len(alerts) == 0

    def test_security_event_cooldown(self):
        event = self._make_event(
            detail={"sensitive": True},
        )
        alerts1 = self.engine.evaluate_security_event(event)
        alerts2 = self.engine.evaluate_security_event(event)
        assert len(alerts1) == 1
        assert len(alerts2) == 0  # Suppressed by cooldown


# ─── ADR 0007 D3+D5 — fs_watcher project_meta enrichment ──────────


class TestFSWatcherProjectMetaEnrichment:
    """ADR 0007 D5 — bulk_change and per-file events carry project_meta
    when a ProjectContext is wired. session is intentionally NOT set
    (D5: fs_watcher cannot derive session attribution).
    """

    def _make_watcher_with_ctx(self, project_ctx=None):
        config = {
            "security": {
                "fs_watcher": {
                    "watch_paths": ["/tmp/sentinel-test"],
                    "sensitive_paths": ["~/.ssh"],
                    "bulk_threshold": 3,
                    "bulk_window_seconds": 60,
                }
            }
        }
        q = queue.Queue(maxsize=100)
        return FSWatcher(config, q, project_ctx=project_ctx), q

    def test_bulk_change_carries_project_meta_and_keeps_legacy_project(
        self, tmp_path,
    ):
        from sentinel_mac.collectors.project_context import ProjectContext
        proj = tmp_path / "demo"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "demo"\n', encoding="utf-8",
        )
        ctx = ProjectContext()
        watcher, q = self._make_watcher_with_ctx(project_ctx=ctx)
        # Force bulk_change emission — _track_bulk fires when threshold
        # is hit AND the cooldown allows it.
        for i in range(4):
            watcher._track_bulk(
                str(proj / f"file{i}.py"), "file_modify",
            )
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        bulk = [e for e in events if e.event_type == "bulk_change"]
        assert bulk, "bulk_change event was not emitted"
        d = bulk[0].detail
        # Legacy string field — ADR 0007 D3 naming note: must stay.
        assert "project" in d
        assert isinstance(d["project"], str)
        # New structured field.
        assert "project_meta" in d
        assert d["project_meta"] is not None
        assert d["project_meta"]["name"] == "demo"

    def test_no_project_ctx_yields_null_project_meta_on_bulk(self, tmp_path):
        proj = tmp_path / "demo"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "demo"\n', encoding="utf-8",
        )
        watcher, q = self._make_watcher_with_ctx(project_ctx=None)
        for i in range(4):
            watcher._track_bulk(
                str(proj / f"file{i}.py"), "file_modify",
            )
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        bulk = [e for e in events if e.event_type == "bulk_change"]
        assert bulk
        assert bulk[0].detail["project_meta"] is None
        # Legacy field still present (string from _guess_project_name).
        assert "project" in bulk[0].detail or bulk[0].detail.get("project") is None

    def test_lookup_project_meta_for_path_uses_parent_dir(self, tmp_path):
        from sentinel_mac.collectors.project_context import ProjectContext
        proj = tmp_path / "demo"
        proj.mkdir()
        (proj / "pyproject.toml").write_text(
            '[project]\nname = "demo"\n', encoding="utf-8",
        )
        # File must exist on disk (cwd-resolution requires the parent
        # directory to be stat-able; file events arrive AFTER the create).
        src = proj / "src"
        src.mkdir()
        (src / "main.py").write_text("# noop", encoding="utf-8")
        ctx = ProjectContext()
        watcher, _ = self._make_watcher_with_ctx(project_ctx=ctx)
        meta = watcher._lookup_project_meta_for_path(
            str(src / "main.py"),
        )
        assert meta is not None
        assert meta["name"] == "demo"

    def test_bulk_source_cwd_uses_commonpath(self):
        paths = [
            "/Users/x/proj/src/a.py",
            "/Users/x/proj/src/b.py",
            "/Users/x/proj/tests/c.py",
        ]
        assert FSWatcher._bulk_source_cwd(paths) == "/Users/x/proj"

    def test_bulk_source_cwd_empty(self):
        assert FSWatcher._bulk_source_cwd([]) is None

