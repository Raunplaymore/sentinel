"""Tests for ADR 0005 — SIGHUP-driven daemon reload (v0.8 Track 1a).

Covers:

* SIGHUP handler registration in ``Sentinel.__init__`` (D5/D7).
* Coalescing of multiple SIGHUPs into a single reload (D5).
* Reload worker shutdown clean-exit on ``_shutdown_event``.
* Atomic-or-nothing reload sequence (D3) — success swap + failure
  isolation at each of steps 3 / 4 / 5.
* D2 NOT-reloaded preservation (cooldowns survive reload).
* event_logger close + reopen inside the swap.
* CLI-side helpers: ``_read_daemon_pid``, ``_signal_daemon_reload``,
  ``_daemon_reload_notice``.
* CLI envelope additive ``daemon_reload`` field on
  ``forget`` / ``block`` / ``unblock`` (ADR 0004 §D3 + ADR 0005 §D7).
* CLI stderr messages keyed off the ``daemon_reload`` outcome.

All tests run hermetically — no real SIGHUPs fire against the test
process and no real daemon is spawned. ``Sentinel`` instances are
created with ``acquire_lock=False`` and
``install_signal_handlers=False`` so the test does not contend with
pytest's own signal setup.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

from sentinel_mac import core as core_mod
from sentinel_mac.commands import context as ctx_cli
from sentinel_mac.core import Sentinel


# ── shared fixtures ───────────────────────────────────────────────


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch) -> Path:
    """Pin HOME / XDG so daemon_lock_path / data_dir land under tmp_path.

    Mirrors the helper in test_context_cli.py; lifted here so this file
    has zero dependency on the older test module.
    """
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    # Also blank out cwd-based data_dir resolution: if any ancestor of cwd
    # has a `logs/` directory, resolve_data_dir() short-circuits there. We
    # cannot easily chdir but we can hand Sentinel a config so it never
    # calls resolve_data_dir() looking for `./logs`.
    return home


def _quiet_config(tmp_path: Path) -> Path:
    """Write the smallest config that produces a no-channel daemon.

    No notifications channels means ``NotificationManager.send`` is a
    no-op — perfect for tests that exercise reload semantics without
    pinging real services.
    """
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "\n".join(
            [
                "check_interval_seconds: 30",
                "status_interval_minutes: 60",
                "cooldown_minutes: 10",
                "notifications:",
                "  macos: false",
                "thresholds:",
                "  battery_warning: 20",
                "  battery_critical: 10",
                "  memory_critical: 90",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return cfg


def _make_sentinel(cfg_path: Path) -> Sentinel:
    """Build a Sentinel that is safe to instantiate from a test thread.

    ``acquire_lock=False`` so the test doesn't contend for the real
    daemon lock. ``install_signal_handlers=False`` so we don't clobber
    pytest's SIGINT handler — tests that need to assert the SIGHUP
    handler is registered flip this back on explicitly.
    """
    return Sentinel(
        config_path=str(cfg_path),
        acquire_lock=False,
        install_signal_handlers=False,
    )


def _stop_sentinel(s: Sentinel) -> None:
    """Cleanly tear down a Sentinel built via ``_make_sentinel``.

    Runs the same shutdown path as a SIGTERM to guarantee the reload
    worker thread exits. Tests should always call this in a try/finally
    so a failed assertion does not leak a daemon thread into the next
    test.
    """
    try:
        s.stop()
    except Exception:
        pass
    if s._reload_worker is not None:
        s._reload_worker.join(timeout=2.0)


# ── 1. handler registration ───────────────────────────────────────


class TestSighupHandlerRegistration:
    """ADR 0005 §D7 frozen surface: SIGHUP handler installed in __init__."""

    def test_handler_installed_when_flag_true(
        self, tmp_path, isolated_home, monkeypatch
    ):
        # Register a recognisable sentinel-handler so we can detect it
        # was overwritten by Sentinel.__init__.
        prior = signal.signal(signal.SIGHUP, signal.SIG_DFL)
        try:
            cfg = _quiet_config(tmp_path)
            s = Sentinel(
                config_path=str(cfg),
                acquire_lock=False,
                install_signal_handlers=True,
            )
            try:
                installed = signal.getsignal(signal.SIGHUP)
                # Bound method on the Sentinel instance.
                assert installed == s._on_sighup
            finally:
                _stop_sentinel(s)
        finally:
            # Restore whatever the test runner had before us so we don't
            # leak handler state across tests.
            signal.signal(signal.SIGHUP, prior)

    def test_handler_not_installed_when_flag_false(
        self, tmp_path, isolated_home
    ):
        # In embedded mode (menubar) Sentinel must not touch signal
        # handlers — the host process owns them.
        prior = signal.signal(signal.SIGHUP, signal.SIG_DFL)
        try:
            cfg = _quiet_config(tmp_path)
            s = _make_sentinel(cfg)
            try:
                installed = signal.getsignal(signal.SIGHUP)
                # Whatever we set above is still in place — Sentinel did
                # not register its own handler.
                assert installed == signal.SIG_DFL
            finally:
                _stop_sentinel(s)
        finally:
            signal.signal(signal.SIGHUP, prior)


# ── 2. coalescing ─────────────────────────────────────────────────


class TestSighupCoalescing:
    """ADR 0005 §D5: rapid SIGHUPs collapse to one reload."""

    def test_multiple_sets_coalesce_to_single_reload(
        self, tmp_path, isolated_home, monkeypatch
    ):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            calls: list[float] = []

            def _slow_reload(self_inner: Sentinel) -> None:
                # Simulate a non-trivial reload so the second/third
                # set() arrive while we are still inside the worker
                # body — exercises the clear()-before-run contract.
                calls.append(time.monotonic())
                time.sleep(0.05)

            monkeypatch.setattr(Sentinel, "_do_reload", _slow_reload)

            # Three rapid SIGHUPs — the first wakes the worker, the
            # second and third pile onto the same Event, and after the
            # clear() inside the loop they re-fire as exactly one
            # additional reload.
            s._reload_requested.set()
            s._reload_requested.set()
            s._reload_requested.set()

            # Give the worker a moment to drain. 1.0s is generous —
            # the worker wakes within 1s of the first set() per the
            # _reload_worker_loop timeout ceiling.
            deadline = time.monotonic() + 2.0
            while len(calls) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)

            # At least one call (the coalesced batch); at most two
            # (one for the first batch, one if a stray re-set happens
            # while the worker is mid-sleep). Three is forbidden.
            assert 1 <= len(calls) <= 2, (
                f"expected coalescing to 1-2 reloads, got {len(calls)}"
            )
        finally:
            _stop_sentinel(s)


# ── 3. shutdown ───────────────────────────────────────────────────


class TestReloadWorkerShutdown:
    """ADR 0005 §D5: shutdown wakes the worker promptly."""

    def test_shutdown_event_breaks_loop(
        self, tmp_path, isolated_home
    ):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        worker = s._reload_worker
        assert worker is not None and worker.is_alive()
        # Same combination _shutdown does: shutdown_event + reload_requested
        # so the worker falls out of Event.wait() immediately.
        s._shutdown_event.set()
        s._reload_requested.set()
        worker.join(timeout=2.0)
        assert not worker.is_alive(), (
            "reload worker did not exit within 2s of shutdown signal"
        )


# ── 4. atomic reload — success ────────────────────────────────────


class TestDoReloadAtomicSuccess:
    """ADR 0005 §D3: successful reload swaps the new state in place."""

    def test_thresholds_swap_under_lock(
        self, tmp_path, isolated_home
    ):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            old_thresholds = s.engine.thresholds
            old_host_ctx = s.host_ctx

            # Rewrite config with a new threshold value.
            cfg.write_text(
                "\n".join(
                    [
                        "check_interval_seconds: 30",
                        "notifications:",
                        "  macos: false",
                        "thresholds:",
                        "  memory_critical: 75",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            s._do_reload()

            # New AlertEngine.thresholds picked up the new value.
            assert s.engine.thresholds.get("memory_critical") == 75
            # host_ctx replaced wholesale (D3 step 6).
            assert s.host_ctx is not old_host_ctx
            # Old thresholds dict object is no longer the engine's
            # (we replaced, not merged).
            assert s.engine.thresholds is not old_thresholds
        finally:
            _stop_sentinel(s)

    def test_cooldowns_preserved_across_reload(
        self, tmp_path, isolated_home
    ):
        # ADR 0005 §D2 NOT-reloaded row: AlertEngine cooldown
        # timestamps survive reload by design.
        from datetime import datetime

        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            # Plant a fake cooldown timestamp.
            s.engine._cooldowns["test_key"] = datetime(2026, 5, 2, 12, 0)

            # Rewrite config with any threshold change.
            cfg.write_text(
                "\n".join(
                    [
                        "notifications:",
                        "  macos: false",
                        "thresholds:",
                        "  memory_critical: 80",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            s._do_reload()

            # Same dict identity, same entry — cooldowns are NOT
            # touched per the D2 contract.
            assert "test_key" in s.engine._cooldowns
            assert s.engine._cooldowns["test_key"] == datetime(2026, 5, 2, 12, 0)
        finally:
            _stop_sentinel(s)


# ── 5. atomic reload — failure isolation ──────────────────────────


class TestDoReloadAtomicFailure:
    """ADR 0005 §D3: a failure at any step leaves old state intact."""

    def test_load_config_failure_keeps_old_state(
        self, tmp_path, isolated_home, monkeypatch, caplog
    ):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            old_host_ctx = s.host_ctx
            old_thresholds = s.engine.thresholds

            def _boom(_path):
                raise RuntimeError("simulated parse failure")

            monkeypatch.setattr(core_mod, "load_config", _boom)
            with caplog.at_level("WARNING"):
                s._do_reload()

            assert s.host_ctx is old_host_ctx
            assert s.engine.thresholds is old_thresholds
            assert any(
                "config reload failed at load_config" in rec.message
                for rec in caplog.records
            )
        finally:
            _stop_sentinel(s)

    def test_validate_failure_keeps_old_state(
        self, tmp_path, isolated_home, monkeypatch, caplog
    ):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            old_host_ctx = s.host_ctx
            old_thresholds = s.engine.thresholds

            def _boom(self_inner, new_config):
                raise ValueError("simulated validation failure")

            monkeypatch.setattr(
                Sentinel, "_validate_reload_config", _boom
            )
            with caplog.at_level("WARNING"):
                s._do_reload()

            assert s.host_ctx is old_host_ctx
            assert s.engine.thresholds is old_thresholds
            assert any(
                "config reload failed at validate" in rec.message
                for rec in caplog.records
            )
        finally:
            _stop_sentinel(s)

    def test_build_failure_keeps_old_state(
        self, tmp_path, isolated_home, monkeypatch, caplog
    ):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            old_host_ctx = s.host_ctx
            old_thresholds = s.engine.thresholds

            from sentinel_mac.collectors import context as ctx_mod

            def _boom(config):
                raise RuntimeError("simulated build failure")

            monkeypatch.setattr(
                ctx_mod.HostContext, "from_config", classmethod(
                    lambda cls, config: _boom(config)
                )
            )
            with caplog.at_level("WARNING"):
                s._do_reload()

            assert s.host_ctx is old_host_ctx
            assert s.engine.thresholds is old_thresholds
            assert any(
                "config reload failed at build" in rec.message
                for rec in caplog.records
            )
        finally:
            _stop_sentinel(s)


# ── 6. event_logger reopen ────────────────────────────────────────


class TestDoReloadEventLoggerReopen:
    """ADR 0005 §D2 row: event_logger handle is closed + reopened."""

    def test_event_logger_replaced(self, tmp_path, isolated_home):
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            old_logger = s._event_logger
            assert old_logger is not None

            s._do_reload()

            # Same data_dir, but a fresh EventLogger instance — the
            # reload logic explicitly re-instantiates.
            assert s._event_logger is not old_logger
        finally:
            _stop_sentinel(s)


# ── 7. CLI helper — _signal_daemon_reload ─────────────────────────


class TestSignalDaemonReload:
    """ADR 0005 §D7 verbatim enum: applied / failed_unreachable / skipped_not_running."""

    def test_enum_frozen_set(self):
        # The exact three values frozen by ADR 0005 §D7.
        assert ctx_cli.DAEMON_RELOAD_RESULTS == frozenset(
            {"applied", "skipped_not_running", "failed_unreachable"}
        )

    def test_skipped_when_no_lock_file(
        self, tmp_path, isolated_home, monkeypatch
    ):
        # Fresh isolated HOME — no lock file present anywhere.
        status, pid = ctx_cli._signal_daemon_reload()
        assert status == "skipped_not_running"
        assert pid is None

    def test_skipped_when_pid_dead(
        self, tmp_path, isolated_home, monkeypatch
    ):
        # Write a bogus, definitely-dead PID into the lock file. PID 1
        # is init and is always alive, so we use a high PID that os.kill
        # rejects with ESRCH.
        from sentinel_mac.core import daemon_lock_path

        lock_path = daemon_lock_path()
        # Use a PID that is overwhelmingly likely to be dead. Linux
        # max is /proc/sys/kernel/pid_max (usually 4M); macOS caps at
        # 99999 by default. 999999 sits above both.
        lock_path.write_text("999999")

        status, pid = ctx_cli._signal_daemon_reload()
        assert status == "skipped_not_running"
        assert pid is None

    def test_applied_when_pid_live(
        self, tmp_path, isolated_home, monkeypatch
    ):
        from sentinel_mac.core import daemon_lock_path

        lock_path = daemon_lock_path()
        # Use the test process's own PID — guaranteed alive.
        my_pid = os.getpid()
        lock_path.write_text(str(my_pid))

        # Intercept os.kill so we don't actually deliver SIGHUP to
        # the test process (would terminate pytest).
        seen: list = []

        real_kill = os.kill

        def _fake_kill(pid: int, sig: int):
            seen.append((pid, sig))
            # Allow the live-probe (signal 0) through so _read_daemon_pid
            # still confirms PID liveness.
            if sig == 0:
                return real_kill(pid, sig)
            # Eat SIGHUP delivery — return success.
            return None

        monkeypatch.setattr(os, "kill", _fake_kill)

        status, pid = ctx_cli._signal_daemon_reload()
        assert status == "applied"
        assert pid == my_pid
        # SIGHUP was attempted on our PID.
        assert (my_pid, signal.SIGHUP) in seen

    def test_failed_unreachable_on_process_lookup_error(
        self, tmp_path, isolated_home, monkeypatch
    ):
        from sentinel_mac.core import daemon_lock_path

        lock_path = daemon_lock_path()
        my_pid = os.getpid()
        lock_path.write_text(str(my_pid))

        real_kill = os.kill

        def _fake_kill(pid: int, sig: int):
            # Probe (signal 0) goes through so _read_daemon_pid still
            # returns a non-None PID, but the SIGHUP delivery races with
            # daemon exit.
            if sig == 0:
                return real_kill(pid, sig)
            raise ProcessLookupError("simulated race")

        monkeypatch.setattr(os, "kill", _fake_kill)

        status, pid = ctx_cli._signal_daemon_reload()
        assert status == "failed_unreachable"
        assert pid == my_pid

    def test_failed_unreachable_on_permission_error(
        self, tmp_path, isolated_home, monkeypatch
    ):
        # Cross-user case: PID is alive but we cannot signal it.
        from sentinel_mac.core import daemon_lock_path

        lock_path = daemon_lock_path()
        my_pid = os.getpid()
        lock_path.write_text(str(my_pid))

        real_kill = os.kill

        def _fake_kill(pid: int, sig: int):
            if sig == 0:
                return real_kill(pid, sig)
            raise PermissionError("simulated cross-user")

        monkeypatch.setattr(os, "kill", _fake_kill)

        status, pid = ctx_cli._signal_daemon_reload()
        assert status == "failed_unreachable"
        assert pid == my_pid


# ── 8. CLI envelope ───────────────────────────────────────────────


def _isolate_xdg(monkeypatch, tmp_path: Path) -> Path:
    """Same helper as test_context_cli.py — pin XDG dirs.

    Duplicated here to keep this file self-contained per the test
    file convention in this project.
    """
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    return home


def _write_config_with_blocklist(
    tmp_path: Path, *, blocklist: list, enabled: bool = True
) -> Path:
    """Minimal config.yaml with a blocklist for block/unblock tests."""
    bl = (
        "[]"
        if not blocklist
        else "\n      - " + "\n      - ".join(repr(b) for b in blocklist)
    )
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "\n".join(
            [
                "security:",
                "  context_aware:",
                f"    enabled: {'true' if enabled else 'false'}",
                "    blocklist:" + (" []" if bl == "[]" else bl),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return cfg


def _read_envelope(capsys) -> dict:
    """Parse the last JSON line emitted to stdout."""
    out = capsys.readouterr().out.strip()
    last = [ln for ln in out.splitlines() if ln.strip()][-1]
    return json.loads(last)


class TestCliEnvelopeDaemonReloadField:
    """Mutation envelopes carry the `daemon_reload` field per ADR 0005 §D7."""

    @pytest.fixture(autouse=True)
    def _require_ruamel(self):
        pytest.importorskip("ruamel.yaml")

    def test_block_envelope_has_daemon_reload(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        # Force "skipped" path so the test does not depend on real
        # daemon presence.
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload",
            lambda: ("skipped_not_running", None),
        )
        rc = ctx_cli.dispatch(["block", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        env = _read_envelope(capsys)
        assert "daemon_reload" in env["data"]
        assert env["data"]["daemon_reload"] in ctx_cli.DAEMON_RELOAD_RESULTS

    def test_unblock_envelope_has_daemon_reload(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(
            tmp_path, blocklist=["evil.com"]
        )
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload",
            lambda: ("applied", 4242),
        )
        rc = ctx_cli.dispatch(["unblock", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        env = _read_envelope(capsys)
        assert env["data"]["daemon_reload"] == "applied"
        assert env["data"]["daemon_reload"] in ctx_cli.DAEMON_RELOAD_RESULTS

    def test_unblock_not_found_envelope_has_daemon_reload(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        rc = ctx_cli.dispatch(
            ["unblock", "ghost.example", "--config", str(cfg), "--json"]
        )
        assert rc == 1
        env = _read_envelope(capsys)
        # No file write happened → skipped_not_running, but the field
        # still appears so consumers see a stable shape.
        assert env["data"]["daemon_reload"] == "skipped_not_running"

    def test_forget_envelope_has_daemon_reload(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        # Force the forget path to "removed" so the SIGHUP branch fires.
        from sentinel_mac.collectors import context as ctx_mod

        def _fake_forget(self_inner, host: str) -> bool:
            return True

        monkeypatch.setattr(ctx_mod.HostContext, "forget", _fake_forget)
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload",
            lambda: ("failed_unreachable", 4242),
        )
        rc = ctx_cli.dispatch(
            ["forget", "host.example", "--config", str(cfg), "--json"]
        )
        assert rc == 0
        env = _read_envelope(capsys)
        assert env["data"]["daemon_reload"] == "failed_unreachable"

    def test_block_idempotent_no_signal_emits_skipped(
        self, tmp_path, monkeypatch, capsys
    ):
        # An "already_present" block does no file write, so we must NOT
        # call _signal_daemon_reload (would cause spurious reloads).
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(
            tmp_path, blocklist=["evil.com"]
        )
        called: list[bool] = []

        def _fake_signal():
            called.append(True)
            return ("applied", 1)

        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload", _fake_signal
        )
        rc = ctx_cli.dispatch(
            ["block", "evil.com", "--config", str(cfg), "--json"]
        )
        assert rc == 0
        env = _read_envelope(capsys)
        assert env["data"]["result"] == "already_present"
        assert env["data"]["daemon_reload"] == "skipped_not_running"
        # Helper was never called — no on-disk change, no SIGHUP.
        assert called == []

    def test_status_envelope_has_no_daemon_reload(
        self, tmp_path, monkeypatch, capsys
    ):
        # Status is read-only — must NOT carry daemon_reload (D7 scopes
        # the field to mutation envelopes only).
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        rc = ctx_cli.dispatch(["status", "--config", str(cfg), "--json"])
        assert rc == 0
        env = _read_envelope(capsys)
        assert "daemon_reload" not in env["data"]


# ── 9. CLI stderr messages ────────────────────────────────────────


class TestCliStdoutMessages:
    """ADR 0005 §D7 message contract on stderr."""

    @pytest.fixture(autouse=True)
    def _require_ruamel(self):
        pytest.importorskip("ruamel.yaml")

    def test_applied_message_on_stderr(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload",
            lambda: ("applied", 4242),
        )
        rc = ctx_cli.dispatch(["block", "evil.com", "--config", str(cfg)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Applied to running daemon (PID 4242)." in captured.err
        # Existing stdout result line is preserved (additive contract).
        assert "Added 'evil.com' to blocklist" in captured.out

    def test_failed_unreachable_message_on_stderr(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload",
            lambda: ("failed_unreachable", 4242),
        )
        rc = ctx_cli.dispatch(["block", "evil.com", "--config", str(cfg)])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Daemon not reachable" in captured.err
        assert "sentinel restart" in captured.err

    def test_skipped_emits_no_daemon_message(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config_with_blocklist(tmp_path, blocklist=[])
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload",
            lambda: ("skipped_not_running", None),
        )
        rc = ctx_cli.dispatch(["block", "evil.com", "--config", str(cfg)])
        assert rc == 0
        captured = capsys.readouterr()
        # No daemon line in either stream — silent on the happy CLI-only path.
        assert "Applied to running daemon" not in captured.err
        assert "Daemon not reachable" not in captured.err
        # Old "Restart the daemon" notice stayed gone (CHANGELOG v0.8 Track 1a).
        assert "Restart the daemon" not in captured.out
        assert "Restart the daemon" not in captured.err


# ── 10. read-side reload lock instrumentation (Track 1c) ──────────


class TestReloadLockReadSide:
    """ADR 0005 §D5 read-side instrumentation — closes PR #16 inline TODO.

    Track 1a frozen the swap-side lock; Track 1c adds the matching
    read-side ``_snapshot_for_main_loop()`` calls in the main loop and
    the queue drainer so a SIGHUP-driven reload landing mid-cycle cannot
    surface partially-swapped state.
    """

    def test_snapshot_returns_four_tuple_of_live_refs(
        self, tmp_path, isolated_home
    ):
        """Snapshot returns the exact 4-tuple shape D5 specifies."""
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            snap = s._snapshot_for_main_loop()
            assert isinstance(snap, tuple)
            assert len(snap) == 4
            engine, host_ctx, event_logger, security_rules = snap
            assert engine is s.engine
            assert host_ctx is s.host_ctx
            assert event_logger is s._event_logger
            assert security_rules is s._security_rules
        finally:
            _stop_sentinel(s)

    def test_snapshot_takes_reload_lock(
        self, tmp_path, isolated_home, monkeypatch
    ):
        """`_snapshot_for_main_loop` enters and exits ``_reload_lock`` exactly once.

        Wraps the real RLock so we can count enter/exit transitions
        without breaking lock semantics. RLock is reentrant, so the
        worker thread's own acquisitions during shutdown still succeed.
        """
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            real_lock = s._reload_lock
            enters: list[float] = []
            exits: list[float] = []

            class _CountingLock:
                def __enter__(self_inner):
                    enters.append(time.monotonic())
                    return real_lock.__enter__()

                def __exit__(self_inner, exc_type, exc, tb):
                    exits.append(time.monotonic())
                    return real_lock.__exit__(exc_type, exc, tb)

                # Forward acquire/release for any code path that uses
                # the lock directly (none in the read side, but defensive).
                def acquire(self_inner, *a, **kw):
                    return real_lock.acquire(*a, **kw)

                def release(self_inner):
                    return real_lock.release()

            s._reload_lock = _CountingLock()  # type: ignore[assignment]

            snap_before = len(enters)
            s._snapshot_for_main_loop()
            assert len(enters) == snap_before + 1
            assert len(exits) == snap_before + 1

            # A second call increments by exactly one — single
            # acquire/release per snapshot, no leaks.
            s._snapshot_for_main_loop()
            assert len(enters) == snap_before + 2
            assert len(exits) == snap_before + 2

            # Restore so _stop_sentinel sees the real lock.
            s._reload_lock = real_lock
        finally:
            _stop_sentinel(s)

    def test_snapshot_is_consistent_against_concurrent_reload(
        self, tmp_path, isolated_home, monkeypatch
    ):
        """Concurrent ``_do_reload`` cannot interleave a partial swap into a snapshot.

        Strategy: monkey-patch ``_do_reload`` with a synthetic swap that
        increments a generation counter and tags **every one** of the
        four reload-managed attributes with the same generation. Run a
        snapshot thread concurrently with the reload thread; assert that
        every captured 4-tuple has all four members from the same
        generation. Without the read-side lock, the snapshot would
        eventually capture e.g. engine=gen N + event_logger=gen N+1 (a
        torn read); with the lock the invariant always holds.

        We avoid invoking the real ``_do_reload`` because its file I/O
        and validation steps dwarf the contended swap window, masking
        the race the test is meant to expose.
        """
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            # Each "generation" is a tiny tagged sentinel object whose
            # only attribute is .gen. We swap all four refs to fresh
            # tagged objects under the same lock that the production
            # _do_reload uses, so the read-side lock contract is the
            # only thing standing between snapshot and a torn tuple.
            class _Tagged:
                __slots__ = ("gen",)

                def __init__(self, gen: int):
                    self.gen = gen

            generations: list[int] = [0]

            def _swap_all(gen: int) -> None:
                with s._reload_lock:
                    s.engine = _Tagged(gen)        # type: ignore[assignment]
                    s.host_ctx = _Tagged(gen)      # type: ignore[assignment]
                    s._event_logger = _Tagged(gen)  # type: ignore[assignment]
                    s._security_rules = _Tagged(gen)  # type: ignore[assignment]

            # Seed gen 0.
            _swap_all(0)

            stop = threading.Event()
            torn: list[tuple] = []

            def _reload_loop():
                while not stop.is_set():
                    generations[0] += 1
                    _swap_all(generations[0])
                    # No sleep — we want maximum contention pressure.

            def _snapshot_loop():
                while not stop.is_set():
                    engine, host_ctx, event_logger, security_rules = (
                        s._snapshot_for_main_loop()
                    )
                    gens = {
                        engine.gen,
                        host_ctx.gen,
                        event_logger.gen,
                        security_rules.gen,
                    }
                    if len(gens) != 1:
                        # All four refs must come from the same swap
                        # generation. A set of size > 1 proves a torn
                        # read leaked through — i.e., the lock is not
                        # serialising the snapshot against the swap.
                        torn.append(tuple(gens))

            t_reload = threading.Thread(target=_reload_loop)
            t_snap1 = threading.Thread(target=_snapshot_loop)
            t_snap2 = threading.Thread(target=_snapshot_loop)
            t_reload.start()
            t_snap1.start()
            t_snap2.start()

            # 200ms is plenty: the synthetic swap is sub-µs so we expect
            # tens of thousands of iterations on each thread, which would
            # surface a torn read with overwhelming probability if the
            # read side were not lock-serialised.
            time.sleep(0.2)
            stop.set()
            t_reload.join(timeout=2.0)
            t_snap1.join(timeout=2.0)
            t_snap2.join(timeout=2.0)

            assert not t_reload.is_alive(), "reload loop did not stop"
            assert not t_snap1.is_alive(), "snapshot loop 1 did not stop"
            assert not t_snap2.is_alive(), "snapshot loop 2 did not stop"
            assert torn == [], (
                f"detected {len(torn)} torn snapshot tuple(s): {torn[:3]}"
            )
            # Sanity: the race actually ran. With a sub-µs swap the
            # reload thread should turn over thousands of generations
            # in 200ms; pick a conservative floor that survives the
            # slowest CI hardware.
            assert generations[0] >= 50, (
                f"reload loop only completed {generations[0]} swaps — "
                "race probably did not exercise the lock"
            )
        finally:
            # Restore the real attributes so _stop_sentinel can do its
            # cleanup without tripping over our _Tagged stand-ins.
            # _shutdown calls host_ctx.flush() and _event_logger.close()
            # which are not present on _Tagged — replace with no-ops.
            class _Noop:
                def flush(self):
                    pass

                def close(self):
                    pass

                def stop(self):
                    pass

            s.host_ctx = _Noop()  # type: ignore[assignment]
            s._event_logger = _Noop()  # type: ignore[assignment]
            _stop_sentinel(s)

    def test_reload_blocks_on_in_flight_snapshot(
        self, tmp_path, isolated_home, monkeypatch
    ):
        """A ``_do_reload`` swap waits for an in-flight snapshot to release the lock.

        Thread A enters ``_snapshot_for_main_loop`` and stalls inside
        the ``with`` block (simulated by a slow ``__enter__`` chain).
        Thread B calls ``_do_reload``. The reload's swap step (which
        also acquires ``_reload_lock``) must not complete until thread
        A releases.
        """
        cfg = _quiet_config(tmp_path)
        s = _make_sentinel(cfg)
        try:
            old_event_logger = s._event_logger
            release_snapshot = threading.Event()
            snapshot_acquired = threading.Event()

            def _holding_snapshot():
                with s._reload_lock:
                    snapshot_acquired.set()
                    # Hold the lock until the test releases us.
                    release_snapshot.wait(timeout=2.0)

            t_hold = threading.Thread(target=_holding_snapshot)
            t_hold.start()
            assert snapshot_acquired.wait(timeout=1.0), (
                "snapshot thread never acquired the lock"
            )

            # Kick off a reload from another thread. It must block on
            # the swap step until we release.
            reload_done = threading.Event()

            def _reload_in_thread():
                try:
                    s._do_reload()
                finally:
                    reload_done.set()

            t_reload = threading.Thread(target=_reload_in_thread)
            t_reload.start()

            # Reload must NOT have completed yet — verify it is still
            # blocked (the swap mutates `_event_logger` so this is
            # detectable). Give it 100ms to prove it is genuinely waiting.
            time.sleep(0.1)
            assert not reload_done.is_set(), (
                "reload completed while a snapshot held the lock — "
                "swap-side serialization is broken"
            )
            assert s._event_logger is old_event_logger, (
                "event_logger was swapped while snapshot held the lock"
            )

            # Release the snapshot; reload should now finish promptly.
            release_snapshot.set()
            t_hold.join(timeout=2.0)
            assert reload_done.wait(timeout=2.0), (
                "reload did not complete within 2s of snapshot release"
            )
            t_reload.join(timeout=2.0)

            # Post-release: event_logger was swapped (proves reload ran).
            assert s._event_logger is not old_event_logger
        finally:
            _stop_sentinel(s)
