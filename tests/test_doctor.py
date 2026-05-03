"""Tests for ``sentinel doctor`` (v0.8 Track 1b).

Covers:

* ``CheckResult`` dataclass — status enum + remediation slot
* Each of the 9 individual checks (daemon / config / config_dir_perms /
  data_dir / event_logs / hook / host_context_cache / backup_files /
  optional_deps)
* The exception-isolated runner (``_run_all_checks``)
* CLI dispatch — text rendering, JSON envelope shape, exit codes,
  ``--config`` propagation.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from sentinel_mac.commands import doctor as doc


def _lock_path_for_test(*, ensure_parent: bool = True) -> Path:
    """Compute the lock-file path the same way `_check_daemon` does.

    Tests previously called ``doc.daemon_lock_path()`` for this, but
    that helper has a ``mkdir(parents=True, exist_ok=True)`` side effect
    we do not want in *production* code (it would mask
    `_check_data_dir` semantics). For test fixtures the parent dir
    must exist so ``lock.write_text()`` can run; this helper does the
    mkdir explicitly when ``ensure_parent`` is True (the default).
    Pass ``ensure_parent=False`` for the no-lock-file scenario.
    """
    path = Path.home() / ".local" / "share" / "sentinel" / "sentinel.lock"
    if ensure_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


# ── shared fixture: pin XDG-style dirs to tmp_path ────────────────


@pytest.fixture
def isolated_home(monkeypatch, tmp_path: Path) -> Path:
    """Pin HOME / XDG / cwd so doctor never touches the real machine.

    ``resolve_config_path`` looks at cwd before falling back to XDG, so
    the test cwd has to be empty too — otherwise a stray ``config.yaml``
    in the repo root leaks into ``_check_config(None)`` results.
    """
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cwd = tmp_path / "cwd"
    cwd.mkdir(exist_ok=True)
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    # Also patch CLAUDE_SETTINGS_PATH to live under the isolated home.
    monkeypatch.setattr(
        doc, "CLAUDE_SETTINGS_PATH", home / ".claude" / "settings.json"
    )
    return home


def _read_last_json(capsys) -> dict:
    out = capsys.readouterr().out.strip()
    return json.loads([ln for ln in out.splitlines() if ln.strip()][-1])


# ── CheckResult dataclass ─────────────────────────────────────────


class TestCheckResultDataclass:
    def test_all_four_status_values_accepted(self):
        for status in (doc.STATUS_OK, doc.STATUS_WARN, doc.STATUS_FAIL, doc.STATUS_INFO):
            r = doc.CheckResult(name="x", status=status, detail="d")
            assert r.status == status

    def test_remediation_optional_default_none(self):
        r = doc.CheckResult(name="x", status=doc.STATUS_OK, detail="d")
        assert r.remediation is None

    def test_invalid_status_normalised_to_fail(self):
        # Defensive: a check returning an unknown status surfaces as FAIL
        # rather than silently mis-classifying. The detail must also
        # carry the original bad value so the diagnostic is actionable
        # (regression guard for the post_init capture-then-reassign order).
        r = doc.CheckResult(name="x", status="bogus", detail="d")
        assert r.status == doc.STATUS_FAIL
        assert "'bogus'" in r.detail
        assert "d" in r.detail  # original detail preserved


# ── _check_daemon ─────────────────────────────────────────────────


class TestCheckDaemon:
    def test_no_lock_returns_info_not_running(self, isolated_home):
        r = doc._check_daemon()
        assert r.status == doc.STATUS_INFO
        assert "not running" in r.detail.lower()

    def test_alive_pid_returns_ok(self, isolated_home):
        # Use os.getpid() — guaranteed alive throughout the test.
        lock = _lock_path_for_test()
        lock.write_text(str(os.getpid()), encoding="utf-8")
        r = doc._check_daemon()
        assert r.status == doc.STATUS_OK
        assert str(os.getpid()) in r.detail

    def test_dead_pid_returns_warn_stale_lock(self, isolated_home, monkeypatch):
        lock = _lock_path_for_test()
        lock.write_text("999999", encoding="utf-8")  # almost-certainly dead PID

        def _boom(pid, sig):
            raise ProcessLookupError("no such process")

        monkeypatch.setattr(doc.os, "kill", _boom)
        r = doc._check_daemon()
        assert r.status == doc.STATUS_WARN
        assert "stale" in r.detail.lower()
        assert r.remediation is not None

    def test_empty_lock_returns_warn(self, isolated_home):
        lock = _lock_path_for_test()
        lock.write_text("", encoding="utf-8")
        r = doc._check_daemon()
        assert r.status == doc.STATUS_WARN

    def test_unparseable_lock_returns_warn(self, isolated_home):
        lock = _lock_path_for_test()
        lock.write_text("not-a-pid", encoding="utf-8")
        r = doc._check_daemon()
        assert r.status == doc.STATUS_WARN


# ── _check_config ─────────────────────────────────────────────────


class TestCheckConfig:
    def test_valid_config_returns_ok(self, isolated_home, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("check_interval_seconds: 30\n", encoding="utf-8")
        r = doc._check_config(cfg)
        assert r.status == doc.STATUS_OK
        assert str(cfg) in r.detail

    def test_missing_path_returns_fail(self, isolated_home, tmp_path):
        ghost = tmp_path / "ghost.yaml"
        r = doc._check_config(ghost)
        assert r.status == doc.STATUS_FAIL
        assert r.remediation is not None

    def test_no_config_anywhere_returns_info(self, isolated_home):
        # No --config provided + no config under HOME → defaults active.
        r = doc._check_config(None)
        assert r.status == doc.STATUS_INFO


# ── _check_config_dir_perms ───────────────────────────────────────


class TestCheckConfigDirPerms:
    def test_700_returns_ok(self, isolated_home):
        cfg_dir = isolated_home / ".config" / "sentinel"
        cfg_dir.mkdir(parents=True)
        os.chmod(cfg_dir, 0o700)
        r = doc._check_config_dir_perms()
        assert r.status == doc.STATUS_OK

    def test_755_returns_warn_with_remediation(self, isolated_home):
        cfg_dir = isolated_home / ".config" / "sentinel"
        cfg_dir.mkdir(parents=True)
        os.chmod(cfg_dir, 0o755)
        r = doc._check_config_dir_perms()
        assert r.status == doc.STATUS_WARN
        assert "chmod 700" in (r.remediation or "")

    def test_777_returns_warn(self, isolated_home):
        cfg_dir = isolated_home / ".config" / "sentinel"
        cfg_dir.mkdir(parents=True)
        os.chmod(cfg_dir, 0o777)
        r = doc._check_config_dir_perms()
        assert r.status == doc.STATUS_WARN

    def test_missing_dir_returns_info(self, isolated_home):
        r = doc._check_config_dir_perms()
        assert r.status == doc.STATUS_INFO


# ── _check_event_logs ─────────────────────────────────────────────


class TestCheckEventLogs:
    def test_empty_dir_returns_info(self, isolated_home):
        ev = doc._events_dir()
        ev.mkdir(parents=True)
        r = doc._check_event_logs()
        assert r.status == doc.STATUS_INFO

    def test_missing_dir_returns_info(self, isolated_home):
        r = doc._check_event_logs()
        assert r.status == doc.STATUS_INFO

    def test_files_present_returns_ok_with_count_and_latest(self, isolated_home):
        ev = doc._events_dir()
        ev.mkdir(parents=True)
        (ev / "2026-04-30.jsonl").write_text("", encoding="utf-8")
        (ev / "2026-05-01.jsonl").write_text("", encoding="utf-8")
        (ev / "2026-05-02.jsonl").write_text("", encoding="utf-8")
        r = doc._check_event_logs()
        assert r.status == doc.STATUS_OK
        assert "3 files" in r.detail
        assert "2026-05-02" in r.detail


# ── _check_hook ───────────────────────────────────────────────────


class TestCheckHook:
    def _write_settings(self, isolated_home, payload: dict) -> Path:
        # The fixture patched CLAUDE_SETTINGS_PATH to home/.claude/settings.json.
        settings_path = doc.CLAUDE_SETTINGS_PATH
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(payload), encoding="utf-8")
        return settings_path

    def test_hook_present_returns_ok(self, isolated_home):
        self._write_settings(
            isolated_home,
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "/x sentinel hook-check"}
                            ],
                        }
                    ]
                }
            },
        )
        r = doc._check_hook()
        assert r.status == doc.STATUS_OK

    def test_hook_missing_returns_info_with_install_hint(self, isolated_home):
        self._write_settings(isolated_home, {"hooks": {"PreToolUse": []}})
        r = doc._check_hook()
        assert r.status == doc.STATUS_INFO
        assert "sentinel hooks install" in (r.remediation or "")

    def test_settings_file_absent_returns_info(self, isolated_home):
        # No file written.
        r = doc._check_hook()
        assert r.status == doc.STATUS_INFO


# ── _check_backup_files ───────────────────────────────────────────


class TestCheckBackupFiles:
    def _seed_backups(self, isolated_home, n: int) -> None:
        cfg_dir = isolated_home / ".config" / "sentinel"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        for i in range(n):
            (cfg_dir / f"config.yaml.bak.{1700000000 + i}").write_text(
                "", encoding="utf-8"
            )

    def test_zero_backups_returns_ok(self, isolated_home):
        # Config dir exists but no backups.
        (isolated_home / ".config" / "sentinel").mkdir(parents=True)
        r = doc._check_backup_files()
        assert r.status == doc.STATUS_OK
        assert "0" in r.detail

    def test_no_config_dir_returns_ok(self, isolated_home):
        r = doc._check_backup_files()
        assert r.status == doc.STATUS_OK

    def test_five_backups_still_ok(self, isolated_home):
        self._seed_backups(isolated_home, 5)
        r = doc._check_backup_files()
        assert r.status == doc.STATUS_OK

    def test_eleven_backups_returns_warn(self, isolated_home):
        self._seed_backups(isolated_home, 11)
        r = doc._check_backup_files()
        assert r.status == doc.STATUS_WARN
        assert "11" in r.detail
        assert r.remediation is not None


# ── _check_data_dir ───────────────────────────────────────────────


class TestCheckDataDir:
    def test_missing_returns_info(self, isolated_home):
        # Missing data dir is the legitimate fresh-install state — daemon
        # creates it on first run. INFO, not FAIL, so a brand-new install
        # of `sentinel doctor` exits 0.
        r = doc._check_data_dir()
        assert r.status == doc.STATUS_INFO
        assert "first daemon run" in r.detail.lower()

    def test_writable_returns_ok(self, isolated_home):
        d = doc._data_dir()
        d.mkdir(parents=True)
        r = doc._check_data_dir()
        assert r.status == doc.STATUS_OK

    def test_unwritable_returns_fail(self, isolated_home):
        # The real FAIL case: dir exists but is not writable. This is a
        # genuine misconfiguration the user must fix.
        d = doc._data_dir()
        d.mkdir(parents=True)
        try:
            os.chmod(d, 0o500)  # read+execute only, no write
            r = doc._check_data_dir()
            assert r.status == doc.STATUS_FAIL
            assert r.remediation is not None
        finally:
            os.chmod(d, 0o700)  # restore so cleanup works


# ── _check_host_context_cache ─────────────────────────────────────


class TestCheckHostContextCache:
    def test_no_cache_returns_info(self, isolated_home):
        # Data dir absent → cache absent → info, no quarantines either.
        r = doc._check_host_context_cache()
        assert r.status == doc.STATUS_INFO

    def test_valid_cache_returns_ok(self, isolated_home):
        d = doc._data_dir()
        d.mkdir(parents=True)
        cache = d / "host_context.jsonl"
        cache.write_text(
            "\n".join(
                [
                    json.dumps({"_meta": {"schema": 1, "written_at": 1}}),
                    json.dumps({"host": "github.com", "count": 3}),
                    json.dumps({"host": "x.io", "count": 5}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        r = doc._check_host_context_cache()
        assert r.status == doc.STATUS_OK
        assert "2 hosts" in r.detail

    def test_corrupted_quarantine_present_returns_warn(self, isolated_home):
        d = doc._data_dir()
        d.mkdir(parents=True)
        (d / "host_context.jsonl.corrupted-1714694400").write_text(
            "garbage", encoding="utf-8"
        )
        r = doc._check_host_context_cache()
        assert r.status == doc.STATUS_WARN

    def test_unparseable_cache_returns_fail(self, isolated_home):
        d = doc._data_dir()
        d.mkdir(parents=True)
        (d / "host_context.jsonl").write_text(
            "not json at all\n", encoding="utf-8"
        )
        r = doc._check_host_context_cache()
        assert r.status == doc.STATUS_FAIL


# ── _check_optional_deps ──────────────────────────────────────────


class TestCheckOptionalDeps:
    def test_returns_info_with_four_packages(self, isolated_home):
        r = doc._check_optional_deps()
        assert r.status == doc.STATUS_INFO
        for name in ("ruamel.yaml", "rumps", "terminal-notifier", "osx-cpu-temp"):
            assert name in r.detail


# ── _run_all_checks runner ────────────────────────────────────────


class TestRunAllChecks:
    def test_all_nine_check_names_present(self, isolated_home):
        results = doc._run_all_checks(None)
        names = [r.name for r in results]
        assert names == [
            "daemon",
            "config",
            "config_dir_perms",
            "data_dir",
            "event_logs",
            "hook",
            "host_context_cache",
            "backup_files",
            "optional_deps",
        ]

    def test_exception_in_one_check_isolated_to_fail_row(
        self, isolated_home, monkeypatch
    ):
        # Make ONE check raise; the rest must still run.
        def _boom():
            raise RuntimeError("simulated failure")

        monkeypatch.setattr(doc, "_check_daemon", _boom)
        results = doc._run_all_checks(None)
        # All 9 still emitted.
        assert len(results) == 9
        # The boom row carries the exception class name + message.
        daemon_row = next(r for r in results if r.name == "daemon")
        assert daemon_row.status == doc.STATUS_FAIL
        assert "RuntimeError" in daemon_row.detail
        assert "simulated failure" in daemon_row.detail


# ── CLI dispatch ──────────────────────────────────────────────────


class TestDoctorCli:
    def test_text_output_has_header_and_summary(self, isolated_home, capsys):
        rc = doc.dispatch([])
        out = capsys.readouterr().out
        assert "Sentinel Doctor" in out
        # Summary line — counts always present even if some are zero.
        assert "Summary:" in out
        # Words "OK", "WARN", "FAIL", "INFO" all appear in the summary tail
        # regardless of which checks fired (zero-counts still emit the label).
        for label in ("OK", "WARN", "FAIL", "INFO"):
            assert label in out
        # `daemon_lock_path()` (called by `_check_daemon`) implicitly creates
        # `~/.local/share/sentinel/`, so by the time `_check_data_dir` runs
        # the directory exists. With every check landing on OK / INFO, the
        # default isolated state is exit 0.
        assert rc == 0

    def test_json_envelope_shape(self, isolated_home, capsys):
        rc = doc.dispatch(["--json"])
        env = _read_last_json(capsys)
        # ADR 0004 §D2 verbatim shape.
        assert set(env.keys()) == {"version", "kind", "generated_at", "data"}
        assert env["version"] == 1
        assert env["kind"] == "health_check"
        assert env["generated_at"].endswith("Z")
        # data.summary + data.checks contract.
        data = env["data"]
        assert set(data.keys()) == {"summary", "checks"}
        assert set(data["summary"].keys()) == {"ok", "warn", "fail", "info"}
        assert isinstance(data["checks"], list) and len(data["checks"]) == 9
        # Per-check shape.
        for row in data["checks"]:
            assert set(row.keys()) == {"name", "status", "detail", "remediation"}
            assert row["status"] in {"ok", "warn", "fail", "info"}

    def test_exit_0_when_no_fail(self, isolated_home, capsys, monkeypatch):
        # Force every check to OK so the exit code reflects the no-FAIL path.
        def _all_ok():
            return [
                doc.CheckResult(name=n, status=doc.STATUS_OK, detail="ok")
                for n in (
                    "daemon", "config", "config_dir_perms", "data_dir",
                    "event_logs", "hook", "host_context_cache", "backup_files",
                    "optional_deps",
                )
            ]
        monkeypatch.setattr(doc, "_run_all_checks", lambda cfg: _all_ok())
        assert doc.dispatch([]) == 0

    def test_exit_1_when_any_fail(self, isolated_home, capsys, monkeypatch):
        def _one_fail():
            return [
                doc.CheckResult(name="daemon", status=doc.STATUS_FAIL, detail="x"),
                doc.CheckResult(name="config", status=doc.STATUS_OK, detail="ok"),
            ]
        monkeypatch.setattr(doc, "_run_all_checks", lambda cfg: _one_fail())
        assert doc.dispatch([]) == 1

    def test_config_flag_propagates(self, isolated_home, tmp_path, capsys):
        cfg = tmp_path / "explicit.yaml"
        cfg.write_text("check_interval_seconds: 30\n", encoding="utf-8")
        rc = doc.dispatch(["--config", str(cfg), "--json"])
        env = _read_last_json(capsys)
        config_row = next(
            r for r in env["data"]["checks"] if r["name"] == "config"
        )
        # Path appears in the OK detail line — proves the flag wired through.
        assert config_row["status"] == "ok"
        assert str(cfg) in config_row["detail"]


class TestDoctorEnvelopeShape:
    """ADR 0004 §D2 verbatim envelope check (mirrors test_context_cli helper)."""

    def _assert_envelope_shape(self, env: dict, *, kind: str) -> None:
        assert set(env.keys()) == {"version", "kind", "generated_at", "data"}
        assert env["version"] == 1
        assert env["kind"] == kind
        assert isinstance(env["generated_at"], str)
        assert env["generated_at"].endswith("Z")
        assert isinstance(env["data"], dict)

    def test_kind_is_health_check(self, isolated_home, capsys):
        doc.dispatch(["--json"])
        env = _read_last_json(capsys)
        self._assert_envelope_shape(env, kind="health_check")

    def test_health_check_kind_extends_adr0004_set(self):
        # The ADR 0004 §D2 frozen `kind` set is extended additively by
        # this module — `health_check` is the new kind. This test
        # documents that intent so an unrelated rename triggers a
        # CHANGELOG / ADR conversation.
        assert "health_check" not in {
            "host_context_status",
            "host_context_host_detail",
            "host_context_mutation",
            "report_events",
            "agent_download_summary",
        }


# ─── ADR 0009 — sentinel doctor --cleanup-backups ──────────────────


def _seed_backups_with_epochs(cfg_dir: Path, epochs: list[int]) -> list[Path]:
    """Create config.yaml.bak.<epoch> files; return their paths."""
    cfg_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for e in epochs:
        p = cfg_dir / f"config.yaml.bak.{e}"
        p.write_text(f"# fake backup for epoch {e}\n", encoding="utf-8")
        paths.append(p)
    return paths


@pytest.fixture
def cleanup_env(isolated_home, monkeypatch, tmp_path):
    """Set up an isolated config + backups directory for cleanup tests.

    Creates ~/.config/sentinel/config.yaml so resolve_config_path()
    finds it, plus a fixed list of backup epochs that callers can
    mutate. Patches sys.stdin.isatty to True by default so prompts are
    not auto-cancelled (cron-safe path is tested explicitly).
    """
    cfg_dir = isolated_home / ".config" / "sentinel"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    config = cfg_dir / "config.yaml"
    config.write_text("check_interval_seconds: 30\n", encoding="utf-8")
    # Default: TTY so input() prompts work (we monkeypatch input to "y"
    # in tests that need confirmation).
    monkeypatch.setattr(doc.sys.stdin, "isatty", lambda: True)
    return {"cfg_dir": cfg_dir, "config": config}


class TestCleanupBackupsArgValidation:
    """ADR 0009 D2 — --keep is mandatory."""

    def test_no_keep_returns_exit_2(self, cleanup_env, capsys):
        rc = doc.dispatch(["--cleanup-backups"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "--keep" in err
        # The example in the error message helps users recover.
        assert "--keep 3" in err

    def test_negative_keep_returns_exit_2(self, cleanup_env, capsys):
        rc = doc.dispatch(["--cleanup-backups", "--keep", "-1"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "must be >= 0" in err

    def test_zero_keep_is_valid_intent(self, cleanup_env, monkeypatch, capsys):
        """ADR 0009 D2 — --keep 0 is valid (delete all backups)."""
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300])
        monkeypatch.setattr("builtins.input", lambda _: "y")
        rc = doc.dispatch(["--cleanup-backups", "--keep", "0"])
        assert rc == 0
        # All three deleted.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert remaining == []


class TestCleanupBackupsSelection:
    """ADR 0009 D3 — most-recent N by epoch in filename, mtime ignored."""

    def test_keeps_n_most_recent(self, cleanup_env, monkeypatch):
        # 5 backups; keep 3 → delete the 2 oldest by epoch.
        epochs = [100, 200, 300, 400, 500]
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], epochs)
        monkeypatch.setattr("builtins.input", lambda _: "y")
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3"])
        assert rc == 0
        remaining_names = sorted(
            p.name for p in cleanup_env["cfg_dir"].glob("config.yaml.bak.*")
        )
        # 3 newest survive (300, 400, 500).
        assert remaining_names == [
            "config.yaml.bak.300",
            "config.yaml.bak.400",
            "config.yaml.bak.500",
        ]

    def test_non_int_suffix_is_skipped(self, cleanup_env, monkeypatch):
        """ADR 0009 D3 — defensive skip of files matching the glob but
        not the freeze pattern. Critically: such files are NEVER
        deleted, even when --keep 0."""
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200])
        # Add a non-int-suffix file that matches the .bak.* glob.
        weird = cleanup_env["cfg_dir"] / "config.yaml.bak.notanint"
        weird.write_text("weird", encoding="utf-8")
        monkeypatch.setattr("builtins.input", lambda _: "y")
        rc = doc.dispatch(["--cleanup-backups", "--keep", "0"])
        assert rc == 0
        # The weird file MUST still be there (skipped from selection).
        assert weird.exists()
        # The two int-suffix backups were deleted.
        ints = sorted(
            p.name for p in cleanup_env["cfg_dir"].glob("config.yaml.bak.*")
            if p.name.split(".bak.", 1)[-1].isdigit()
        )
        assert ints == []


class TestCleanupBackupsInteractive:
    """ADR 0009 D4 — interactive [y/N] prompt by default."""

    def test_user_says_y_proceeds(self, cleanup_env, monkeypatch, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        monkeypatch.setattr("builtins.input", lambda _: "y")
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Will delete 2 backup file(s)" in out
        # 3 backups remain (300, 400, 500).
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 3

    def test_user_says_n_cancels(self, cleanup_env, monkeypatch, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        monkeypatch.setattr("builtins.input", lambda _: "n")
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Cancelled" in out
        # All 5 still there.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 5

    def test_user_eof_cancels(self, cleanup_env, monkeypatch, capsys):
        """Ctrl-D / EOF on prompt → cancel cleanly, no traceback."""
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])

        def _eof(_):
            raise EOFError()
        monkeypatch.setattr("builtins.input", _eof)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3"])
        assert rc == 0
        # All 5 still there.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 5

    def test_yes_skips_prompt(self, cleanup_env, monkeypatch):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])

        # If anything calls input() the test should fail loudly — --yes
        # must skip the prompt entirely.
        def _explode(_):
            raise AssertionError("--yes must skip the input() prompt")
        monkeypatch.setattr("builtins.input", _explode)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3", "--yes"])
        assert rc == 0
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 3

    def test_dry_run_does_not_delete(self, cleanup_env, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3", "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Would delete 2 backup file(s)" in out
        # All 5 untouched.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 5


class TestCleanupBackupsIdempotency:
    """ADR 0009 D5 — running twice in a row is safe."""

    def test_nothing_to_delete_when_under_keep(self, cleanup_env, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300])
        rc = doc.dispatch(["--cleanup-backups", "--keep", "10", "--yes"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Nothing to delete" in out
        # Files untouched.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 3

    def test_second_run_after_cleanup_is_noop(self, cleanup_env, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        # First run: deletes 2.
        rc1 = doc.dispatch(["--cleanup-backups", "--keep", "3", "--yes"])
        assert rc1 == 0
        capsys.readouterr()  # discard
        # Second run: nothing to delete.
        rc2 = doc.dispatch(["--cleanup-backups", "--keep", "3", "--yes"])
        assert rc2 == 0
        out = capsys.readouterr().out
        assert "Nothing to delete" in out


class TestCleanupBackupsNonTty:
    """ADR 0009 D4 — cron-safe non-TTY behavior."""

    def test_non_tty_no_yes_auto_cancels(
        self, cleanup_env, monkeypatch, capsys
    ):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        monkeypatch.setattr(doc.sys.stdin, "isatty", lambda: False)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3"])
        # Auto-cancel exit code is 0 (the operation was deliberately
        # not-performed; nothing went wrong from the CLI's perspective).
        assert rc == 0
        err = capsys.readouterr().err
        assert "non-TTY stdin" in err
        assert "skipping deletion" in err
        # All 5 still there — never touched the filesystem.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 5

    def test_non_tty_with_yes_proceeds(
        self, cleanup_env, monkeypatch
    ):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        monkeypatch.setattr(doc.sys.stdin, "isatty", lambda: False)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3", "--yes"])
        # --yes overrides the non-TTY cancel — cron use case.
        assert rc == 0
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 3


class TestCleanupBackupsJson:
    """ADR 0009 D6 — JSON envelope shape (kind=backup_cleanup)."""

    def test_envelope_shape(self, cleanup_env, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3", "--json"])
        # JSON mode implies --yes per ADR 0009 D6.
        assert rc == 0
        env = _read_last_json(capsys)
        # ADR 0004 §D2 envelope shape verbatim.
        assert set(env.keys()) == {"version", "kind", "generated_at", "data"}
        assert env["version"] == 1
        assert env["kind"] == "backup_cleanup"
        assert env["generated_at"].endswith("Z")
        # data shape per ADR 0009 D6.
        data = env["data"]
        assert data["found"] == 5
        assert data["kept"] == 3
        assert len(data["deleted"]) == 2
        assert data["dry_run"] is False
        assert "config_path" in data
        # Confirm the actual delete happened.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 3

    def test_dry_run_envelope_marks_dry_run(self, cleanup_env, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])
        rc = doc.dispatch([
            "--cleanup-backups", "--keep", "3", "--json", "--dry-run"
        ])
        assert rc == 0
        env = _read_last_json(capsys)
        assert env["data"]["dry_run"] is True
        assert env["data"]["found"] == 5
        assert len(env["data"]["deleted"]) == 2  # what would be deleted
        # All 5 still there — dry run.
        remaining = list(cleanup_env["cfg_dir"].glob("config.yaml.bak.*"))
        assert len(remaining) == 5

    def test_json_nothing_to_delete(self, cleanup_env, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300])
        rc = doc.dispatch(["--cleanup-backups", "--keep", "10", "--json"])
        assert rc == 0
        env = _read_last_json(capsys)
        assert env["kind"] == "backup_cleanup"
        assert env["data"]["found"] == 3
        assert env["data"]["kept"] == 3
        assert env["data"]["deleted"] == []


class TestCleanupBackupsKindInFrozenSet:
    """ADR 0004 §D2 frozen `kind` set extends to backup_cleanup
    additively (no version bump)."""

    def test_backup_cleanup_kind_distinct(self):
        # Documents that backup_cleanup is a NEW kind, not a rename of
        # any existing one. A future rename would require a CHANGELOG
        # / ADR conversation.
        assert "backup_cleanup" not in {
            "host_context_status",
            "host_context_host_detail",
            "host_context_mutation",
            "report_events",
            "agent_download_summary",
            "health_check",
        }


class TestCleanupBackupsPartialFailure:
    """ADR 0009 D7 — partial unlink failure → exit 1, errors surfaced."""

    def test_partial_failure_returns_exit_1(self, cleanup_env, monkeypatch, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])

        # Make every other unlink raise PermissionError.
        original_unlink = Path.unlink
        call_count = {"n": 0}

        def _flaky_unlink(self, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] % 2 == 0:
                raise PermissionError(f"simulated EACCES on {self}")
            return original_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", _flaky_unlink)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3", "--yes"])
        # Some failed → exit 1.
        assert rc == 1
        err = capsys.readouterr().err
        assert "failed to delete" in err

    def test_partial_failure_in_json(self, cleanup_env, monkeypatch, capsys):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300, 400, 500])

        original_unlink = Path.unlink

        def _all_fail(self, *args, **kwargs):
            raise PermissionError(f"simulated EACCES on {self}")

        monkeypatch.setattr(Path, "unlink", _all_fail)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3", "--json"])
        assert rc == 1
        env = _read_last_json(capsys)
        # data.errors populated per ADR 0009 D7 / D6.
        assert "errors" in env["data"]
        assert len(env["data"]["errors"]) == 2
        for row in env["data"]["errors"]:
            assert "path" in row and "error" in row
            assert "PermissionError" in row["error"]
        # Still call original_unlink for cleanup.
        monkeypatch.setattr(Path, "unlink", original_unlink)


class TestCleanupBackupsMutuallyExclusive:
    """ADR 0009 D1 — cleanup mode skips the 9-check pass entirely."""

    def test_cleanup_does_not_emit_health_check_envelope(
        self, cleanup_env, capsys
    ):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300])
        rc = doc.dispatch([
            "--cleanup-backups", "--keep", "10", "--json"
        ])
        assert rc == 0
        env = _read_last_json(capsys)
        # The 9-check JSON envelope is kind=health_check; cleanup mode
        # MUST emit kind=backup_cleanup instead. Mutually exclusive.
        assert env["kind"] == "backup_cleanup"
        assert env["kind"] != "health_check"

    def test_cleanup_text_does_not_print_doctor_header(
        self, cleanup_env, capsys
    ):
        _seed_backups_with_epochs(cleanup_env["cfg_dir"], [100, 200, 300])
        doc.dispatch(["--cleanup-backups", "--keep", "10", "--yes"])
        out = capsys.readouterr().out
        # The 9-check text output starts with "Sentinel Doctor —" and
        # ends with a "Summary:" line. Cleanup mode shows neither.
        assert "Sentinel Doctor —" not in out
        assert "Summary:" not in out


class TestCleanupBackupsConfigFlag:
    """--config flag points the cleanup at a specific config file."""

    def test_explicit_config_flag(self, isolated_home, tmp_path, monkeypatch, capsys):
        # Custom config dir under tmp_path (not the standard XDG path).
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        custom_config = custom_dir / "myconfig.yaml"
        custom_config.write_text("check_interval_seconds: 30\n", encoding="utf-8")
        # Backups for the custom config name.
        for e in (100, 200, 300, 400, 500):
            (custom_dir / f"myconfig.yaml.bak.{e}").write_text("x", encoding="utf-8")
        monkeypatch.setattr(doc.sys.stdin, "isatty", lambda: True)
        rc = doc.dispatch([
            "--cleanup-backups", "--keep", "3",
            "--config", str(custom_config), "--yes",
        ])
        assert rc == 0
        # 3 newest survive.
        remaining = sorted(p.name for p in custom_dir.glob("myconfig.yaml.bak.*"))
        assert remaining == [
            "myconfig.yaml.bak.300",
            "myconfig.yaml.bak.400",
            "myconfig.yaml.bak.500",
        ]

    def test_no_config_anywhere_returns_exit_2(
        self, isolated_home, monkeypatch, capsys
    ):
        # No config in cwd, no XDG config — _resolve_config_for_cleanup
        # returns None.
        monkeypatch.setattr(doc.sys.stdin, "isatty", lambda: True)
        rc = doc.dispatch(["--cleanup-backups", "--keep", "3"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "no config file found" in err
