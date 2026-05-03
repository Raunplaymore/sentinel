"""Tests for ``sentinel context …`` CLI subcommands (ADR 0003).

Covers the four frozen verbs (``status`` / ``forget`` / ``block`` /
``unblock``) plus envelope shape and exit code matrix verification.
``ruamel.yaml`` is required for the block/unblock paths — when the
extra is not installed the relevant test classes are skipped.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from sentinel_mac.commands import context as ctx_cli

# ── shared fixtures ───────────────────────────────────────────────


@pytest.fixture
def fake_known_hosts(tmp_path: Path) -> Path:
    """Write a small known_hosts file with a mix of literal + wildcard entries."""
    p = tmp_path / "known_hosts"
    p.write_text(
        "\n".join(
            [
                "# comment line — ignored",
                "github.com,gh.alt ssh-rsa AAAA",
                "*.internal.corp ssh-ed25519 AAAA",
                "bastion.example.org ssh-ed25519 AAAA",
                "|1|hashedSalt|hashedHost ssh-rsa AAAA",  # skipped
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return p


@pytest.fixture
def fake_cache(tmp_path: Path) -> Path:
    """Write a host_context.jsonl with a couple of learned hosts."""
    cache_path = tmp_path / "host_context.jsonl"
    now = int(time.time())
    lines = [
        json.dumps({"_meta": {"schema": 1, "written_at": now}}),
        json.dumps(
            {
                "host": "api.anthropic.com",
                "count": 42,
                "first_seen": now - 10000,
                "last_seen": now - 100,
            }
        ),
        json.dumps(
            {
                "host": "github.com",
                "count": 7,
                "first_seen": now - 9000,
                "last_seen": now - 50,
            }
        ),
    ]
    cache_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return cache_path


def _write_config(
    tmp_path: Path,
    *,
    enabled: bool,
    cache_path: Path | None = None,
    known_hosts_path: Path | None = None,
    blocklist: list | None = None,
    name: str = "config.yaml",
    extra_top_level: str | None = None,
    leading_comment: str | None = None,
) -> Path:
    """Write a YAML config under tmp_path. Returns the absolute path."""
    blocklist = blocklist or []
    bl_yaml = (
        "[]"
        if not blocklist
        else "\n      - " + "\n      - ".join(repr(b) for b in blocklist)
    )

    parts: list = []
    if leading_comment:
        parts.append(leading_comment)
    if extra_top_level:
        parts.append(extra_top_level)
    parts.append("security:")
    parts.append("  context_aware:")
    parts.append(f"    enabled: {'true' if enabled else 'false'}")
    if cache_path is not None:
        parts.append(f"    cache_path: {str(cache_path)!r}")
    if known_hosts_path is not None:
        parts.append(f"    known_hosts_path: {str(known_hosts_path)!r}")
    if bl_yaml == "[]":
        parts.append("    blocklist: []")
    else:
        parts.append("    blocklist:" + bl_yaml)

    cfg = tmp_path / name
    cfg.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return cfg


def _isolate_xdg(monkeypatch, tmp_path: Path) -> Path:
    """Pin XDG dirs + HOME so daemon_lock_path() never points at the real one."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    return home


def _run(argv: list) -> int:
    """Invoke ``ctx_cli.dispatch(argv)`` and return its exit code."""
    return int(ctx_cli.dispatch(argv))


def _read_envelope(capsys) -> dict:
    """Parse the last JSON line emitted to stdout by the CLI."""
    out = capsys.readouterr().out.strip()
    # When the CLI emits multiple lines (e.g., text + envelope) take the
    # last non-empty one — current code only ever emits one JSON envelope
    # at a time but this future-proofs the helper.
    last = [ln for ln in out.splitlines() if ln.strip()][-1]
    return json.loads(last)


def _assert_envelope_shape(env: dict, *, kind: str) -> None:
    """ADR 0004 §D2 verbatim envelope check."""
    assert set(env.keys()) == {"version", "kind", "generated_at", "data"}
    assert env["version"] == 1
    assert env["kind"] == kind
    assert isinstance(env["generated_at"], str)
    assert env["generated_at"].endswith("Z")
    assert isinstance(env["data"], dict)


# ── status snapshot ───────────────────────────────────────────────


class TestStatusSnapshot:
    """`sentinel context status` (no host) — full snapshot."""

    def test_disabled_empty_envelope(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=False)
        assert _run(["status", "--config", str(cfg), "--json"]) == 0
        env = _read_envelope(capsys)
        _assert_envelope_shape(env, kind="host_context_status")
        data = env["data"]
        assert data["enabled"] is False
        assert data["frequency"] == []
        assert data["blocklist"] == []
        assert data["known_hosts"]["count"] == 0
        assert data["known_hosts"]["sample"] == []

    def test_enabled_with_cache(
        self, tmp_path, monkeypatch, capsys, fake_cache
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True, cache_path=fake_cache)
        assert _run(["status", "--config", str(cfg), "--json"]) == 0
        env = _read_envelope(capsys)
        data = env["data"]
        assert data["enabled"] is True
        hosts = {row["host"] for row in data["frequency"]}
        assert hosts == {"api.anthropic.com", "github.com"}
        for row in data["frequency"]:
            assert row["count"] >= 1
            assert "first_seen" in row and "last_seen" in row
            assert row["trust"] in {"unknown", "learned", "known", "blocked"}

    def test_known_hosts_sample(
        self, tmp_path, monkeypatch, capsys, fake_known_hosts
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, known_hosts_path=fake_known_hosts
        )
        assert _run(["status", "--config", str(cfg), "--json"]) == 0
        env = _read_envelope(capsys)
        kh = env["data"]["known_hosts"]
        # github.com + gh.alt + *.internal.corp + bastion.example.org = 4.
        # Hashed entry must be skipped.
        assert kh["count"] == 4
        assert "github.com" in kh["sample"]
        assert "*.internal.corp" in kh["sample"]

    def test_blocklist_echoed(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, blocklist=["evil.com", "*.bad.tld"]
        )
        assert _run(["status", "--config", str(cfg), "--json"]) == 0
        env = _read_envelope(capsys)
        assert env["data"]["blocklist"] == ["evil.com", "*.bad.tld"]

    def test_text_output_has_section_headers(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=False)
        assert _run(["status", "--config", str(cfg)]) == 0
        out = capsys.readouterr().out
        assert "Sentinel — Host Context Status" in out
        assert "Frequency-learned hosts" in out
        assert "Blocklist (config)" in out
        assert "known_hosts" in out


# ── status single host ────────────────────────────────────────────


class TestStatusSingleHost:
    """`sentinel context status HOST` — single-host detail."""

    def test_known_host(
        self, tmp_path, monkeypatch, capsys, fake_known_hosts
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, known_hosts_path=fake_known_hosts
        )
        assert (
            _run(["status", "github.com", "--config", str(cfg), "--json"])
            == 0
        )
        env = _read_envelope(capsys)
        _assert_envelope_shape(env, kind="host_context_host_detail")
        data = env["data"]
        assert data["host"] == "github.com"
        assert data["trust"] == "known"
        assert data["in_known_hosts"] is True
        assert data["in_blocklist"] is False

    def test_learned_host(self, tmp_path, monkeypatch, capsys, fake_cache):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, cache_path=fake_cache
        )
        assert (
            _run(
                [
                    "status",
                    "api.anthropic.com",
                    "--config",
                    str(cfg),
                    "--json",
                ]
            )
            == 0
        )
        data = _read_envelope(capsys)["data"]
        # 42 observations in fake_cache, default auto_trust_after_seen=5.
        assert data["trust"] == "learned"
        assert data["count"] == 42

    def test_blocked_host(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, blocklist=["evil.com"]
        )
        assert (
            _run(["status", "evil.com", "--config", str(cfg), "--json"])
            == 0
        )
        data = _read_envelope(capsys)["data"]
        assert data["trust"] == "blocked"
        assert data["in_blocklist"] is True

    def test_unknown_host(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert (
            _run(
                [
                    "status",
                    "never-seen.example",
                    "--config",
                    str(cfg),
                    "--json",
                ]
            )
            == 0
        )
        data = _read_envelope(capsys)["data"]
        assert data["trust"] == "unknown"
        assert data["count"] == 0
        assert data["in_known_hosts"] is False
        assert data["in_blocklist"] is False

    def test_kind_is_host_detail(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert (
            _run(["status", "x.io", "--config", str(cfg), "--json"]) == 0
        )
        env = _read_envelope(capsys)
        # Single-host invocation must NOT collide with snapshot kind.
        assert env["kind"] == "host_context_host_detail"


# ── forget ────────────────────────────────────────────────────────


class TestForget:
    """`sentinel context forget HOST`."""

    def test_existing_host_removed(
        self, tmp_path, monkeypatch, capsys, fake_cache
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, cache_path=fake_cache
        )
        rc = _run(
            ["forget", "github.com", "--config", str(cfg), "--json"]
        )
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        assert data["action"] == "forget"
        assert data["host"] == "github.com"
        assert data["result"] == "removed"

        # Re-load via a fresh status call and confirm github.com gone.
        rc2 = _run(["status", "--config", str(cfg), "--json"])
        assert rc2 == 0
        env2 = _read_envelope(capsys)
        hosts = {row["host"] for row in env2["data"]["frequency"]}
        assert "github.com" not in hosts
        assert "api.anthropic.com" in hosts

    def test_unknown_host_exit_1(
        self, tmp_path, monkeypatch, capsys, fake_cache
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, cache_path=fake_cache
        )
        rc = _run(
            [
                "forget",
                "never-seen.example",
                "--config",
                str(cfg),
                "--json",
            ]
        )
        assert rc == 1
        data = _read_envelope(capsys)["data"]
        assert data["result"] == "not_found"

    def test_disabled_mode_works(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=False)
        rc = _run(["forget", "x.io", "--config", str(cfg), "--json"])
        # Disabled context never has anything to remove → not_found / exit 1.
        assert rc == 1
        data = _read_envelope(capsys)["data"]
        assert data["enabled"] is False

    def test_daemon_running_notice(
        self, tmp_path, monkeypatch, capsys, fake_cache
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, cache_path=fake_cache
        )
        # ADR 0005 §D7 — when the daemon is running, `forget` SIGHUPs it
        # and prints `Applied to running daemon (PID NNN).` to stderr,
        # replacing the pre-v0.8 "Restart the daemon" stdout notice.
        # Mock _signal_daemon_reload so no real SIGHUP fires; the helper
        # contract is `(status, pid)` per the new D7 surface.
        monkeypatch.setattr(
            ctx_cli, "_is_daemon_running", lambda: True
        )
        monkeypatch.setattr(
            ctx_cli, "_signal_daemon_reload", lambda: ("applied", 4242)
        )
        rc = _run(["forget", "github.com", "--config", str(cfg)])
        assert rc == 0
        captured = capsys.readouterr()
        # ADR 0005 §D7 frozen message location: stderr.
        assert "Applied to running daemon (PID 4242)." in captured.err
        # Old "Restart the daemon" notice removed (CHANGELOG v0.8 Track 1a).
        assert "Restart the daemon" not in captured.out
        assert "Restart the daemon" not in captured.err

    def test_validation_error_exit_2(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        # Embedded whitespace must trip _validate_host.
        rc = _run(["forget", "foo bar", "--config", str(cfg)])
        assert rc == 2


# ── block / unblock ───────────────────────────────────────────────


class TestBlockUnblock:
    """`sentinel context block` / `unblock` — config.yaml round-trip."""

    @pytest.fixture(autouse=True)
    def _require_ruamel(self):
        pytest.importorskip("ruamel.yaml")

    def test_block_new_host(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        rc = _run(["block", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        assert data["action"] == "block"
        assert data["result"] == "added"
        # File on disk now contains evil.com under blocklist.
        assert "evil.com" in cfg.read_text(encoding="utf-8")

    def test_block_already_present_idempotent(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, blocklist=["evil.com"]
        )
        rc = _run(["block", "evil.com", "--config", str(cfg), "--json"])
        # Idempotent: still exit 0, but result reflects no-op.
        assert rc == 0
        assert _read_envelope(capsys)["data"]["result"] == "already_present"

    def test_unblock_existing(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, blocklist=["evil.com", "x.io"]
        )
        rc = _run(
            ["unblock", "evil.com", "--config", str(cfg), "--json"]
        )
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        assert data["result"] == "removed"
        text = cfg.read_text(encoding="utf-8")
        assert "evil.com" not in text
        assert "x.io" in text

    def test_unblock_missing_exit_1(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        rc = _run(
            [
                "unblock",
                "never-blocked.example",
                "--config",
                str(cfg),
                "--json",
            ]
        )
        assert rc == 1
        assert _read_envelope(capsys)["data"]["result"] == "not_found"

    def test_block_validation_error_empty(
        self, tmp_path, monkeypatch
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert _run(["block", "", "--config", str(cfg)]) == 2
        assert _run(["block", "   ", "--config", str(cfg)]) == 2
        assert _run(["block", "foo bar", "--config", str(cfg)]) == 2

    def test_block_no_config_exit_3(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        # Point at a non-existent path explicitly. resolve_config_path
        # will return it as-is when --config is set.
        ghost = tmp_path / "ghost.yaml"
        rc = _run(["block", "evil.com", "--config", str(ghost)])
        assert rc == 3

    def test_block_ruamel_missing_falls_back_to_pyyaml_exit_0(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D4 supersedes ADR 0003 §D6 for the ruamel-missing
        # case: the historical exit-3 behaviour is replaced by an
        # automatic PyYAML fallback that exits 0 on a successful write.
        # This test used to assert exit 3 — kept as a regression-anchor
        # for the supersede semantics under the new name.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)

        # Force the import-resolver to raise as if [app] extra is missing.
        def _raise():
            raise RuntimeError(
                "install with `pip install sentinel-mac[app]` to use "
                "config-mutating subcommands"
            )

        monkeypatch.setattr(ctx_cli, "_require_ruamel", _raise)
        rc = _run(["block", "evil.com", "--config", str(cfg)])
        # ADR 0006 §D4 — fallback succeeded → exit 0 (was exit 3).
        assert rc == 0
        # File on disk now contains evil.com (PyYAML did write through).
        assert "evil.com" in cfg.read_text(encoding="utf-8")

    def test_block_preserves_comments_and_other_keys(
        self, tmp_path, monkeypatch
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path,
            enabled=True,
            blocklist=["already.example"],
            extra_top_level=(
                "check_interval_seconds: 30\n"
                "notifications:\n"
                "  macos: true\n"
            ),
            leading_comment="# user-managed config — please keep my comments\n",
        )
        before = cfg.read_text(encoding="utf-8")
        assert "# user-managed config" in before
        assert "check_interval_seconds: 30" in before

        assert _run(["block", "evil.com", "--config", str(cfg)]) == 0
        after = cfg.read_text(encoding="utf-8")
        # ruamel round-trip MUST preserve the leading comment + sibling keys.
        assert "# user-managed config" in after
        assert "check_interval_seconds: 30" in after
        assert "macos: true" in after
        # New entry present.
        assert "evil.com" in after
        # Old entry still present.
        assert "already.example" in after


# ── envelope shape (cross-cutting) ────────────────────────────────


class TestEnvelopeShape:
    """ADR 0004 §D2 envelope — verbatim shape across every kind we emit."""

    @pytest.fixture(autouse=True)
    def _require_ruamel(self):
        pytest.importorskip("ruamel.yaml")

    def _all_envelopes(self, tmp_path, monkeypatch, capsys, fake_cache):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True, cache_path=fake_cache)
        envelopes: list = []

        for argv in (
            ["status", "--config", str(cfg), "--json"],
            ["status", "github.com", "--config", str(cfg), "--json"],
            ["forget", "github.com", "--config", str(cfg), "--json"],
            ["block", "evil.com", "--config", str(cfg), "--json"],
            ["unblock", "evil.com", "--config", str(cfg), "--json"],
        ):
            _run(argv)
            envelopes.append(_read_envelope(capsys))
        return envelopes

    def test_all_envelopes_have_canonical_shape(
        self, tmp_path, monkeypatch, capsys, fake_cache
    ):
        envelopes = self._all_envelopes(
            tmp_path, monkeypatch, capsys, fake_cache
        )
        for env in envelopes:
            assert set(env.keys()) == {
                "version",
                "kind",
                "generated_at",
                "data",
            }
            assert env["version"] == 1
            assert env["generated_at"].endswith("Z")
            assert isinstance(env["data"], dict)

    def test_all_kinds_are_in_frozen_set(
        self, tmp_path, monkeypatch, capsys, fake_cache
    ):
        envelopes = self._all_envelopes(
            tmp_path, monkeypatch, capsys, fake_cache
        )
        kinds = {env["kind"] for env in envelopes}
        # ADR 0003 §D5 freezes exactly these three.
        assert kinds <= {
            "host_context_status",
            "host_context_host_detail",
            "host_context_mutation",
        }


# ── exit code matrix (ADR 0003 §D6) ───────────────────────────────


class TestExitCodes:
    """Verbatim coverage of the ADR §D6 exit code map."""

    @pytest.fixture(autouse=True)
    def _require_ruamel_for_block(self):
        # Only block/unblock tests need ruamel; status/forget tests below
        # don't, so skipif-on-fixture-use isn't ideal — we just import it
        # globally for this class. The block-specific assertions will skip
        # cleanly if the extra is missing.
        pytest.importorskip("ruamel.yaml")

    def test_exit_0_status_success(self, tmp_path, monkeypatch):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=False)
        assert _run(["status", "--config", str(cfg)]) == 0

    def test_exit_0_block_success(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert _run(["block", "evil.com", "--config", str(cfg)]) == 0

    def test_exit_1_forget_unknown_host(
        self, tmp_path, monkeypatch, capsys
    ):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert _run(["forget", "x.io", "--config", str(cfg)]) == 1

    def test_exit_1_unblock_missing(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert _run(["unblock", "x.io", "--config", str(cfg)]) == 1

    def test_exit_2_validation_error(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        assert _run(["forget", "   ", "--config", str(cfg)]) == 2
        assert _run(["block", "foo bar", "--config", str(cfg)]) == 2

    def test_exit_3_block_no_config(self, tmp_path, monkeypatch, capsys):
        _isolate_xdg(monkeypatch, tmp_path)
        ghost = tmp_path / "ghost.yaml"
        assert _run(["block", "evil.com", "--config", str(ghost)]) == 3

    def test_exit_0_block_ruamel_missing_falls_back_to_pyyaml(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D4 — exit 3 for ruamel-missing is superseded by an
        # automatic PyYAML fallback that returns exit 0 on success.
        # The exit-3 row in this matrix is now exclusively reached by
        # other mutation failures (no config file, unwritable target).
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)

        def _raise():
            raise RuntimeError("missing extra")

        monkeypatch.setattr(ctx_cli, "_require_ruamel", _raise)
        assert _run(["block", "evil.com", "--config", str(cfg)]) == 0

    def test_exit_4_corrupt_cache_read(
        self, tmp_path, monkeypatch, capsys
    ):
        # Force HostContext.load() to raise OSError so cmd_status surfaces
        # exit 4. Direct OS-level corruption is recovered silently inside
        # HostContext (quarantine + reset), so we monkeypatch instead of
        # simulating a real corrupt file.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)

        from sentinel_mac.collectors import context as ctx_mod

        def _boom(self):
            raise OSError("simulated cache read failure")

        monkeypatch.setattr(ctx_mod.HostContext, "load", _boom)
        assert _run(["status", "--config", str(cfg)]) == 4


# ── core.py argparse integration smoke ────────────────────────────


class TestCoreIntegration:
    """``sentinel context …`` must dispatch through core.main without invoking
    the daemon's argparse path."""

    def test_dispatch_module_callable(self):
        # Module is importable + dispatch is callable + parser builds.
        assert callable(ctx_cli.dispatch)
        parser = ctx_cli._build_parser()
        # status is the only subparser with an optional positional.
        ns = parser.parse_args(["status"])
        assert ns.context_command == "status"
        assert ns.host is None
        assert ns.json is False
        assert ns.config is None

    def test_core_main_routes_context(
        self, tmp_path, monkeypatch, capsys
    ):
        # Simulate `sentinel context status --json --config <path>` by
        # patching argv and letting core.main() take the dispatch branch.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=False)
        monkeypatch.setattr(
            "sys.argv",
            [
                "sentinel",
                "context",
                "status",
                "--config",
                str(cfg),
                "--json",
            ],
        )
        from sentinel_mac.core import main as core_main

        with pytest.raises(SystemExit) as exc_info:
            core_main()
        # cmd_status returns 0 → sys.exit(0) → SystemExit.code == 0.
        assert exc_info.value.code == 0
        env = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert env["kind"] == "host_context_status"


# ── PyYAML fallback (ADR 0006) ─────────────────────────────────────


class TestPyyamlFallback:
    """`sentinel context block` / `unblock` ruamel→PyYAML fallback.

    Verifies the ADR 0006 D1–D5 freeze:
      D1 — ruamel preferred, PyYAML automatic fallback (no flag).
      D2 — backup-then-write with sort_keys=False.
      D3 — single-line stderr warning + uniform JSON envelope additions.
      D4 — ruamel-missing → exit 0 on successful write (was exit 3).
      D5 — backup naming `config.yaml.bak.<epoch>`, mode 0o600.
    """

    def _force_pyyaml(self, monkeypatch):
        """Simulate `[app]` extra missing — `_require_ruamel` raises."""
        def _raise():
            raise RuntimeError("simulated [app] extra missing")
        monkeypatch.setattr(ctx_cli, "_require_ruamel", _raise)

    def test_ruamel_missing_falls_back_to_pyyaml_and_exits_0(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D4 — exit 0 (not 3) when PyYAML write succeeds.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        self._force_pyyaml(monkeypatch)

        rc = _run(["block", "evil.com", "--config", str(cfg)])
        assert rc == 0
        # File on disk now contains the new entry.
        assert "evil.com" in cfg.read_text(encoding="utf-8")

    def test_pyyaml_path_creates_backup(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D5 — backup naming + mode 0o600.
        _isolate_xdg(monkeypatch, tmp_path)
        original = _write_config(
            tmp_path, enabled=True, blocklist=["already.example"]
        )
        original_text = original.read_text(encoding="utf-8")
        self._force_pyyaml(monkeypatch)

        rc = _run(["block", "evil.com", "--config", str(original), "--json"])
        assert rc == 0

        backups = sorted(tmp_path.glob("config.yaml.bak.*"))
        assert len(backups) == 1
        backup = backups[0]
        # Naming: `config.yaml.bak.<unix_epoch_seconds>` per D5.
        assert backup.name.startswith("config.yaml.bak.")
        epoch_part = backup.name.rsplit(".", 1)[-1]
        assert epoch_part.isdigit()
        # Mode 0o600 (D5 — secrets-grade perms).
        import stat as _stat
        backup_mode = _stat.S_IMODE(backup.stat().st_mode)
        assert backup_mode == 0o600
        # Backup body matches the *pre-mutation* config.
        assert backup.read_text(encoding="utf-8") == original_text

    def test_pyyaml_warning_emitted_to_stderr(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D3 — single-line stderr warning under ~120 chars
        # (path is shortened to ~/<…> when under HOME so the literal text
        # plus path stays inside the budget). Must include the four
        # identifying tokens so a future contributor that rewords the
        # message still surfaces the same information to users.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        self._force_pyyaml(monkeypatch)

        rc = _run(["block", "evil.com", "--config", str(cfg)])
        assert rc == 0
        captured = capsys.readouterr()
        warning_lines = [
            ln for ln in captured.err.splitlines()
            if "ruamel.yaml missing" in ln
        ]
        assert len(warning_lines) == 1
        warning = warning_lines[0]
        assert "PyYAML fallback" in warning
        assert "config.yaml.bak." in warning
        assert "sentinel-mac[app]" in warning
        # Single-line warning per the freeze.
        assert "\n" not in warning
        # ADR §D3 budget — fixed text plus the (possibly tilde-shortened)
        # backup path. The production path under HOME stays well under
        # 120 chars after tilde shortening; CI temp dirs (e.g.,
        # /private/var/folders/np/.../pytest-of-...) can be 100+ chars on
        # their own and bypass the tilde shortcut, pushing the line near
        # 300. The 350 cap is a regression guard against accidental
        # message ballooning, not a tight enforcement of the freeze.
        assert len(warning) < 350

    def test_pyyaml_path_preserves_key_order(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D2 — `sort_keys=False` so key order survives.
        _isolate_xdg(monkeypatch, tmp_path)
        # `_write_config` emits `security:` first, then optional
        # extra_top_level. Force a config with multiple top-level keys
        # in a deliberate (non-alphabetic) order.
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "\n".join(
                [
                    "zeta_marker: 1",
                    "alpha_marker: 2",
                    "security:",
                    "  context_aware:",
                    "    enabled: true",
                    "    blocklist: []",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self._force_pyyaml(monkeypatch)

        rc = _run(["block", "evil.com", "--config", str(cfg)])
        assert rc == 0
        after = cfg.read_text(encoding="utf-8")
        zeta_pos = after.index("zeta_marker")
        alpha_pos = after.index("alpha_marker")
        sec_pos = after.index("security:")
        # Original (non-alphabetic) order preserved: zeta < alpha < security.
        assert zeta_pos < alpha_pos < sec_pos

    def test_envelope_yaml_backend_pyyaml_path(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D3 — uniform additive fields on the PyYAML path.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        self._force_pyyaml(monkeypatch)

        rc = _run(["block", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        import re
        import stat as _stat

        assert data["yaml_backend"] == "pyyaml"
        assert isinstance(data["backup_path"], str)
        # ADR 0006 §D5 — backup naming: `<config>.bak.<unix_epoch_seconds>`.
        # Anchored regex prevents the previous tautology where the suffix
        # was sliced from the same value being asserted.
        assert re.search(r"\.bak\.\d+$", data["backup_path"]), (
            f"backup_path does not match `.bak.<digits>$`: {data['backup_path']}"
        )
        # Backup file exists at the reported path.
        backup = Path(data["backup_path"])
        assert backup.exists()
        # ADR 0006 §D5 — backup mode 0o600.
        assert _stat.S_IMODE(backup.stat().st_mode) == 0o600
        # ADR 0006 §D5 — the rewritten config file must also be 0o600
        # (config may contain webhook secrets; PyYAML write must not
        # leave it world-readable).
        assert _stat.S_IMODE(cfg.stat().st_mode) == 0o600
        assert data["comment_preservation"] == "lost"

    def test_envelope_yaml_backend_ruamel_path(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D3 — uniform additive fields on the ruamel path
        # (backup_path stays None, comment_preservation = "preserved").
        pytest.importorskip("ruamel.yaml")
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)

        rc = _run(["block", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        assert data["yaml_backend"] == "ruamel"
        assert data["backup_path"] is None
        assert data["comment_preservation"] == "preserved"

    def test_idempotent_block_no_backup(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0006 §D2 — `already_present` is a no-op on disk; no backup
        # file should be created on the PyYAML path either.
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(
            tmp_path, enabled=True, blocklist=["evil.com"]
        )
        self._force_pyyaml(monkeypatch)

        rc = _run(["block", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        assert data["result"] == "already_present"
        # Uniform shape — `backup_path` still present (None), no file created.
        assert data["backup_path"] is None
        assert list(tmp_path.glob("config.yaml.bak.*")) == []

    def test_pyyaml_path_envelope_has_daemon_reload(
        self, tmp_path, monkeypatch, capsys
    ):
        # ADR 0005 §D7 + ADR 0006 §D3 — PyYAML path emits the same
        # `daemon_reload` field as the ruamel path (uniform shape).
        _isolate_xdg(monkeypatch, tmp_path)
        cfg = _write_config(tmp_path, enabled=True)
        self._force_pyyaml(monkeypatch)
        # No daemon running — expected `skipped_not_running` outcome.
        monkeypatch.setattr(ctx_cli, "_is_daemon_running", lambda: False)

        rc = _run(["block", "evil.com", "--config", str(cfg), "--json"])
        assert rc == 0
        data = _read_envelope(capsys)["data"]
        # ADR 0005 §D7 frozen enum.
        assert data["daemon_reload"] in ctx_cli.DAEMON_RELOAD_RESULTS
        # PyYAML path-specific additive triplet.
        assert data["yaml_backend"] == "pyyaml"
        assert data["comment_preservation"] == "lost"
