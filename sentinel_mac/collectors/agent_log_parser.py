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
import shlex
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from sentinel_mac.models import SecurityEvent
from sentinel_mac.collectors.context import HostContext, TrustLevel
from sentinel_mac.collectors.project_context import ProjectContext
from sentinel_mac.collectors.typosquatting import (
    check_typosquatting,
    extract_pip_packages,
    extract_npm_packages,
)

logger = logging.getLogger(__name__)


# ── ADR 0007 D1: per-session metadata cache ─────────────────────────────
# Captured from the first ``user`` / ``assistant`` record of each JSONL
# file (housekeeping records — queue-operation / last-prompt / summary /
# permission-mode / file-history-snapshot — are skipped because they
# don't carry cwd / gitBranch / version / model). Defensive reads only:
# missing keys leave the corresponding field None and never raise.

# ADR 0007 D1 explicitly lists {queue-operation, last-prompt, summary} as
# the housekeeping prefix that does not carry session metadata. Observed
# Claude Code 2.1.x JSONLs add `permission-mode` and `file-history-snapshot`
# in the same prefix position — they also lack cwd/version/gitBranch, so
# we extend the skip set as a conservative additive (skip-only — never
# changes which types CAN populate metadata, only which to bypass).
_SESSION_HOUSEKEEPING_TYPES: frozenset[str] = frozenset({
    "queue-operation",
    "last-prompt",
    "summary",
    "permission-mode",
    "file-history-snapshot",
})


@dataclass
class SessionMeta:
    """ADR 0007 D1 — session metadata extracted from a JSONL file.

    All fields are nullable. The cache is per-file (JSONL path → meta);
    cwd is overridden per-message at emit time because Claude Code's
    ``cd`` updates the per-record cwd field but not the cached
    session-start value.
    """
    id: Optional[str] = None
    model: Optional[str] = None
    version: Optional[str] = None
    cwd: Optional[str] = None
    git_branch: Optional[str] = None


def _build_session_detail(
    meta: Optional[SessionMeta], per_message_cwd: Optional[str]
) -> dict:
    """ADR 0007 D2 — build the ``session`` sub-dict for SecurityEvent.detail.

    Always returns a dict with all four keys present (id / model /
    version / cwd); any unknown field is None. Per ADR 0007 D1 step 4,
    ``cwd`` prefers the per-message override and falls back to the
    cached session-start cwd.
    """
    if meta is None:
        meta = SessionMeta()
    return {
        "id": meta.id,
        "model": meta.model,
        "version": meta.version,
        "cwd": per_message_cwd or meta.cwd,
    }


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


# ── ADR 0002: download extraction (curl / wget / git clone) ──────────
# Conservative parser. Returns None when output_path / source_url cannot
# be confidently identified. Recognized patterns (ADR 0002 §D4):
#
#   curl URL -o PATH | --output PATH | -O (basename of URL) | > PATH
#   wget URL -O PATH | --output-document=PATH | (no flag → basename)
#   git clone URL [TARGET]
#
# Out of scope (ADR 0002 §D4): pip download, brew fetch, aria2c, axel,
# httpie, xh, bare shell redirects without curl/wget.

_URL_RE = re.compile(r"https?://[^\s'\";|>&]+")

# curl flags that take an argument (we skip the argument when scanning).
_CURL_ARG_FLAGS: frozenset[str] = frozenset({
    "-o", "--output",
    "-X", "--request",
    "-H", "--header",
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-F", "--form",
    "-u", "--user",
    "-A", "--user-agent",
    "-e", "--referer",
    "-b", "--cookie",
    "-c", "--cookie-jar",
    "-K", "--config",
    "--connect-timeout", "--max-time",
    "--proxy", "-x",
    "--cacert", "--cert", "--key",
    "--retry", "--retry-delay", "--retry-max-time",
    "-T", "--upload-file",
    "--resolve",
    "--range", "-r",
})

# curl long flags that already carry their value via `=` (split lazily).
_CURL_NO_DOWNLOAD_METHODS: frozenset[str] = frozenset({
    "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
})


def _basename_from_url(url: str) -> Optional[str]:
    """Return the trailing path segment of ``url`` if it looks like a filename.

    Strips query string + fragment, returns the last non-empty path
    component or None when the URL has only a hostname.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return None
    path = (parsed.path or "").rstrip("/")
    if not path:
        return None
    base = path.rsplit("/", 1)[-1]
    return base or None


def _extract_url(tokens: list[str]) -> Optional[str]:
    """Find the first http(s):// token in a tokenized command line."""
    for tok in tokens:
        if tok.startswith(("http://", "https://")):
            return tok
        # Some shells quote URLs; strip surrounding quotes.
        stripped = tok.strip("'\"")
        if stripped.startswith(("http://", "https://")):
            return stripped
    return None


def _extract_curl_download(tokens: list[str]) -> Optional[dict]:
    """Parse a tokenized curl command. Returns a download dict or None.

    Only treats the invocation as a download when:
    - A URL is present, AND
    - Either ``-o PATH`` / ``--output PATH`` / ``-O`` is given, OR a shell
      redirect ``> PATH`` follows the curl invocation (handled by caller).

    HTTP methods other than implicit GET (``-X POST`` etc.) cause us to
    return None — the request is probably not a download.
    """
    url: Optional[str] = None
    output_path: Optional[str] = None
    saw_dash_big_o = False
    method_override: Optional[str] = None

    i = 1  # skip leading "curl"
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-o", "--output"):
            if i + 1 < len(tokens):
                output_path = tokens[i + 1]
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("--output="):
            output_path = tok.split("=", 1)[1]
            i += 1
            continue
        if tok == "-O" or tok == "--remote-name":
            saw_dash_big_o = True
            i += 1
            continue
        if tok in ("-X", "--request"):
            if i + 1 < len(tokens):
                method_override = tokens[i + 1].upper()
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("--request="):
            method_override = tok.split("=", 1)[1].upper()
            i += 1
            continue
        # Skip flags-with-args generically.
        if tok in _CURL_ARG_FLAGS:
            i += 2
            continue
        if tok.startswith(("http://", "https://")):
            if url is None:
                url = tok
            i += 1
            continue
        # Bare flags we don't know — just skip without consuming next.
        if tok.startswith("-"):
            i += 1
            continue
        i += 1

    if url is None:
        return None

    # Reject obvious non-download HTTP methods unless an explicit output
    # flag was given (rare but technically possible — `curl -X POST -o
    # response.json …`).
    if (
        method_override
        and method_override in _CURL_NO_DOWNLOAD_METHODS
        and output_path is None
        and not saw_dash_big_o
    ):
        return None

    if output_path is None and saw_dash_big_o:
        output_path = _basename_from_url(url)

    if output_path is None:
        # Plain `curl URL` with no save flag — ADR 0002 §D4 says skip
        # (curl prints to stdout by default; not a download).
        return None

    return {
        "source_url": url,
        "output_path": output_path,
        "downloader": "curl",
    }


def _extract_wget_download(tokens: list[str]) -> Optional[dict]:
    """Parse a tokenized wget command."""
    url: Optional[str] = None
    output_path: Optional[str] = None

    i = 1  # skip leading "wget"
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-O", "--output-document"):
            if i + 1 < len(tokens):
                output_path = tokens[i + 1]
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("--output-document="):
            output_path = tok.split("=", 1)[1]
            i += 1
            continue
        if tok.startswith(("http://", "https://")):
            if url is None:
                url = tok
            i += 1
            continue
        if tok.startswith("-"):
            # Some wget flags take args (`-P DIR`, `--directory-prefix=DIR`,
            # `-e CMD`, `-O FILE`). We already handled -O. Be conservative:
            # when a known short flag is followed by something that does
            # not look like a URL or another flag, consume it.
            if tok in {"-P", "-e", "-i", "-Q", "--quota", "--directory-prefix"}:
                i += 2
                continue
            i += 1
            continue
        i += 1

    if url is None:
        return None

    if output_path is None:
        # ADR 0002 §D4: wget with no flag drops the file in cwd using the
        # URL basename. We don't know cwd, so record only the basename.
        output_path = _basename_from_url(url)

    return {
        "source_url": url,
        "output_path": output_path,
        "downloader": "wget",
    }


def _extract_git_clone_download(tokens: list[str]) -> Optional[dict]:
    """Parse a tokenized git command. Only ``git clone …`` is recognized."""
    if len(tokens) < 3 or tokens[0] != "git" or tokens[1] != "clone":
        return None

    url: Optional[str] = None
    target: Optional[str] = None
    positional: list[str] = []

    i = 2
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            # Skip flag + (possibly) its argument. Be conservative: any
            # `--foo=bar` is single token; `--depth 1` is two.
            if "=" in tok:
                i += 1
                continue
            # Known git clone flags that take an argument.
            if tok in {
                "--depth", "--branch", "-b", "--origin", "-o",
                "--config", "-c", "--reference", "--separate-git-dir",
                "--shallow-since", "--shallow-exclude", "--filter",
                "-j", "--jobs", "--template", "--upload-pack", "-u",
            }:
                i += 2
                continue
            i += 1
            continue
        positional.append(tok)
        i += 1

    if not positional:
        return None
    url = positional[0]
    if len(positional) >= 2:
        target = positional[1]

    if not url.startswith(("http://", "https://", "git://", "ssh://", "git@")):
        # Local-path clone — not a download.
        return None

    if target is None:
        # Default git behavior: directory = repo basename, stripping
        # trailing ".git" if present.
        base = _basename_from_url(url) if url.startswith(("http://", "https://")) else None
        if base is None:
            base = url.rsplit("/", 1)[-1] if "/" in url else url
        if base.endswith(".git"):
            base = base[:-4]
        target = base or None

    if target is None:
        return None

    return {
        "source_url": url,
        "output_path": target,
        "downloader": "git",
    }


def _extract_redirect_path(command: str) -> Optional[str]:
    """If the command ends with a `> PATH` redirect, return PATH.

    Conservative: only considers a single `>` (not `>>`, `2>`, `&>`)
    followed by a single token. Returns None for anything else.
    """
    # Strip trailing whitespace / semicolons.
    stripped = command.rstrip().rstrip(";").rstrip()
    # Match "  > path" at end. Reject ">>" by requiring no preceding ">".
    m = re.search(r"(?<![>&\d])>\s*([^\s>&|]+)\s*$", stripped)
    if m:
        return m.group(1)
    return None


def _extract_download(command: str) -> Optional[dict]:
    """Top-level download extractor (ADR 0002 §D4).

    Returns a dict with keys ``source_url``, ``output_path``, ``downloader``
    when ``command`` is recognized as a curl / wget / git clone download.
    Returns None for non-download commands or when extraction is ambiguous.
    """
    if not command or not command.strip():
        return None

    # Only inspect the first command in a pipeline / sequence: we look at
    # the leading subexpression up to the first unquoted `|`, `&&`, `;`.
    # For robustness against malformed input, fall back to the raw command
    # if shlex fails.
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None

    leader = tokens[0].lower()

    # Strip a possible trailing pipeline. We only want the first segment's
    # tokens — anything past `|` belongs to a downstream tool (e.g. `… | sh`).
    try:
        pipe_idx = tokens.index("|")
        first_tokens = tokens[:pipe_idx]
    except ValueError:
        first_tokens = tokens

    if not first_tokens:
        return None
    leader = first_tokens[0].lower()

    if leader == "curl":
        result = _extract_curl_download(first_tokens)
        if result is not None and result["output_path"] is None:
            # Try shell redirect on the original command.
            redirect = _extract_redirect_path(command)
            if redirect:
                result["output_path"] = redirect
            else:
                return None
        if result is None:
            # No -o / -O / --output. Try shell redirect: `curl URL > file`.
            redirect = _extract_redirect_path(command)
            if redirect:
                url = _extract_url(first_tokens)
                if url:
                    return {
                        "source_url": url,
                        "output_path": redirect,
                        "downloader": "curl",
                    }
        return result

    if leader == "wget":
        return _extract_wget_download(first_tokens)

    if leader == "git":
        return _extract_git_clone_download(first_tokens)

    return None


def _evaluate_download_risk(
    download: dict,
    host_ctx: "HostContext",
    *,
    is_path_sensitive: bool,
) -> tuple[float, str, bool]:
    """Score a download and produce its trust label + high_risk flag.

    Returns ``(risk_score, trust_label, high_risk)`` per ADR 0002 §D5:
        - sensitive output_path                   → 0.9 (critical)
        - host BLOCKED                            → 0.5 (warning)
        - host UNKNOWN (not KNOWN, not LEARNED)   → 0.5 (warning)
        - host KNOWN / LEARNED                    → 0.2 (info)
        - sensitive AND BLOCKED                   → 0.9 (critical)

    ``high_risk`` mirrors warning-or-above (>= 0.5). Trust is computed
    against the URL host.
    """
    from sentinel_mac.collectors.context import TrustLevel

    url = download.get("source_url", "")
    host = ""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except (ValueError, TypeError):
        host = ""

    trust: "TrustLevel"
    if host:
        host_ctx.observe(host)
        trust = host_ctx.classify(host)
    else:
        trust = TrustLevel.UNKNOWN
    trust_label = trust.value

    if is_path_sensitive:
        # Sensitive-path always trumps host trust (ADR 0002 §D5).
        return 0.9, trust_label, True

    if trust == TrustLevel.BLOCKED:
        return 0.5, trust_label, True
    if trust in (TrustLevel.KNOWN, TrustLevel.LEARNED):
        return 0.2, trust_label, False
    # UNKNOWN
    return 0.5, trust_label, True


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
        project_ctx: Optional[ProjectContext] = None,
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

        # ADR 0007 D4 — project context. Optional injection so existing
        # callers/tests keep working; when None, project_meta enrichment
        # is omitted (set to None on every emitted detail dict).
        self._project_ctx: Optional[ProjectContext] = project_ctx

        # ADR 0007 D1 — per-file session metadata cache. Populated lazily
        # on the first user/assistant record we see in each JSONL file.
        # Key: absolute JSONL path. Value: SessionMeta (mutated in place).
        self._session_meta: dict[str, SessionMeta] = {}

        # ADR 0007 D1 — track which file we're currently processing so the
        # per-record handlers can build session/project context without
        # threading the path through every internal call signature.
        self._current_file: Optional[str] = None

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

        # ADR 0002 — download tracking (opt-in). When disabled, download
        # extraction is skipped entirely so the curl/wget regex work is
        # not paid on every Bash command.
        download_cfg = (
            config.get("security", {}).get("download_tracking", {}) or {}
        )
        self._download_enabled = bool(download_cfg.get("enabled", False))

        # Track file positions for tail-f style reading
        # Key: file path, Value: last read position
        self._file_positions: dict[str, int] = {}

        # Track which log files we've already warned about
        self._warned_paths: set[str] = set()

        # v0.9 Track 3b — most-recent user/assistant message timestamp
        # (epoch seconds). Surfaced via
        # last_user_or_assistant_activity_epoch() so the AlertEngine can
        # consult it before firing the stuck_process heuristic
        # (PR #28 follow-up — false-positive on active interactive
        # sessions with high CPU + low network). None until the first
        # user/assistant record is parsed in this process. Updated
        # under a small lock so a metric-collection thread can read it
        # while the parser thread is mid-update without tearing.
        self._last_message_ts: Optional[float] = None
        self._last_message_lock = threading.Lock()

    def last_user_or_assistant_activity_epoch(self) -> Optional[float]:
        """Most recent user/assistant message timestamp (epoch seconds), or None.

        Updated whenever a JSONL record with ``type`` in
        ``{"user", "assistant"}`` is processed. Housekeeping records
        (queue-operation / last-prompt / summary / permission-mode /
        file-history-snapshot) and tool_result records do NOT advance
        this value — only "real" user/assistant turns count as activity.

        Thread-safe: the parser thread writes under
        ``_last_message_lock``; readers (e.g. the AlertEngine via the
        callback wired in core.Sentinel.__init__) take the same lock
        for the read.

        Used by AlertEngine.evaluate to skip the stuck_process alert
        when there has been recent agent activity (see engine.py /
        v0.9 Track 3b — PR #28 follow-up).
        """
        with self._last_message_lock:
            return self._last_message_ts

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

            # ADR 0007 D1 — set the current file so per-record handlers
            # can pull (and mutate) the right SessionMeta from the cache.
            previous_file = self._current_file
            self._current_file = file_path
            try:
                for line in new_data.strip().splitlines():
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        self._process_claude_code_entry(entry)
                    except json.JSONDecodeError:
                        continue
            finally:
                self._current_file = previous_file

        except OSError as e:
            logger.debug(f"AgentLogParser: cannot read {file_path}: {e}")

    def _process_claude_code_entry(self, entry: dict):
        """Process a single Claude Code JSONL entry."""
        entry_type = entry.get("type", "")

        # ADR 0007 D1 — capture session metadata on the first user /
        # assistant record (housekeeping records like queue-operation /
        # last-prompt / summary / permission-mode / file-history-snapshot
        # don't carry cwd/gitBranch/version/model). Defensive — never
        # raise on missing keys.
        self._update_session_meta(entry, entry_type)

        # v0.9 Track 3b — track most-recent user/assistant activity
        # so the AlertEngine can skip false-positive stuck_process
        # alerts on active interactive sessions. Housekeeping types
        # and tool_result records do NOT count as activity here (a
        # tool_result is a system-emitted echo of a tool run, not a
        # fresh user turn or model thought).
        if entry_type in ("user", "assistant"):
            self._note_activity(entry)

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
                self._handle_mcp_tool_call(
                    tool_name, tool_input, timestamp, entry,
                )

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
            # DEFECT FIX (v0.8 Track 2b, mirrors PR #18): set risk_score
            # on the collector side so the persisted JSONL audit row
            # carries the same severity as the user-visible Alert. The
            # engine still applies the same mapping idempotently (see
            # engine._evaluate_agent_log_event WebFetch branch).
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
                risk_score=0.3,
            ))

        # ADR 0007 D2+D3 — enrich every emitted detail with session +
        # project_meta before queueing. Per-message cwd from this entry
        # overrides the cached session-start cwd (D1 step 4).
        per_message_cwd = self._entry_cwd(entry)
        for event in events:
            self._enrich_detail(event.detail, per_message_cwd=per_message_cwd)
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

            # DEFECT FIX (v0.8 Track 2b, mirrors PR #18): default to the
            # high-risk score (engine maps to "critical"). Trust downgrade
            # below may lower this for SSH/SCP + KNOWN/LEARNED hosts so
            # the persisted JSONL severity matches the downgraded Alert.
            risk_score = 0.9

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
                        # Trust-downgraded SSH/SCP: engine never assigns
                        # 0.9 in this branch (the high_risk gate is
                        # False), so the alert is suppressed entirely
                        # for built-in rules. Persist a small info-level
                        # score so the audit row is not "critical" and
                        # --report --severity critical does not
                        # surface a downgraded ssh.
                        risk_score = 0.2

            events.append(SecurityEvent(
                timestamp=timestamp,
                source="agent_log",
                actor_pid=0,
                actor_name="claude_code",
                event_type="agent_command",
                target=command[:200],  # Truncate for readability
                detail=detail,
                risk_score=risk_score,
            ))
            break  # One match is enough

        # ADR 0002 §D1: in addition to (not in place of) any agent_command
        # event, emit an agent_download event when the command is a
        # recognized download invocation. Two events for one command is
        # intentional — they have distinct semantics.
        if self._download_enabled:
            download_event = self._maybe_emit_download(command, timestamp)
            if download_event is not None:
                events.append(download_event)

        return events

    def _maybe_emit_download(
        self, command: str, timestamp: datetime
    ) -> Optional[SecurityEvent]:
        """Build an ``agent_download`` SecurityEvent if ``command`` is a
        recognized download (curl / wget / git clone). Returns None when
        not a download or when extraction was inconclusive.
        """
        download = _extract_download(command)
        if download is None:
            return None

        output_path = download.get("output_path")
        is_path_sensitive = bool(
            output_path and _is_sensitive_path(output_path)
        )
        risk_score, trust_label, high_risk = _evaluate_download_risk(
            download, self._host_ctx, is_path_sensitive=is_path_sensitive,
        )

        # ADR 0002 §D2 — frozen detail key set (additive only).
        detail: dict = {
            "source_url": download["source_url"],
            "output_path": output_path,
            "downloader": download["downloader"],
            "command": command[:500],
            "high_risk": high_risk,
            "trust_level": trust_label,
            "joined_fs_event": None,
        }

        return SecurityEvent(
            timestamp=timestamp,
            source="agent_log",
            actor_pid=0,
            actor_name="claude_code",
            event_type="agent_download",
            target=download["source_url"],
            detail=detail,
            risk_score=risk_score,
        )

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

            # DEFECT FIX (v0.8): set risk_score on the collector side so
            # the value persisted to the JSONL audit log matches the
            # severity of the user-visible Alert. Previously the engine
            # mutated risk_score in _evaluate_agent_log_event AFTER the
            # event was already written to disk, so the audit log stored
            # the dataclass default (0 → "info") while the desktop alert
            # showed "critical". `sentinel --report --severity critical`
            # therefore could not surface these events.
            #
            # The engine still applies the same mapping idempotently for
            # backward compatibility (see engine._evaluate_agent_log_event).
            risk_score = 0.9 if result["confidence"] == "high" else 0.6
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
                risk_score=risk_score,
            ))

        return events

    def _check_file_write(self, file_path: str, tool_name: str,
                          timestamp: datetime) -> list[SecurityEvent]:
        """Check if a file write/edit targets a sensitive location."""
        if not _is_sensitive_path(file_path):
            return []
        # DEFECT FIX (v0.8 Track 2b, mirrors PR #18): collector pre-sets
        # risk_score so the JSONL audit row carries the same severity as
        # the user-visible Alert. Engine still re-asserts the same value
        # idempotently for callers that bypass the collector.
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
            risk_score=0.8,
        )]

    def _check_file_read(self, file_path: str,
                         timestamp: datetime) -> list[SecurityEvent]:
        """Check if a file read targets a sensitive location."""
        if not _is_sensitive_path(file_path):
            return []
        # DEFECT FIX (v0.8 Track 2b, mirrors PR #18): same as
        # _check_file_write — read of a sensitive file is a high-risk
        # agent_tool_use and must persist with risk_score=0.8 so the
        # audit log severity matches the warning-level Alert.
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
            risk_score=0.8,
        )]

    def _handle_mcp_tool_call(self, tool_name: str, tool_input: dict,
                              timestamp: datetime,
                              entry: Optional[dict] = None):
        """Log MCP tool calls as informational events."""
        # Parse mcp__serverName__toolName
        parts = tool_name.split("__")
        server_name = parts[1] if len(parts) >= 3 else "unknown"
        method_name = parts[2] if len(parts) >= 3 else tool_name

        # DEFECT FIX (v0.8 Track 2b, mirrors PR #18): MCP tool calls are
        # info-level (engine maps to 0.2). Setting it on the collector
        # side keeps the JSONL audit row in lockstep with the Alert
        # level so --report --severity info correctly buckets them.
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
            risk_score=0.2,
        )
        # ADR 0007 D2+D3 — enrich with session + project_meta.
        per_message_cwd = self._entry_cwd(entry) if entry else None
        self._enrich_detail(event.detail, per_message_cwd=per_message_cwd)
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            logger.warning("AgentLogParser: event queue full, dropping MCP event")

    # ── ADR 0007 D1+D2+D3 enrichment helpers ─────────────────────────

    def _update_session_meta(self, entry: dict, entry_type: str) -> None:
        """ADR 0007 D1 — populate per-file SessionMeta from a JSONL record.

        Skips housekeeping records that don't carry the metadata we need.
        Defensive reads via ``dict.get`` — a future Claude Code release
        renaming any of these fields leaves the corresponding session.*
        sub-field None and the daemon keeps running.
        """
        if entry_type in _SESSION_HOUSEKEEPING_TYPES:
            return
        # We accept user/assistant/system/attachment as metadata sources
        # because they all carry sessionId/cwd/gitBranch/version on the
        # observed Claude Code 2.1.x JSONL shape. Only assistant carries
        # the model field on `message.model`.
        file_path = self._current_file
        if not file_path:
            return

        meta = self._session_meta.get(file_path)
        if meta is None:
            meta = SessionMeta()
            self._session_meta[file_path] = meta

        # First-write-wins for stable fields (sessionId/cwd/gitBranch/version
        # are session-wide). cwd is intentionally first-write-wins here
        # because per-message cwd is re-derived at emit time from the
        # triggering record (ADR 0007 D1 step 4).
        if meta.id is None:
            sid = entry.get("sessionId")
            if isinstance(sid, str) and sid:
                meta.id = sid
        if meta.cwd is None:
            cwd = entry.get("cwd")
            if isinstance(cwd, str) and cwd:
                meta.cwd = cwd
        if meta.version is None:
            ver = entry.get("version")
            if isinstance(ver, str) and ver:
                meta.version = ver
        if meta.git_branch is None:
            gb = entry.get("gitBranch")
            if isinstance(gb, str) and gb:
                meta.git_branch = gb
        if meta.model is None and entry_type == "assistant":
            message = entry.get("message")
            if isinstance(message, dict):
                model = message.get("model")
                if isinstance(model, str) and model:
                    meta.model = model

    def _note_activity(self, entry: dict) -> None:
        """v0.9 Track 3b — advance ``_last_message_ts`` from a user/assistant record.

        Prefers the record's own ISO ``timestamp`` field (so replayed
        history lines don't pretend to be "now"); falls back to
        ``time.time()`` when parsing fails. Either way the value is
        monotonically advancing in practice — Claude Code writes
        records in chronological order, and ``time.time()`` only ever
        moves forward at the second granularity used here.
        """
        ts_raw = entry.get("timestamp")
        epoch: Optional[float] = None
        if isinstance(ts_raw, str) and ts_raw:
            try:
                # Claude Code uses RFC3339 with trailing "Z"; fromisoformat
                # in Py3.11+ handles "Z" but Py3.9/3.10 do not. Normalize.
                normalized = ts_raw.replace("Z", "+00:00")
                epoch = datetime.fromisoformat(normalized).timestamp()
            except (ValueError, TypeError):
                epoch = None
        if epoch is None:
            epoch = time.time()

        with self._last_message_lock:
            # Defensive: never let a stale/replayed record move the
            # cursor backwards. The stuck_process check cares about
            # "most recent activity", so monotonic-on-write is the
            # contract that matches the consumer's mental model.
            if self._last_message_ts is None or epoch > self._last_message_ts:
                self._last_message_ts = epoch

    def _current_session_meta(self) -> Optional[SessionMeta]:
        """Return the SessionMeta for the file currently being tailed
        (or None when called outside a tail loop, e.g., direct
        ``parse_line`` invocation in tests)."""
        if not self._current_file:
            return None
        return self._session_meta.get(self._current_file)

    def _enrich_detail(
        self, detail: dict, *, per_message_cwd: Optional[str] = None
    ) -> dict:
        """ADR 0007 D2+D3 — overlay session + project_meta on a detail dict.

        Mutates ``detail`` in place and also returns it for call-site
        ergonomics. Always sets both keys; either or both may be None
        (event types without enrichment context).

        ``per_message_cwd`` defaults to the cached session-start cwd
        (D1 step 4 — the per-record cwd should be passed by the caller
        when known so ``cd`` mid-session is reflected).
        """
        meta = self._current_session_meta()
        effective_cwd = per_message_cwd or (meta.cwd if meta else None)

        detail["session"] = _build_session_detail(meta, effective_cwd)

        if self._project_ctx is None:
            detail["project_meta"] = None
        else:
            branch_hint = meta.git_branch if meta else None
            detail["project_meta"] = self._project_ctx.lookup(
                effective_cwd, branch_hint=branch_hint,
            )
        return detail

    @staticmethod
    def _entry_cwd(entry: dict) -> Optional[str]:
        """Defensively pull the per-message cwd from a JSONL record."""
        cwd = entry.get("cwd") if isinstance(entry, dict) else None
        return cwd if isinstance(cwd, str) and cwd else None

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
                # DEFECT FIX (v0.8 Track 2b, mirrors PR #18): MCP
                # injection is the highest-severity agent_log event
                # type (engine maps to 0.95 → critical). Persist the
                # score on the collector side so the JSONL audit row
                # is correctly classified for --report --severity
                # critical.
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
                    risk_score=0.95,
                )
                # ADR 0007 D2+D3 — enrich with session + project_meta.
                per_message_cwd = self._entry_cwd(entry)
                self._enrich_detail(
                    event.detail, per_message_cwd=per_message_cwd,
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
