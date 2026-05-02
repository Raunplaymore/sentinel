"""Unit tests for sentinel_mac.collectors.typosquatting.

Focus areas (v0.8 defect fix):
- ``extract_pip_packages`` / ``extract_npm_packages`` no longer trip on
  package-shaped tokens that live inside quoted strings.
- ``check_typosquatting`` confidence levels remain stable so the
  collector-side risk_score mapping (0.9 high / 0.6 medium) stays
  correct.
"""

import pytest

from sentinel_mac.collectors.typosquatting import (
    _is_valid_npm_name,
    _is_valid_pip_name,
    _split_subcommands,
    check_typosquatting,
    extract_npm_packages,
    extract_pip_packages,
)


class TestSplitSubcommands:
    """The shlex-aware splitter is the foundation of the false-positive fix."""

    def test_simple_command(self):
        assert _split_subcommands("pip install foo") == [["pip", "install", "foo"]]

    def test_compound_with_and(self):
        assert _split_subcommands("pip install foo && pip install bar") == [
            ["pip", "install", "foo"],
            ["pip", "install", "bar"],
        ]

    def test_compound_with_or(self):
        assert _split_subcommands("pip install foo || true") == [
            ["pip", "install", "foo"],
            ["true"],
        ]

    def test_compound_with_semicolon(self):
        assert _split_subcommands("a ; b") == [["a"], ["b"]]

    def test_quoted_separator_not_split(self):
        # The literal `&&` lives inside quotes — must not split.
        assert _split_subcommands('echo "foo && bar"') == [
            ["echo", "foo && bar"],
        ]

    def test_quoted_pip_install_kept_intact_as_arg(self):
        # The git case from the user's bug report.
        result = _split_subcommands('git commit -m "feat: pip install foo"')
        assert result == [["git", "commit", "-m", "feat: pip install foo"]]

    def test_unclosed_quote_returns_empty(self):
        assert _split_subcommands('unclosed "quote pip install foo') == []

    def test_empty_command(self):
        assert _split_subcommands("") == []

    # ── Operator-without-whitespace regression (post-review fix) ──
    # bash treats `cmd1&&cmd2` identically to `cmd1 && cmd2`. The first
    # patch pass used `shlex.split`, which glued `&&` to a neighboring
    # token (`foo&&pip` → single token) and missed the second
    # subcommand. Switching to `shlex.shlex(punctuation_chars=True)`
    # plus a redirect-aware loop fixed it. These tests pin the
    # behavior so a future contributor cannot regress to the gluing
    # variant.

    def test_compound_no_space_and(self):
        assert _split_subcommands("pip install foo&&pip install bar") == [
            ["pip", "install", "foo"],
            ["pip", "install", "bar"],
        ]

    def test_compound_no_space_or(self):
        assert _split_subcommands("pip install foo||true") == [
            ["pip", "install", "foo"],
            ["true"],
        ]

    def test_compound_no_space_semicolon(self):
        assert _split_subcommands("pip install foo;rm -rf /") == [
            ["pip", "install", "foo"],
            ["rm", "-rf", "/"],
        ]

    def test_redirect_target_dropped(self):
        # `out.txt` is the redirect target, NOT a package name.
        assert _split_subcommands("pip install foo > out.txt") == [
            ["pip", "install", "foo"],
        ]

    def test_redirect_no_space_dropped(self):
        # No-space redirect — same handling.
        assert _split_subcommands("pip install foo>out.txt") == [
            ["pip", "install", "foo"],
        ]

    def test_pipe_target_dropped(self):
        # `tee log` is the pipe sink, not packages.
        assert _split_subcommands("pip install foo | tee log") == [
            ["pip", "install", "foo"],
        ]


class TestIsValidPipName:
    @pytest.mark.parametrize("name", ["foo", "Foo", "foo-bar", "foo_bar", "foo.bar", "f", "f1", "MyPkg", "a" * 200])
    def test_valid(self, name):
        assert _is_valid_pip_name(name) is True

    @pytest.mark.parametrize("name", ["", "2", "123", "(mypy", "foo!", "MCP,", "-foo", ".foo", "_foo"])
    def test_invalid(self, name):
        assert _is_valid_pip_name(name) is False

    def test_too_long(self):
        # 215 chars > 214 cap
        assert _is_valid_pip_name("a" + "b" * 214) is False


class TestIsValidNpmName:
    @pytest.mark.parametrize("name", ["foo", "foo-bar", "foo.bar", "foo_bar", "@scope/pkg", "@a/b", "react", "lodash"])
    def test_valid(self, name):
        assert _is_valid_npm_name(name) is True

    @pytest.mark.parametrize("name", ["", "Foo", "FOO", "MyPkg", "2", "999", "-foo", "(mypy", "@/pkg"])
    def test_invalid(self, name):
        # npm forbids uppercase since 2017 + obvious noise
        assert _is_valid_npm_name(name) is False


class TestExtractPipPackages:
    """Spec — see extract_pip_packages docstring."""

    # ── Real installs ──

    def test_basic_install(self):
        assert extract_pip_packages("pip install requests") == ["requests"]

    def test_pip3(self):
        assert extract_pip_packages("pip3 install foo bar") == ["foo", "bar"]

    def test_python_dash_m_pip(self):
        assert extract_pip_packages("python -m pip install xxx") == ["xxx"]

    def test_python3_dash_m_pip_with_flag(self):
        # --upgrade is a flag → skip; foo is the real package.
        assert extract_pip_packages(
            "python3 -m pip install --upgrade foo"
        ) == ["foo"]

    def test_version_specifier_stripped(self):
        assert extract_pip_packages("pip install foo>=1.0") == ["foo"]

    def test_extras_stripped(self):
        assert extract_pip_packages("pip install foo[bar]") == ["foo"]

    def test_uppercase_pip_name_allowed(self):
        # PEP 503 permits uppercase in the source name.
        assert extract_pip_packages("pip install MyPkg") == ["MyPkg"]

    def test_compound_install(self):
        assert extract_pip_packages(
            "pip install foo && pip install bar"
        ) == ["foo", "bar"]

    def test_compound_install_no_whitespace(self):
        # Post-review fix: was missing the second package because shlex
        # glued `&&` to a neighboring token.
        assert extract_pip_packages(
            "pip install foo&&pip install bar"
        ) == ["foo", "bar"]

    def test_redirect_target_not_extracted(self):
        # Post-review fix: was wrongly extracting `out.txt` as a package.
        assert extract_pip_packages(
            "pip install requets > out.txt"
        ) == ["requets"]

    def test_pipe_target_not_extracted(self):
        assert extract_pip_packages(
            "pip install requets | tee install.log"
        ) == ["requets"]

    def test_typosquat_followed_by_destructive_no_space(self):
        # The exact attack pattern the splitter must NOT swallow:
        # typosquat + destructive command with no whitespace.
        assert extract_pip_packages(
            "pip install requets;rm -rf /"
        ) == ["requets"]

    def test_known_typosquat_extracted(self):
        # Regression: the canonical typosquat case must still flow through.
        assert extract_pip_packages("pip install requets") == ["requets"]

    def test_requirements_flag_skipped(self):
        # `-r requirements.txt` — `-r` is a flag (skipped); the path that
        # follows is preserved as a token but is not a package name we
        # care to typo-check (it has a `.`, but the typosquatting matcher
        # will not match it against any popular package).
        assert extract_pip_packages(
            "pip install -r requirements.txt"
        ) == ["requirements.txt"]

    # ── False-positive cases (the 24h burst) ──

    def test_quoted_in_git_commit_message_no_match(self):
        assert extract_pip_packages(
            'git commit -m "feat: pip install foo"'
        ) == []

    def test_quoted_in_gh_pr_body_no_match(self):
        assert extract_pip_packages(
            'gh pr create --body "use pip install foo"'
        ) == []

    def test_echo_quoted_no_match(self):
        assert extract_pip_packages('echo "pip install foo"') == []

    def test_install_with_no_following_package_no_match(self):
        assert extract_pip_packages("pip install && other") == []

    def test_unclosed_quote_returns_empty(self):
        assert extract_pip_packages('unclosed "quote pip install foo') == []

    def test_pure_digit_token_rejected(self):
        assert extract_pip_packages("pip install 2") == []

    def test_invalid_paren_token_rejected(self):
        # `pip install (mypy` is malformed shell. With punctuation-aware
        # shlex, `(` is split off as its own punctuation token and
        # `mypy` is what remains — and `mypy` IS a real package name.
        # The original false-positive risk this test was guarding (e.g.,
        # `(mypy` appearing inside a commit message body) is now blocked
        # by quote awareness; see test_real_user_case_24h_burst.
        assert extract_pip_packages("pip install (mypy") == ["mypy"]

    def test_real_user_case_24h_burst(self):
        """Verbatim-style cases from the 24h false-positive incident.

        The user observed alerts on tokens like 'block', 'up', '2',
        'MCP,', 'Python', '(mypy' that appeared inside long commit
        messages or PR bodies. None of these are real installs.
        """
        cases = [
            'git commit -m "feat: add block list and bump up version 2 with MCP, Python (mypy + ruff)"',
            'gh pr create --title "fix" --body "Resolves an issue where pip install foo would be miscounted."',
            'echo "checking pip install requets noise"',
        ]
        for cmd in cases:
            assert extract_pip_packages(cmd) == [], (
                f"False-positive regression on: {cmd}"
            )


class TestExtractNpmPackages:

    # ── Real installs ──

    def test_basic_install(self):
        assert extract_npm_packages("npm install foo") == ["foo"]

    def test_npm_i_shorthand(self):
        assert extract_npm_packages("npm i foo bar") == ["foo", "bar"]

    def test_npm_add(self):
        assert extract_npm_packages("npm add @scope/pkg") == ["@scope/pkg"]

    def test_version_stripped(self):
        assert extract_npm_packages("npm install foo@1.0") == ["foo"]

    def test_compound_install(self):
        assert extract_npm_packages(
            "npm install foo && npm install bar"
        ) == ["foo", "bar"]

    def test_compound_install_no_whitespace(self):
        # Post-review fix: same operator-without-space defect as pip.
        assert extract_npm_packages(
            "npm install lodashs&&npm install requets"
        ) == ["lodashs", "requets"]

    def test_redirect_target_not_extracted(self):
        assert extract_npm_packages(
            "npm install lodashs > out.txt"
        ) == ["lodashs"]

    # ── False positives ──

    def test_quoted_in_git_commit_no_match(self):
        assert extract_npm_packages(
            'git commit -m "npm install evil"'
        ) == []

    def test_pure_digit_rejected(self):
        assert extract_npm_packages("npm install 2") == []

    def test_uppercase_rejected(self):
        # npm registry rejects uppercase since 2017.
        assert extract_npm_packages("npm install Foo") == []

    def test_unclosed_quote_returns_empty(self):
        assert extract_npm_packages('npm install "foo bar') == []


class TestCheckTyposquattingConfidenceMapping:
    """The risk_score that the collector now sets directly depends on the
    confidence label. Pin those mappings here so a future tuning of
    edit-distance thresholds cannot silently break audit-log severity.
    """

    def test_short_name_distance_one_is_high(self):
        # 'requets' vs 'requests' — distance 1, len 7.
        result = check_typosquatting("requets", "pip")
        assert result is not None
        assert result["confidence"] == "high"
        assert result["edit_distance"] == 1

    def test_exact_match_returns_none(self):
        assert check_typosquatting("requests", "pip") is None

    def test_unknown_package_returns_none(self):
        assert check_typosquatting("totally-novel-pkg-zzzzz", "pip") is None
