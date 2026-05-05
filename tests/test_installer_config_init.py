"""Tests for sentinel_mac.installer.config_init module (ADR 0011 Track A).

Covers:
* Template path resolution (package lookup)
* Config creation from template
* Idempotency (existing config preservation)
* Force overwrite
"""

from pathlib import Path

from sentinel_mac.installer.config_init import ensure_config, template_path


class TestTemplatePath:
    """Test template_path() helper."""

    def test_template_path_exists(self) -> None:
        """Template path should point to an existing file."""
        template = template_path()
        assert template.exists(), f"Template not found at {template}"

    def test_template_path_is_config_example(self) -> None:
        """Template should be named config.example.yaml."""
        template = template_path()
        assert template.name == "config.example.yaml"

    def test_template_contains_yaml_content(self) -> None:
        """Template should contain YAML content."""
        template = template_path()
        content = template.read_text()
        # Check for basic YAML structure
        assert ":" in content  # YAML key:value
        assert len(content) > 0


class TestEnsureConfig:
    """Test ensure_config() idempotent function."""

    def test_creates_config_if_missing(self, tmp_path: Path) -> None:
        """Should create config from template if missing."""
        config = tmp_path / "config.yaml"
        assert not config.exists()

        result = ensure_config(config)

        assert result is True
        assert config.exists()

    def test_created_config_contains_content(self, tmp_path: Path) -> None:
        """Created config should have content from template."""
        config = tmp_path / "config.yaml"
        ensure_config(config)

        content = config.read_text()
        assert len(content) > 0
        assert ":" in content

    def test_preserves_existing_config_by_default(self, tmp_path: Path) -> None:
        """Should not overwrite existing config unless force=True."""
        config = tmp_path / "config.yaml"
        original_content = "my custom config"
        config.write_text(original_content)

        result = ensure_config(config, force=False)

        assert result is False
        assert config.read_text() == original_content

    def test_force_overwrites_config(self, tmp_path: Path) -> None:
        """With force=True, should overwrite existing config."""
        config = tmp_path / "config.yaml"
        original_content = "my custom config"
        config.write_text(original_content)

        result = ensure_config(config, force=True)

        assert result is True
        new_content = config.read_text()
        assert new_content != original_content
        assert ":" in new_content

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """Should create parent directories if missing."""
        config = tmp_path / "a" / "b" / "c" / "config.yaml"
        ensure_config(config)

        assert config.exists()
        assert config.parent == tmp_path / "a" / "b" / "c"

    def test_sets_correct_permissions(self, tmp_path: Path) -> None:
        """Created config should have 0o600 permissions."""
        config = tmp_path / "config.yaml"
        ensure_config(config)

        stat_info = config.stat()
        mode = stat_info.st_mode & 0o777
        assert mode == 0o600

    def test_multiple_calls_idempotent(self, tmp_path: Path) -> None:
        """Multiple calls should be idempotent (no re-creation)."""
        config = tmp_path / "config.yaml"

        ensure_config(config)
        first_content = config.read_text()
        first_mtime = config.stat().st_mtime

        # Wait a tiny bit
        import time
        time.sleep(0.01)

        # Call again
        ensure_config(config)
        second_content = config.read_text()
        second_mtime = config.stat().st_mtime

        assert first_content == second_content
        assert first_mtime == second_mtime
