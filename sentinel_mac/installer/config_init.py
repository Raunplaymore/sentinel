"""Config initialization for sentinel install (ADR 0011 §D2 step 2).

Provides idempotent config creation from template.
"""

from pathlib import Path


def template_path() -> Path:
    """Locate config.example.yaml inside the sentinel_mac package.

    Tries multiple paths to find the template: package directory, then
    source tree fallback.

    Returns:
        Path to config.example.yaml within the sentinel_mac package.

    Raises:
        FileNotFoundError: If template cannot be found.
    """
    # First try: direct path in package directory (works for both installed and editable)
    try:
        import sentinel_mac
        sentinel_path = Path(sentinel_mac.__file__).parent
        template = sentinel_path / "config.example.yaml"
        if template.exists():
            return template
    except Exception:
        pass

    # Fallback: source tree (for development)
    try:
        # Walk up to find the repo root
        current = Path(__file__).parent
        for _ in range(5):  # Try up to 5 levels
            candidate = current / "config.example.yaml"
            if candidate.exists():
                return candidate
            current = current.parent
    except Exception:
        pass

    raise FileNotFoundError(
        "config.example.yaml not found in sentinel_mac package or source tree. "
        "Ensure the package is properly installed."
    )


def ensure_config(config_path: Path, *, force: bool = False) -> bool:
    """Create config from template if missing (ADR 0011 §D2 step 2).

    Idempotent: does not overwrite existing config unless force=True.

    Args:
        config_path: Target path for config.yaml (typically ~/.config/sentinel/config.yaml).
        force: If True, overwrite existing config with fresh template.

    Returns:
        True if config was newly created or force-overwritten; False if already existed (and force=False).

    Raises:
        IOError: If template cannot be read or config cannot be written.
    """
    if config_path.exists() and not force:
        return False

    # Read template
    try:
        template = template_path()
        template_content = template.read_text()
    except FileNotFoundError as e:
        # Fallback: try to locate in the source tree (for development)
        fallback = Path(__file__).parent.parent.parent / "config.example.yaml"
        if fallback.exists():
            template_content = fallback.read_text()
        else:
            raise FileNotFoundError(
                "config.example.yaml not found in package or source tree"
            ) from e

    # Write config
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(template_content)
    config_path.chmod(0o600)
    return True
