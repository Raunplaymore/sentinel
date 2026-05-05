"""LaunchAgent plist generation and management (ADR 0011 §D2 step 4).

Provides pure functions for generating plist XML and utilities for
detecting existing install methods from plist files.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


def plist_path() -> Path:
    """Return the standard LaunchAgent plist path.

    Returns:
        ~/Library/LaunchAgents/com.sentinel.agent.plist
    """
    from sentinel_mac.core import PLIST_NAME
    return Path.home() / "Library" / "LaunchAgents" / f"{PLIST_NAME}.plist"


def generate_plist(binary_path: Path, data_dir: Path) -> str:
    """Generate LaunchAgent plist XML content (ADR 0011 §D2 step 4).

    Pure function — returns XML string without writing to disk.

    Args:
        binary_path: Absolute path to the sentinel binary.
        data_dir: Absolute path to the data directory for logs.

    Returns:
        XML string with DOCTYPE and complete plist.
    """
    from sentinel_mac.core import PLIST_NAME

    # Build the plist dict structure
    plist_dict = {
        "Label": PLIST_NAME,
        "ProgramArguments": [str(binary_path)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(data_dir / "stdout.log"),
        "StandardErrorPath": str(data_dir / "stderr.log"),
    }

    # Create XML structure
    root = ET.Element("plist")
    root.set("version", "1.0")

    dict_elem = ET.SubElement(root, "dict")

    for key, value in plist_dict.items():
        key_elem = ET.SubElement(dict_elem, "key")
        key_elem.text = key

        if isinstance(value, str):
            string_elem = ET.SubElement(dict_elem, "string")
            string_elem.text = value
        elif isinstance(value, bool):
            bool_tag = "true" if value else "false"
            ET.SubElement(dict_elem, bool_tag)
        elif isinstance(value, list):
            array_elem = ET.SubElement(dict_elem, "array")
            for item in value:
                string_elem = ET.SubElement(array_elem, "string")
                string_elem.text = item

    # Convert to string with proper DOCTYPE
    xml_str = ET.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n{xml_str}\n'


def write_plist(content: str, path: Path) -> None:
    """Write plist XML to disk with 0o644 permissions.

    Args:
        content: XML string from generate_plist().
        path: Target path (typically ~/Library/LaunchAgents/...).

    Raises:
        IOError: If write fails.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o644)


def existing_plist_install_method(path: Path) -> Optional[str]:
    """Parse an existing plist to detect its install method.

    Used by ADR 0011 §D5 conflict detection.

    Args:
        path: Path to the plist file. If missing, returns None.

    Returns:
        One of: 'pipx', 'pip-venv', 'editable', 'unknown', or None (no plist).
    """
    if not path.exists():
        return None

    try:
        tree = ET.parse(path)
        root = tree.getroot()

        # Navigate to ProgramArguments array
        dict_elem = root.find("dict")
        if dict_elem is None:
            return "unknown"

        # Find ProgramArguments key
        keys = [elem.text for elem in dict_elem.findall("key")]
        try:
            keys.index("ProgramArguments")
        except ValueError:
            return "unknown"

        # Get the corresponding array element
        # XML structure: key, string, key, string, ... key, array, ...
        # We need to find the position of the array after ProgramArguments key
        elements = list(dict_elem)
        prog_args_key_pos = None
        for i, elem in enumerate(elements):
            if elem.tag == "key" and elem.text == "ProgramArguments":
                prog_args_key_pos = i
                break

        if prog_args_key_pos is None:
            return "unknown"

        # Array should be right after the key
        if prog_args_key_pos + 1 < len(elements):
            array_elem = elements[prog_args_key_pos + 1]
            if array_elem.tag == "array":
                strings = array_elem.findall("string")
                if strings:
                    binary_path = strings[0].text
                    if binary_path:
                        # Detect by path patterns
                        if "/.venv/" in binary_path or "/venv/" in binary_path:
                            return "pip-venv"
                        if "/.local/pipx/venvs/" in binary_path:
                            return "pipx"
                        if "/.editable/" in binary_path or "__editable__" in binary_path:
                            return "editable"
                        return "unknown"

        return "unknown"
    except Exception:
        return "unknown"
