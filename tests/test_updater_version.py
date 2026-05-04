"""Tests for sentinel_mac.updater.version (ADR 0010 §D2)."""

from unittest.mock import Mock, patch

import pytest
import requests

from sentinel_mac.updater.version import (
	fetch_latest_pypi_version,
	get_running_version,
	is_update_available,
)


class TestGetRunningVersion:
	"""Test running version detection."""

	def test_returns_current_version(self) -> None:
		"""Should return the installed version of sentinel-mac."""
		version = get_running_version()
		# Should not raise, and should be a valid version string
		assert isinstance(version, str)
		assert len(version) > 0


class TestFetchLatestPypiVersion:
	"""Test PyPI version fetching."""

	def test_fetches_version_from_pypi(self) -> None:
		"""Should fetch the latest version from PyPI JSON API."""
		mock_response = Mock()
		mock_response.json.return_value = {
			"info": {
				"version": "0.10.0",
			}
		}

		with patch("requests.get", return_value=mock_response):
			version = fetch_latest_pypi_version()
			assert version == "0.10.0"

	def test_returns_none_on_timeout(self) -> None:
		"""Should return None on request timeout."""
		with patch("requests.get", side_effect=requests.exceptions.Timeout):
			version = fetch_latest_pypi_version()
			assert version is None

	def test_returns_none_on_connection_error(self) -> None:
		"""Should return None on connection error."""
		with patch("requests.get", side_effect=requests.exceptions.ConnectionError):
			version = fetch_latest_pypi_version()
			assert version is None

	def test_returns_none_on_http_error(self) -> None:
		"""Should return None on HTTP error (e.g., 404)."""
		with patch("requests.get", side_effect=requests.exceptions.HTTPError):
			version = fetch_latest_pypi_version()
			assert version is None

	def test_returns_none_on_invalid_json(self) -> None:
		"""Should return None if response JSON is invalid."""
		mock_response = Mock()
		mock_response.json.side_effect = ValueError("invalid json")

		with patch("requests.get", return_value=mock_response):
			version = fetch_latest_pypi_version()
			assert version is None

	def test_respects_timeout_parameter(self) -> None:
		"""Should pass timeout parameter to requests.get."""
		mock_response = Mock()
		mock_response.json.return_value = {"info": {"version": "0.10.0"}}

		with patch("requests.get", return_value=mock_response) as mock_get:
			fetch_latest_pypi_version(timeout=10.0)
			# Check that timeout was passed
			assert mock_get.call_args[1]["timeout"] == 10.0

	def test_includes_user_agent(self) -> None:
		"""Should set User-Agent header with version info."""
		mock_response = Mock()
		mock_response.json.return_value = {"info": {"version": "0.10.0"}}

		with patch("requests.get", return_value=mock_response) as mock_get:
			with patch("sentinel_mac.updater.version.get_running_version", return_value="0.9.0"):
				fetch_latest_pypi_version()
				# Check that User-Agent was set
				call_headers = mock_get.call_args[1]["headers"]
				assert "sentinel-mac/0.9.0 (update-check)" in call_headers["User-Agent"]


class TestIsUpdateAvailable:
	"""Test version comparison."""

	def test_newer_version_available(self) -> None:
		"""Should return True when latest > running."""
		assert is_update_available("0.9.0", "0.10.0") is True
		assert is_update_available("1.0.0a1", "1.0.0") is True
		assert is_update_available("0.9.9", "1.0.0") is True

	def test_no_update_available(self) -> None:
		"""Should return False when latest == running."""
		assert is_update_available("0.10.0", "0.10.0") is False

	def test_running_newer(self) -> None:
		"""Should return False when latest < running."""
		assert is_update_available("0.10.0", "0.9.0") is False
		assert is_update_available("1.0.0", "1.0.0a1") is False

	def test_handles_prerelease_versions(self) -> None:
		"""Should correctly handle pre-release version strings."""
		assert is_update_available("0.10.0a1", "0.10.0") is True
		assert is_update_available("0.10.0rc1", "0.10.0") is True
		assert is_update_available("0.10.0", "0.10.0rc1") is False

	def test_handles_unparseable_versions(self) -> None:
		"""Should return False if version strings cannot be parsed."""
		assert is_update_available("invalid", "0.10.0") is False
		assert is_update_available("0.10.0", "invalid") is False
		assert is_update_available("invalid", "also-invalid") is False
