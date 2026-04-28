"""
`tests/test_config.py`

Unit tests for `scanner/core/congif.py`. Verifies that `ScanConfig` correctly 
loads valid YAML files, raises `FileNOtFoundError` for missing files, and that 
`validate()` catches missing required fields before any scan begins.
"""
import os
import pytest

from scanner.core.config import ScanConfig

# Minimal valid YAML string representing the JS target, with one admin credential entry.
VALID_YAML = """\
target:
  base_url: "http://localhost:3000"
credentials:
  - username: "admin@juice-sh.op"
    password: "CHANGE_ME_ADMIN"
    role: "admin"
    auth_type: "bearer"
"""
# YAML string where `target` is present, but `base_url` is not, used to test `validate()` rejection.
MISSING_BASE_URL_YAML = """\
target:
  excluded_paths: []
credentials:
  - username: "admin@juice-sh.op"
    password: "CHANGE_ME_ADMIN"
    role: "admin"
    auth_type: "bearer"
"""
# YAML string with a valid `target.base_url`, but no `credentials` block, used to test `validate()` rejection.
MISSING_CREDENTIALS_YAML = """\
target:
  base_url: "http://localhost:3000"
"""


def _write_yaml(tmp_path, content, filename="config.yaml"):
    """ Writes `content` to a temporary file (`tmp_path`), and returns the absolute path."""

    # Creates the file in the pytest-managed temp directory, which is cleaned up automatically after each test.
    config_file = tmp_path / filename
    config_file.write_text(content)
    return str(config_file)


class TestScanConfigLoading:
    """ Tests that `ScanCOnfig` loads, and parses, valid YAML without any errors."""

    def test_loads_valid_yaml(self, tmp_path):
        """ Verifies that a valid YAML file loads without raising any exceptrions, and exposes the correct `target_url`."""

        # Writes `VALID_YAML` to a temporary file, and loads it via `ScanCOnfig`.
        path = _write_yaml(tmp_path, VALID_YAML)
        config = ScanConfig(path)
        # Confirms that the `target_url` property strips the trailing slash, and returns the JS base url.
        assert config.target_url == "http://localhost:3000"

    def test_missing_file_raises_file_not_found(self, tmp_path):
        """ Verifies that `ScanConfig` raises `FileNotFOundError`, when the config path does not exist on disk."""

        # Constructs a path that does not exist in the termporary directory.
        missing_path = str(tmp_path / "nonexistent.yaml")
        # Confirms that `ScanConfig.__init__` raises `FileNotFoundError` before parsing the file.
        with pytest.raises(FileNotFoundError):
            ScanConfig(missing_path)

    def test_credentials_loaded_correctly(self, tmp_path):
        """ Verifies that `credentials` returns a list containing the single credential entry, defined in the YAML"""
        path = _write_yaml(tmp_path, VALID_YAML)
        config = ScanConfig(path)
        # Confirms that exactly one credential entry was parsed from the YAML.
        assert len(config.credentials) == 1
        # Confirms that the parsed credential entry does actually carry the expected admin role value.
        assert config.credentials[0]["role"] == "admin"

    def test_empty_yaml_returns_safe_defaults(self, tmp_path):
        """ Verifies that an empty YAML fileddoes not crash on load, and returns empty defaults for any optional fields."""

        # Writes an empty string to simulate a blank config file, which `yaml.safe_load` should return as `None`.
        path = _write_yaml(tmp_path, "")
        config = ScanConfig(path)
        # COnfirms that `credentials` returns an empty list, rather than `None`, when the YAML is empty.
        assert config.credentials == []


class TestScanConfigValidate:
    """ Tests that `validate()` raises `ValueError`, for each category of missing required fields."""

    def test_validate_passes_on_valid_config(self, tmp_path):
        """ Verifies that `validate()` raises no exception when the config contains all required fields."""
        path = _write_yaml(tmp_path, VALID_YAML)
        config = ScanConfig(path)
        # Calls `validate()` without a `pytest.raises` block, to confirm that it completes without raising.
        config.validate()

    def test_validate_raises_when_base_url_missing(self, tmp_path):
        """ Verifies that `validate()` raises `ValueError`, when `target.base_url` is absent from the YAML."""

        # uses `MISSING_BASE_URL_YAML`, which has a `target` block but no `base_url` key inside it.
        path = _write_yaml(tmp_path, MISSING_BASE_URL_YAML)
        config = ScanConfig(path)
        # COnfirms the error message references `target.base_url` to help in debugging. 
        with pytest.raises(ValueError, match="target.base_url"):
            config.validate()

    def test_validate_raises_when_credentials_missing(self, tmp_path):
        """ Verifies that `validate()` raises `ValueError`, when no credential entries are defined in the YAML."""

        # Uses `MISSING_CREDENTIALS_YAML`, which omits the entire `credentials` block,
        path = _write_yaml(tmp_path, MISSING_CREDENTIALS_YAML)
        config = ScanConfig(path)
        # COnfirms the error message references `credentials`, so the user knows which field to add.
        with pytest.raises(ValueError, match="credentials"):
            config.validate()

    def test_validate_raises_on_invalid_auth_type(self, tmp_path):
        """ Verifies that `validate()` raises `ValueEError`, when a credential entry specifies an unrecognised `auth_type`.
        
        # Defines a YAML string with `invalid_type`, as the `auth_type`, which is not in the allowed set."""
        yaml_content = """\
target:
  base_url: "http://localhost:3000"
credentials:
  - username: "admin@juice-sh.op"
    password: "CHANGE_ME_ADMIN"
    role: "admin"
    auth_type: "invalid_type"
"""
        path = _write_yaml(tmp_path, yaml_content)
        config = ScanConfig(path)
        # COnfirms the error message references `auth_type`, to help the user identify the invalid field.
        with pytest.raises(ValueError, match="auth_type"):
            config.validate()