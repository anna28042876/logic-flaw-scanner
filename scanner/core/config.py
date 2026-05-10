"""
`config.py`

This module is loaded when the scanner starts, and is responsible for reader the user supplied YAML configuration file.
Every configuration value is exposed as a typed Python property, so that other modules can access the settings without
needing to understand the underlying YAML structure. If a value is missing from the config file, a safe default is returned
instead."""

import yaml
import os


class ScanConfig:
    """Configuration loader for the scanner. It reads a YAML config file, and exposes the typed properties for all scanner
    settings."""

    def __init__(self, file_path):
        """LOads and parses the YAML config file, at `file_path`.

        Args:
            file_path (Str): Path to the YAML config file.

            Raises:
                FileNotFoundError: This is raised if the supplied file path doesn't exist.
        """

        # Fails immediately with error message, if the config file can't be found.
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Config file not found: '{file_path}'. "
                f"Please provide a valid YAML config path."
            )

        # Opens the config file, and safely parses the YAML contents into Python dictionary.
        with open(file_path, "r") as f:
            self._data = yaml.safe_load(f)

        # Replaces `None` with an empty dictionary, if the YAML file exists but contains no data.
        if self._data is None:
            self._data = {}

    # `target_url`.
    @property
    def target_url(self):
        """Scan target base URL, with any trailing slashes remoived.

        Returns:
            str: A target base url e.g., `http://localhost:3000`.
        """
        return self._data["target"]["base_url"].rstrip("/")

    # `credentials`.
    @property
    def credentials(self):
        """COnfigured authentication credentials for scanner.

        Returns:
            list[dict]: credential definitions, or empty list if none are configured.
        """

        # Returns empty dictionary if credentials are missing. Validation is handled seperately via `validate()`.
        return self._data.get("credentials", [])

    # `login_config`.
    @property
    def login_config(self):
        """Authentication config used during login.

        Rerturns:
            dict: The login config mapping, or an empty dictionary if no login section is defined.
        """

        # Returns an empty dictionary if the login settings are absent. Required keys are later checked via the session manager.
        return self._data.get("login", {})

    # `crawl_config`.
    @property
    def crawl_config(self):
        """Crawler configuration with defaults automatically applied.

        Returns:
            dict: Tghe merged crawler configuration values.
        """

        defaults = {
            # Max crawler traversal depth from the starting URL.
            "max_depth": 3,
            # Increased to support large applications like JS.
            "max_pages": 500,
            # Terminates crawling after five minutes, regardless of page count.
            "max_crawl_time": 300,
            # Restricts crawling to the targert domain only.
            "follow_external": False,
            # ENables PLaywright based crawling, for single page applications.
            "handle_spa": True,
        }

        # APplies user supplied values over the defaults, so that only customised settings need to be included in the YAML file.
        defaults.update(self._data.get("crawl", {}))
        return defaults

    # `rate_limit_config`.
    @property
    def rate_limit_config(self):
        """RAte limit testing configuration with the defaults applied.

        Returns:
            dict: The merged rate limiting config values.
        """

        defaults = {
            # Recued to avoid degrading the local VM performance during testing.
            "requests_per_second": 10,
            # Lower default used for the initial bnurst request.
            "total_requests": 100,
            "critical_endpoints": [],
            "bypass_headers": [
                "X-Forwarded-For",
                "X-Originating-IP",
                "X-Remote-IP",
                "X-Client-IP",
                "X-Real-IP",
            ],
            "rate_limit_tiers": [
                {"rps": 10, "count": 100},
                {"rps": 25, "count": 150},
                {"rps": 50, "count": 200},
            ],
        }

        # Allows YAML supplied values to override the dewfault config.
        defaults.update(self._data.get("rate_limit", {}))
        return defaults

    # `workflows`.
    @property
    def workflows(self):
        """Workflow definitions that are loaded from the config file.

        Returns:
            list: COnfigured workflow definitions, or an empty list if none exist.
        """
        return self._data.get("workflows", [])

    # `known_Admin_endpoints`.
    @property
    def known_admin_endpoints(self):
        """Statistically defined administrator endpoints, used during vertical auth testing.

        Returns:
            lsit[dict]: COnfigured administrator endpoint definitions.
        """
        return self._data.get("known_admin_endpoints", [])

    # `excluded_paths`.
    @property
    def excluded_paths(self):
        """The regex patterns representing paths that should never be crawled.

        Returns:
            list[str]: COnfigured exclusion patterns.
        """

        # Reads the excludes paths from the nested target `target.excluded_paths` YAML.
        return self._data.get("target", {}).get("excluded_paths", [])

    # `proxy`.
    @property
    def proxy(self):
        """
        Proxy address used to route scanner traffic, through an intercepting proxy e.g., BUrp suite.

        Returns"
            str or None: COnfigured proxy URL, or None if disabled.
        """

        return self._data.get("proxy", None)

    # `verify_ssl`.
    @property
    def verify_ssl(self):
        """Controls whether SSL certificates are verified for HTTP requests.

        Returns:
            bool: True if SSL certificates should be verified.
        """
        return self._data.get("verify_ssl", True)

    # `throttle_delay`.
    @property
    def throttle_delay(self):
        """Delay between HTTP requests in seconds.

        Returns:
            float: COnfigured throttle delay value.
        """

        # Uses a low default delay, because localhost DOcker environemnts have negligible network latency.
        return self._data.get("throttle_delay", 0.05)

    # `scope`.
    @property
    def scope(self):
        """Scope restriction settings controlled which targets may be scanned.

        Returns:
            dict: Merged scope configuration values.
        """

        defaults = {
            # Restricts scannign to the exact configured target domain.
            "include_subdomains": False,
            # Empty list means that no path restrictions are applied.
            "allowed_paths": [],
            # Ignores robots.txt, because sensitive paths are commonly disallowed intentionally.
            "robots_txt": False,
        }

        # Applies user supplied scope values, over the defaults.
        defaults.update(self._data.get("scope", {}))
        return defaults

    # `random_seed`.
    @property
    def random_seed(self):
        """Fixed seed value used by all the scanner random number generators.

        Returns:
            int: Configured random seed value.
        """
        return self._data.get("random_seed", 42)

    # `validate()`
    def validate(self):
        """Validates that all required config files exist, nd contain correctly structured values.

        Raises:
            ValueErrror: Raised if requried fields are missing, or invalid.
        """

        # Imported locally, because its only used during validation.
        import re

        # Ensures that the config contains a target section, with a base URL.
        if "target" not in self._data or "base_url" not in self._data["target"]:
            raise ValueError("Config missing required field: target.base_url")

        # Verified that the target URL begins with either `http://`, or `https://`.
        url = self._data["target"]["base_url"]
        if not re.match(r"https?://", url):
            raise ValueError(
                f"target.base_url must start with http:// or https://, got: '{url}'"
            )

        # Requires at least one credential set, so authenticated functionality can be tested.
        if not self._data.get("credentials"):
            raise ValueError(
                "Config must define at least one entry under 'credentials'."
            )

        # Validates the structure, and authentication type of every configured credential entry.
        valid_auth_types = {"form", "bearer", "api_key", "basic"}

        # Iterates through  every credential entryu loaded from the YAML config file.
        for i, cred in enumerate(self._data["credentials"]):
            # Checks that all the required credential fields are present, before the scan begins.
            for field in ("username", "password", "role", "auth_type"):
                # Raises a validation immediately if a required field is missing.
                if field not in cred:
                    raise ValueError(
                        f"Credential entry {i} missing required field: '{field}'"
                    )

            # Ensures the configured auth type is recognised by the scanner.
            if cred["auth_type"] not in valid_auth_types:
                raise ValueError(
                    f"Credential entry {i} has invalid auth_type "
                    f"'{cred['auth_type']}'. Must be one of: {valid_auth_types}"
                )

    # `__repr__`.
    def __repr__(self):
        """Returns a readable summary of the active config.

        Returns"
            str: String representation, containing key config details.
        """

        # Provides a concise config summary, that is useful for debugging and scan startup logging.
        cred_count = len(self._data.get("credentials", []))

        return (
            f"ScanConfig(target='{self.target_url}', "
            f"credentials={cred_count}, "
            f"scope={self.scope})"
        )
