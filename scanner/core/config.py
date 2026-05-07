# scanner/core/config.py

"""This module is the first thing loaded by the scanner when started. Reads the user's YAML configuration file and exposes every setting as a typed python property, so that all other
modules can access configuration values without knowing anything about the YAML structures themselves. If a setting is missing from the YAML, a safe default is returned."""

# Import statements.
import yaml  # Third-party library for parsing YAML files.
import os  # Checks whether the configuration file exists on disk.


# Loads the YAML config file and exposes every setting as a typed property with safe defaults.
class ScanConfig:
    """Configuration loader for the logic flaw scanner.
    Reads a YAML config file and exposes the typed properties for all scanner settings."""

    def __init__(self, file_path):
        """Loads and parses the YAML configuration file.
        Args: file_path (str): Path to the YAML config file.
        Raises: FileNotFoundError if the file does not exist."""

        # Guard clause - fails immediately with a clear message if the file doesn't exist, rather than letting `yaml.safe_load` raise an ambiguous error.
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Config file not found: '{file_path}'. "
                f"Please provide a valid YAML config path."
            )

        # Opens the file and parses it into a Python `dict` using `safe_load`.
        # `safe_load` is used instead of `load()` because it prevents arbitrary Python objects from instantiating from untrusted YAML inputs.
        with open(file_path, "r") as f:
            self._data = yaml.safe_load(f)

        # `safe_load` returns None if the file exists but is empty.
        # Replaces it with an empty `dict` so that all `.get()` calls below still execute safely.
        if self._data is None:
            self._data = {}

    ### `target_url`.
    @property
    def target_url(self):
        """Base URL of the scan target, trailing slash stripped."""
        # Strips the trailing slash so that when modules append paths like `/api/users`, we don't end up with double slashes (`//api/users`).
        return self._data["target"]["base_url"].rstrip("/")

    ### `credentials`.
    @property
    def credentials(self):
        """A list of credential `dicts`. Each has: `username`, `password`, `role`, `auth_type`."""
        # Returns an empty list if `credentials` is missing from the YAML, which will be caught later by `validate()`.
        return self._data.get("credentials", [])

    ### `login_config`.
    @property
    def login_config(self):
        """Login settings: `login_url`, `login_method`, `username_field`, `password_field`, `success_indicator`."""
        # Returns an empty `dict` if `login` is not defined in the YAML. The session manager checks for the required keys before using this.
        return self._data.get("login", {})

    ### `crawl_config`.
    # `max_pages` raised from 200 to 500 - Juice Shop has 60+.
    # REST endpoints: 200 risks terminating before all ground-truth targets are discovered. `max_crawl_time` is added as a secondary safety cutoff.
    @property
    def crawl_config(self):
        """Crawl settings with defaults applied."""
        defaults = {
            "max_depth": 3,  # How many links deep to follow from the starting URL.
            "max_pages": 500,  # Raised from 200 - Juice Shop has 60+ endpoints.
            "max_crawl_time": 300,  # Stop crawling after 300 seconds regardless.
            "follow_external": False,  # Never leave the target domain.
            "handle_spa": True,  # Also run the Playwright SPA crawler.
        }
        # Any values set in the YAML overrides the defaults above - means that the YAML only needs to specify values that differ from the defaults.
        defaults.update(self._data.get("crawl", {}))
        return defaults

    ### `rate_limit_config`.
    # Default rps reduced from 50 to 10 to avoid degradation of Juice Shop performance inside the kali machine.
    # Tiered escalation included so that the scanner automatically increases rps if no limiting is detected at lower tiers.
    # Provides better data than that of a single blast.
    @property
    def rate_limit_config(self):
        """Rate limit testing with defaults applied."""
        defaults = {
            "requests_per_second": 10,  # Reduced from 50 to protect VM performance.
            "total_requests": 100,  # Reduced from 200 for the initial pass.
            # Explicitly declared endpoints for `rate_limit_detector.py` to probe.
            # An empty list causes the detector to fall back to its own hard-coded critical paths.
            # Populated per-target in `juiceshop.yaml` and `dvwa.yaml`.
            "critical_endpoints": [],
            # Headers are to rotate when testing rate limit bypass techniques.
            # Each of these can be used to spoof a different client IP address.
            "bypass_headers": [
                "X-Forwarded-For",
                "X-Originating-IP",
                "X-Remote-IP",
                "X-Client-IP",
                "X-Real-IP",
            ],
            # Tiered escalation - if no rate limiting is found at 10 rps, the detector automatically retries at 25, then 50, recording
            # at which threshold, (if any), the server starts responding with 429s.
            "rate_limit_tiers": [
                {"rps": 10, "count": 100},
                {"rps": 25, "count": 150},
                {"rps": 50, "count": 200},
            ],
        }
        defaults.update(self._data.get("rate_limit", {}))
        return defaults

    ### `workflows`.
    @property
    def workflows(self):
        """List of workflow definitions from the configuration file.
        Each workflow is a named sequence of HTTP steps, used by the
        `WorkflowRecorder` and `WorkflowBypassTester`."""
        return self._data.get("workflows", [])

    ### `known_admin_endpoints`.
    @property
    def known_admin_endpoints(self):
        """List of statically declared admin-only endpoints for `vertical_auth.py` to test
        regardless of crawl differentiation. Each entry is a dict with `url` and `method` keys.
        Populated per-target in `juiceshop.yaml` to cover endpoints all crawl roles discover
        equally, such as `/api/Users` and `/api/Complaints`, which the `discovered_by_roles`
        heuristic in `vertical_auth.py` would otherwise miss."""
        return self._data.get("known_admin_endpoints", [])

    ### `excluded_paths`.
    @property
    def excluded_paths(self):
        """Regex patterns for paths the crawler should never visit.
        Useful for skipping logout endpoints or known-broken pages."""
        # Nested under `target` in the YAML: `target.excluded_paths`.
        return self._data.get("target", {}).get("excluded_paths", [])

    ### `proxy`.
    @property
    def proxy(self):
        """Proxy URL, `http://127.0.0.1:8080` for Burp Suite.
        When set, all scanner HTTP traffic is routed through this proxy, allowing for manual inspection of requests and responses. But none if not set."""
        return self._data.get("proxy", None)

    ### `verify_ssl`.
    @property
    def verify_ssl(self):
        """Whether to verify SSL certificates.
        Defaults to True for safety; sets to False in lab environments where the Docker containers use self-signed certificates."""
        return self._data.get("verify_ssl", True)

    ### `throttle_delay`.
    # Defaults reduced from 0.1 to 0.05 seconds for local Docker targets.
    # Network latency to `localhost` is negligible, so 0.1 would double scan time for no benefit.
    # Increase to 0.1+ for external targets.
    @property
    def throttle_delay(self):
        """Seconds to wait between HTTP requests.
        0.05 (20 requests/s) suits local Docker targets.
        Increase to 0.1 or higher for external/production targets."""
        return self._data.get("throttle_delay", 0.05)

    ### `scope`.
    # `allowed_paths` is empty by default (all paths allowed).
    # Setting `['/api/', '/rest/']` as a generic default would cause the crawler to miss DVWA entirely - `(/vulnerabilities/, /dvwa/)`.
    # Each target gets its own `allowed_paths` in `configs/juiceshop.yaml` and `configs/dvwa.yaml`.
    # `robots_txt` defaults to False as security scanners must test disallowed paths because those are often the most sensitive targets.
    @property
    def scope(self):
        """Scope enforcement settings. `allowed_paths` is empty by default (all paths are in scope).
        `robots_txt` defaults to `False` - do not skip disallowed paths."""
        defaults = {
            "include_subdomains": False,  # Only scan the exact target domain specified.
            "allowed_paths": [],  # `empty` = no path restrictions in generic configuration file.
            "robots_txt": False,  # Ignore `robots.txt` - disallowed paths are often sensitive targets.
        }
        defaults.update(self._data.get("scope", {}))
        return defaults

    ### `random_seed`.
    @property
    def random_seed(self):
        """Fixed integer seed for all random number generators in the scanner.
        Ensures three consecutive scan runs produce byte-identical JSON reports."""
        return self._data.get("random_seed", 42)

    ### `validate()`.
    def validate(self):
        """Validate that all required configuration fields are present and formed right. Called by the scanner entry point immediately after loading the config.
        Raises: `ValueError` with a descriptive message if validation fails."""
        import re  # Single use, imported locally to keep top-level imports minimal.

        # Verifies top-level `target` section and `base_url` are both present.
        if "target" not in self._data or "base_url" not in self._data["target"]:
            raise ValueError("Config missing required field: target.base_url")

        # Checks that the URL looks like a real URL (starts with http:// or https://).
        url = self._data["target"]["base_url"]
        if not re.match(r"https?://", url):
            raise ValueError(
                f"target.base_url must start with http:// or https://, got: '{url}'"
            )

        # At least one credential set must be defined as without credentials the scanner cannot test any authenticated endpoints at all.
        if not self._data.get("credentials"):
            raise ValueError(
                "Config must define at least one entry under 'credentials'."
            )

        # Validates that every credential entry has the four required fields and a recognised `auth_type`. This catches typos before the scan starts.
        valid_auth_types = {"form", "bearer", "api_key", "basic"}
        for i, cred in enumerate(self._data["credentials"]):
            for field in ("username", "password", "role", "auth_type"):
                if field not in cred:
                    raise ValueError(
                        f"Credential entry {i} missing required field: '{field}'"
                    )
            if cred["auth_type"] not in valid_auth_types:
                raise ValueError(
                    f"Credential entry {i} has invalid auth_type "
                    f"'{cred['auth_type']}'. Must be one of: {valid_auth_types}"
                )

    ### `__repr__`.
    def __repr__(self):
        # Provides an understandable summary when the object is printed, which is useful for confirming the correct configuration file was loaded at scan start.
        cred_count = len(self._data.get("credentials", []))
        return (
            f"ScanConfig(target='{self.target_url}', "
            f"credentials={cred_count}, "
            f"scope={self.scope})"
        )