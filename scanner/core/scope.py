"""
`scope.py`

Scope control module. Ensures that all discovered and tested URLs remain within defined scanning boundaries.
Prevents the scanner from accidentally targeting external systems, sensitive endpoints, or areas explicitly excluded via configuration.
Provides the domain and subdomain restriction enforcement, path-based inclusion and exclusion logic, optional `robots.txt` parsing for ethical crawling behaviour, and URL
filtering utilities for use by discovery and crawling elements of the project. Overall, acts as a safety and compliance layer that sits between the URL discovery and
request execution layers, ensuring that the scanner stays within the bounds of its intended scope.
"""

import re
import urllib.parse

import requests

from scanner.core.logger import get_logger

logger = get_logger(__name__)


class ScopeEnforcer:
    """Enforces scanning boundaries across all phases of the pipeline. Instantiated once in `main.py`, then passed to `Crawler`, `SPACrawler`, `ParameterEnumerator`, and all other test modules, so that every URL passes
    through a single consistent scope check before its requested, or tested."""

    def __init__(self, config):
        """Parses tghe target domain from `config.target_url`, builds the set of allowed domains, compiles the optional subdomain regex, and fetches `robots.txt` if the condfig enables it."""
        
        # Full `ScanConfig` stored so that `target_url`, `excluded_paths`, `verify_ssl` and scope sub-keys are accessible without separate arguments.
        self.config = config

        # Populated by `fetch_robots_txt()` when `robots_txt` is true in config.
        self.disallowed_paths = []

        # logger.debug("Initialising ScopeEnforcer")

        # Extracts netloc from `target_url` - "localhost:3000" for Juice Shop.
        parsed = urllib.parse.urlparse(config.target_url)
        self.target_domain = parsed.netloc

        # DONT USE URLSPLIT - error to log - breaks downstream matching.
        self.allowed_domains = {self.target_domain}

        # print(self.allowed_domains)

        # Defaults to an empty dictionary if the scope key is absent from config.
        scope = config.scope if isinstance(config.scope, dict) else {}    # keep as set not list - membership checks frequent.

        if scope.get("include_subdomains", False):
            # Strips ports before building the regex so both `api.localhost` and `api.localhost:3000` match correctly.
            base = self.target_domain.split(":")[0]

            # Fallback checks needed - older configs didn't alwasy include in scope.
            self.subdomain_pattern = re.compile(
                r"^(.+\.)?" + re.escape(base) + r"(:\d+)?$"
            )

            # Dont reuse - doesnt handle ports properly.
            # self.subdomain_pattern = re.compile(r".*" + base)

        else:
            # Single-host enforcement only, which is correct for both Juice Shop and DVWA.
            self.subdomain_pattern = None

        # Calls here so `disallowed_paths` is fully populated before the crawler makes its first request.
        if scope.get("robots_txt", False):
            # Regex easier than manually stripping subdomains very request.
            self.fetch_robots_txt()

    def fetch_robots_txt(self):
        """ GETs `/robots.txt` from thes target, and parseds each `Disallow` directive into `self.disallowed_paths`. A 404, or connetcion failure, sets `disallowed_paths` to an empty list, and logs a warning so that the scan continues with only
        `excluded_paths` from config as path restrictions."""

        robots_url = self.config.target_url.rstrip("/") + "/robots.txt"

        # logger.info(f"Checking robots.txt at {robots_url}")

        try:
            # DONT touch - crawler overloads before robots is loaded.
            response = requests.get(
                robots_url,
                verify=self.config.verify_ssl,
                timeout=10,
            )

            # print(response.status_code)

            # Using plain requests here on purpose, dont need HTTPClient overhead.
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()

                    # logger.debug(f"robots.txt line: {line}")

                    # `User-agent`, `Allow`, `Sitemap`, and comment lines are ignored.
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        # Empty `Disallow` means "allow everything" in robots.txt syntax.
                        if path:
                            self.disallowed_paths.append(path)

                            # print(f"Added disallowed path: {path}")

                logger.info(
                    f"robots.txt parsed - {len(self.disallowed_paths)} disallowed path(s) found"
                )
            else:
                # Juice Shop v17.1.1 and DVWA 1.9 serve no `robots.txt`, so a 404 here is expected in lab env.
                logger.warning(
                    f"robots.txt not found at {robots_url} (status {response.status_code}) - continuing unrestricted"
                )
                self.disallowed_paths = []

        except Exception as e:
            # Connection error or timeout - the scan continues with config `excluded_paths` as the only path restriction.
            logger.warning(f"Failed to fetch robots.txt: {e} - continuing unrestricted")

            # logger.exception("robots.txt fetch failed")

            self.disallowed_paths = []

    def is_in_scope(self, url: str) -> bool:
        """ Checks `url` against all configured scope rules in order. Returns `False` at tghe first failed check so that t most important constraints (domain, exclusions) 
        are evaluaeted before the more permissive path-prefix filter."""
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            # Rejects malformed hrefs such as javascript: and data: URIs.
            return False

        domain = parsed.netloc
        path = parsed.path

        # print(domain, path)

        # JS HTML contains links to third-party CDNs - any domain not in the target host or an allowed subdomain is rejected here.
        if domain not in self.allowed_domains:
            if self.subdomain_pattern and self.subdomain_pattern.match(domain):
                pass
            else:
                # logger.debug(f"Rejected out-of-scope domain: {domain}")
                return False

        # Rejects paths matching any `excluded_paths` regex from config.
        for pattern in self.config.excluded_paths:
            try:
                #  Regex - exact string matching too limited.
                if re.search(pattern, path):

                    # print(f"Excluded by regex: {pattern}")

                    return False
            except re.error:
                # Malformed regex logs a warning and is skipped so one bad pattern cannot abort the scan.
                logger.warning(
                    f"Invalid excluded_paths regex pattern: '{pattern}' - skipping"
                )

                # logger.debug("Skipping malformed regex")

        scope = self.config.scope if isinstance(self.config.scope, dict) else {}
        if scope.get("robots_txt", False):
            for disallowed in self.disallowed_paths:
                if path.startswith(disallowed):

                    # logger.debug(f"Blocked by robots.txt: {path}")

                    return False

        # When set, restricts the scan to a specific section of the target.
        allowed_paths = scope.get("allowed_paths", [])
        if allowed_paths:
            # Always permits the root path through as the crawler's seed entry point.
            if path not in ("", "/"):
                if not any(path.startswith(prefix) for prefix in allowed_paths):

                    # return path.startswith(tuple(allowed_paths))

                    return False

        return True

    def filter_urls(self, url_list: list) -> list:
        """Passes each URL through `is_in_scope`, and returns only those that pass all scope checks."""
        
        # print(len(url_list))

        return [url for url in url_list if self.is_in_scope(url)]