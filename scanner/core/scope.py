"""
`scope.py`

Scope control module. 
Ensures that all discovered and tested URLs remain within defined scanning boundaries. 
Prevents the scanner from accidentally targeting external systems, sensitive endpoints, 
or areas explicitly excluded via configuration. 
Provides the domain and subdomain restriction enforcement, path-based inclusion and 
exclusion logic, optional `robots.txt` parsing for ethical crawling behaviour, and URL
filtering utilities for use by discovery and crawling elements of the project.
Overall, acts as a safety and compliance layer that sits between the URL discovery and 
request execution layers, ensuring that the scanner stays within the bounds of its intended
scope. 
"""

import re
import urllib.parse

import requests

from scanner.core.logger import get_logger

logger = get_logger(__name__)


class ScopeEnforcer:
    """ 
    Enforces scanning boundaries across all phases of the pipeline.
    Instantiated once in `main.py` and passed to the `Crawler`, `SPACrawler`,
    `ParameterEnumerator`, and all other test modules so that every URL 
    passes through a single consistent scope check before it is requested or
    test3ed.
    """
    def __init__(self, config):
        # Full `ScanConfig` stored so that `target_url`, `excluded_paths`, `verify_ssl`-
        # and scope sub-keys are accessible without separate arguments. 
        self.config = config

        # Populated by `fetch_robots_txt()` when `robots.txt` (true in `scan_config.yaml`)-
        #- an empty list means no `robots.txt` restrictions apply.
        self.disallowed_paths = []

        # Extract netloc from `target_url` - used as the baseline allowed domain. 
        # "localhost:3000" for JuiceShop.
        # "localhost:8080" for DVWA.
        parsed = urllib.parse.urlparse(config.target_url)
        self.target_domain = parsed.netloc
        self.allowed_domains = {self.target_domain}

        # Defaults to an empty dictionary if the scope key is absent from `scan_config.yaml`.
        scope = config.scope if isinstance(config.scope, dict) else {}

        if scope.get("include_subdomains", False):
            # Ports stripped prior to building the regex.
            # So both `api.localhost` and `api.localhost:3000` match correctly.
            base = self.target_domain.split(":")[0]
            self.subdomain_pattern = re.compile(
                r"^(.+\.)?" + re.escape(base) + r"(:\d+)?$"
            )
        else:
            # Single-host enforcement only which is correct for both Juice SHop and DVWA. 
            self.subdomain_pattern = None

        # Called here so `disallowed_paths` is fully pipulated before the crawler makes first req.
        if scope.get("robots_txt", False):
            self.fetch_robots_txt()

    def fetch_robots_txt(self):
        """
        `GETs / robots.txt` from the target and parses each `Disallow` directive into `self.disallowed_paths`.
        A 404 or connection failure sets `disallowed_paths` to `[]` and logs a warning so that the scan continues 
        with the exclusions only defined in the `scan_config.yaml`.
        """
        robots_url = self.config.target_url.rstrip("/") + "/robots.txt"

        try:
            response = requests.get(
                robots_url,
                verify=self.config.verify_ssl,
                timeout=10,
            )

            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    # `User-agent`, `Allow`, `Sitemap`, and `comment` lines are ignored.
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        # Empty `Disallow` means "allow everything" in `robots.txt`.
                        # `syntax` is not added to `disallowed_paths`.
                        if path:
                            self.disallowed_paths.append(path)
                logger.info(f"robots.txt parsed - {len(self.disallowed_paths)} disallowed path(s) found")
            else:
                # Juice Shop v17.1.1 and DVWA 1.9 serve no `robots.txt`, so a 404 here is expected in lab env. 
                logger.warning(f"robots.txt not found at {robots_url} (status {response.status_code}) - continuing unrestricted")
                self.disallowed_paths = []

        except Exception as e:
            # Connection error or timeout - the scan continues with config `excluded_paths` as the only path restriction.
            logger.warning(f"Failed to fetch robots.txt: {e} - continuing unrestricted")
            self.disallowed_paths = []

    def is_in_scope(self, url: str) -> bool:
        """
        Called before any URL is queued or requested. Returns False at the first dailed check, True if only all pass.
        Checks in order: `domain`, `excluded_paths`, `regexes`, `robots.txt`. Disallow `prefixes`, `allowed_paths` `prefixes`.
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            # Rejects malformed hrefs such as javascript, and data URIs extracted from Juice Shop's Angular frontend. 
            return False

        domain = parsed.netloc
        path = parsed.path

        # Juice Shop's HTML contains links to third-part CDNs - any domain that is not in the target host or an allowed-
        # -subdomain  is rejected  here. 
        if domain not in self.allowed_domains:
            if self.subdomain_pattern and self.subdomain_pattern.match(domain):
                pass
            else:
                return False

        # Rejects paths matching any `excluded_paths` regex from the `scan_config.yaml` file e.g., `/logout`,-
        # #- or `/rest/user/reset` which would break the session state. 
        for pattern in self.config.excluded_paths:
            try:
                if re.search(pattern, path):
                    return False
            except re.error:
                # Malformed regex logs a warning and is skipped so one bad pattern in `scan_config.yaml` cannot abort the scan.
                logger.warning(f"Invalid excluded_paths regex pattern: '{pattern}' - skipping")

        scope = self.config.scope if isinstance(self.config.scope, dict) else {}
        if scope.get("robots_txt", False):
            for disallowed in self.disallowed_paths:
                if path.startswith(disallowed):
                    return False

        # When set, restricts the scan to a specific section of the target, e.g., `/rest/` on Juice Shop or `/api/` only.
        allowed_paths = scope.get("allowed_paths", [])
        if allowed_paths:
            if not any(path.startswith(prefix) for prefix in allowed_paths):
                return False

        return True

    def filter_urls(self, url_list: list) -> list:
        """ 
        Passes each URL through `is_in_scope()` and returns only those that pass the specified criteria. 
        Called by the `Crawler` and `SPACrawler` after each page crawl to remove  any out-of-scope URLs
        before they enter the discovery queue. 
        """
        return [url for url in url_list if self.is_in_scope(url)]