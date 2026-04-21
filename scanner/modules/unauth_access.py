"""
unauth_access.py

Performs unauthenticated access checls on discovered endpoints for authentication bypass, by comparing authenticated responses from 
`http_client.py` against responses sent by a bare session with no credentials. Also performs forced browsing using 
`wordlists/common_paths.txt` to find resources accessible without authentication on Juice Shop and DVWA.
"""

import os
import requests

from scanner.core.http_client import HTTPClient
from scanner.core.session_manager import SessionManager
from scanner.core.comparator import ResponseComparator
from scanner.core.scope import ScopeEnforcer
from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability


logger = get_logger(__name__)


class UnauthAccessChecker:
    """ Detects authentication bypass, and forced browsing vulnerabilities across all discovered endpoints."""

    def __init__(
        self,
        config,
        http_client: HTTPClient,
        session_manager: SessionManager,
        comparator: ResponseComparator,
    ):
        
        """ Stores all injected dependencies and initialises `self.findings` as an empty list
        for recording `Vulnerability` objects found during unauthenticated access, and
        forced browsing tests. Creates a `ScopeEnforcer` from `config` for scope validation."""
        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.scope = ScopeEnforcer(config)
        self.findings = []

    def test_endpoint(self, endpoint):
        """ Sends both authenticated, and unauthenticated, requests to the same endpoint, then compares
        responses. Flags an authentication bypass if `ResponseComparator` detects matching content
        length. or sensitive field exposure in the unauthenticated response."""

        # Skips endpoints outside of the configured scan scope to avoid unintended requests.
        if not self.scope.is_in_scope(endpoint.url):
            logger.debug(f"{endpoint.url} is out of scope, skipping unauthenticated access check.")
            return

        # Sends a GET or POST request to the endpoint URL using the `user_a` authenticated session from `http_client`.
        try:
            if endpoint.method.upper() == "POST":
                response_auth = self.http_client.send_request("POST", endpoint.url, session_key="user_a")[0]
            else:
                response_auth = self.http_client.send_request("GET", endpoint.url, session_key="user_a")[0]
        except Exception as exc:
            logger.warning(f"Authenticated request to {endpoint.url} failed: {exc}")
            return

        # Skips this endpoint if the authenticated request returned no respponse after retries.
        if response_auth is None:
            logger.debug(f"No authenticated response received for {endpoint.url}, skipping.")
            return

        # Sends an identical request using a bare session, with no cookies or authentication headers.
        try:
            bare_session = requests.Session()
            bare_session.headers.clear()
            # Sends a POST or GET request matching the authenticated call, but using the bare session.
            if endpoint.method.upper() == "POST":
                response_unauth = bare_session.post(
                    endpoint.url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                )
            else:
                response_unauth = bare_session.get(
                    endpoint.url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                )
        except Exception as exc:
            logger.debug(
                f"Unauthenticated request to {endpoint.url} raised a connection error, skipping: {exc}"
            )
            return

        # Skips  this endpoint if the unauthenticated request produced no usable response.
        if response_unauth is None:
            logger.debug(f"Unauthenticated response for {endpoint.url} was None, skipping.")
            return

        # Skips  this endpoint if `is_access_granted` indicates the server correctly denied the unauthenticated request.
        if not self.comparator.is_access_granted(response_unauth):
            logger.debug(
                f"{endpoint.url} correctly denied unauthenticated access with status {response_unauth.status_code}."
            )
            return

        # Checks if the authenticated and unauthenticated body lengths are within 10%, suggesting that identical content was returned.
        length_result = self.comparator.compare_body_length(response_auth, response_unauth)
        same_content = length_result.get("within_threshold", False)

        # Extracts any sensitive JSON fields from the unauthenticated response body to confirm data exposure.
        try:
            body_json = response_unauth.json()
        except Exception:
            body_json = {}

        sensitive_fields = self.comparator.extract_sensitive_fields(body_json)
        confirmed = same_content or bool(sensitive_fields)

        # Creates and appends a high severity Authentication BYpass vulnerability if access, or data exposure is confirmed.
        if confirmed:
            vuln = Vulnerability(
                vuln_type="Authentication Bypass",
                severity="High",
                endpoint=endpoint.url,
                method=endpoint.method,
                description=(
                    f"Endpoint accessible without authentication. "
                    f"Returned status {response_unauth.status_code} with {len(response_unauth.content)} bytes."
                ),
                evidence={
                    "auth_status_code": response_auth.status_code,
                    "unauth_status_code": response_unauth.status_code,
                    "body_within_threshold": same_content,
                    "sensitive_fields_exposed": sensitive_fields,
                    "unauth_body_length": len(response_unauth.content),
                },
            )
            self.findings.append(vuln)
            logger.warning(
                f"Authentication bypass confirmed at {endpoint.url} ({endpoint.method})."
            )

    def test_forced_browsing(self, custom_paths=None):
        """ Loads all paths from `wordlists/common_paths.txt`, and sends unauthenticated GET requests
        to each. Flags any path returning status 200 with over 500 bytes that does not redirect
        to a Juice Shop or DVWA login page as a forced browsing vulnerability."""

        # Resolves the absolute path to `wordlists/common_paths.txt` relative to the module's location.
        wordlist_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "common_paths.txt")
        )

        paths = []
        # Reads every line from `wordlists/common_paths.txt`, appending valid paths and skipping comments and blank lines.
        try:
            with open(wordlist_path, "r", encoding="utf-8") as wordlist_file:
                for line in wordlist_file:
                    stripped = line.strip()
                    # Appends the path when the line is not blank and does not begin with the comment character.
                    if stripped and not stripped.startswith("#"):
                        paths.append(stripped)
        except FileNotFoundError:
            logger.error(
                f"Wordlist not found at {wordlist_path}, forced browsing will not run."
            )
            return

        # Extends the path list with any additional paths provided by the caller prior to the scan beginning.
        if custom_paths:
            paths.extend(custom_paths)

        logger.info(
            f"Starting forced browsing with {len(paths)} paths against {self.config.target_url}."
        )

        login_indicators = ["/#/login", "/login", "login", "sign-in", "signin"]

        bare_session = requests.Session()
        bare_session.headers.clear()

        # Iterates over every path, constructing the full target URL, sending a bare GET, and then flagging resources accessible without credentials.
        for path in paths:
            url = self.config.target_url.rstrip("/") + "/" + path.lstrip("/")

            # Skips the paths outside of the configured scan scope before sending any requests.
            if not self.scope.is_in_scope(url):
                continue

            try:
                response = bare_session.get(
                    url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                    allow_redirects=True,
                )
            except Exception as exc:
                logger.debug(f"Forced browsing request to {url} failed: {exc}")
                continue
            
            # Skips responses without status 200, or with a body of 500 bytes or fewer, as these are likely error pages.
            if response.status_code != 200 or len(response.content) <= 500:
                continue

            final_url = response.url.lower()
            # Skips paths where the final resolved URL contains a Juice Shop or DVWA login page indicator.
            if any(indicator in final_url for indicator in login_indicators):
                logger.debug(
                    f"{url} resolved to a login page and will not be recorded as a finding."
                )
                continue

            vuln = Vulnerability(
                vuln_type="Forced Browsing - Unprotected Resource",
                severity="Medium",
                endpoint=url,
                method="GET",
                description=(
                    f"Path accessible without authentication. "
                    f"Returned status {response.status_code} with {len(response.content)} bytes."
                ),
                evidence={
                    "status_code": response.status_code,
                    "body_length": len(response.content),
                    "final_url": response.url,
                },
            )
            self.findings.append(vuln)
            logger.warning(
                f"Forced browsing finding: {url} returned {response.status_code} without authentication."
            )

    def test_all(self, endpoints):
        """ Calls `test_endpoint` on each item in the provided list, covering all endpoints that were 
        discovered by `crawler.py` and `spa_crawler.py` for unauthenticated access vulnerabilities."""

        logger.info(
            f"Running unauthenticated access checks across {len(endpoints)} endpoints."
        )

        # Calls `test_endpoint` on each endpoint, to run the full unauthenticated access check across the list.
        for endpoint in endpoints:
            self.test_endpoint(endpoint)

    def get_findings(self):
        """Returns the complete list of `Vulnerability` objects recorded during unauthenticated access testing."""
        return self.findings