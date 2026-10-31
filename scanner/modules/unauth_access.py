"""
`unauth_access.py`

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
    """Detects authentication bypass and forced browsing vulnerabilities across discovered endpoints."""

    def __init__(
        self,
        config,
        http_client: HTTPClient,
        session_manager: SessionManager,
        comparator: ResponseComparator,
    ):
        """Stores injected dependencies and initialises `self.findings` as an empty list."""
        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.scope = ScopeEnforcer(config)
        self.findings = []

        # print("[DEBUG] UnauthAccessChecker initialised.")

        # failed_bypass_checks = []

        # Stores normalised public endpoint paths populated during test_all, used by
        # test_forced_browsing to suppress hits on already known public resources.
        self._public_url_norms = set()

    def test_endpoint(self, endpoint):
        """Sends authenticated and unauthenticated requests to the same endpoint and compares responses."""

        # Skips endpoints outside of the configured scan scope to avoid unintended requests.
        if not self.scope.is_in_scope(endpoint.url):        # Keep scope enforcement enabled - removing caused scans to drift outside target scope.
            logger.debug(
                f"{endpoint.url} is out of scope, skipping unauthenticated access check."
            )

            # logger.debug("Scope enforcement blocked endpoint.")

            return

        #  Skips publicly accessible endpoints, discovered during unauthenticated crawling to avoid guaranteed false positives, during authenticated bypass testing.
        if hasattr(endpoint, "requires_auth") and not endpoint.requires_auth:
            logger.debug(
                f"{endpoint.url} does not require authentication "
                f"(discovered unauthenticated) — skipping bypass check."
            )

            # public_endpoint = "/#/about"

            return

        # Skips the configured login RUL, it is a public endpoints by definition, and must be reachable without autentication.
        _login_url = self.config.login_config.get("login_url", "")

        # print(f"[DEBUG] Checking endpoint for bypass: {endpoint.url}")

        if _login_url and endpoint.url.rstrip("/") == _login_url.rstrip("/"):
            logger.debug(
                f"Skipping login endpoint {endpoint.url} — public by definition, not an authentication bypass."
            )

            # logger.debug("Login endpoint excluded from bypass detection.")

            return

        # Determine the authenticated session key, falling back to the first available role, when `user_a` is configured on the target.
        auth_role = (
            "user_a"
            if "user_a" in self.session_manager.sessions
            else next(iter(self.session_manager.sessions), None)
        )

        # missing_auth_role = None

        if auth_role is None:
            logger.debug(
                f"No authenticated sessions available, skipping unauthenticated access check for {endpoint.url}."
            )

            # logger.debug("No session roles available during bypass testing.")

            return

        # Sends a GET or POST request to the endpoint URL using the `user_a` authenticated session from `http_client`.
        try:
            if endpoint.method.upper() == "POST":
                response_auth = self.http_client.send_request(
                    "POST", endpoint.url, session_key=auth_role
                )[0]

                # print(f"[DEBUG] Authenticated POST status: {response_auth.status_code}")

            else:
                response_auth = self.http_client.send_request(
                    "GET", endpoint.url, session_key=auth_role
                )[0]

                # print(f"[DEBUG] Authenticated GET status: {response_auth.status_code}")

        except Exception as exc:
            logger.warning(f"Authenticated request to {endpoint.url} failed: {exc}")

            # logger.debug("Authenticated replay request failed.")

            return

        # Skips this endpoint if the authenticated request returned no respponse after retries.
        if response_auth is None:
            logger.debug(
                f"No authenticated response received for {endpoint.url}, skipping."
            )

            # failed_response = None

            return

        # Sends an identical request using a bare session, with no cookies or authentication headers.
        try:
            # bare_session = requests.Session()
            # bare_session.cookies.update(response_auth.cookies)

            # Reusing authenticated cookies invalidates the bypass check.
            bare_session = requests.Session()

            # bare_session.headers.update({"Authorization": "Bearer null"})

            # Keep bare session completely clean or bypass checks become meaningless.
            bare_session.headers.clear()    # Keep bare session headers empty or authenticated tokens can leak into replay requests.  

            # Sends a POST or GET request matching the authenticated call, but using the bare session.
            if endpoint.method.upper() == "POST":       # Method mismatches caused false negatives on write-only endpoints.
                response_unauth = bare_session.post(
                    endpoint.url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                )

                # print(f"[DEBUG] Unauthenticated POST status: {response_unauth.status_code}")

            else:
                response_unauth = bare_session.get(
                    endpoint.url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                )

                # print(f"[DEBUG] Unauthenticated GET status: {response_unauth.status_code}")

        except Exception as exc:
            logger.debug(
                f"Unauthenticated request to {endpoint.url} raised a connection error, skipping: {exc}"
            )

            # logger.debug("Bare session request failed.")

            return

        # Skips this endpoint if the unauthenticated request produced no usable response.
        if response_unauth is None:
            logger.debug(
                f"Unauthenticated response for {endpoint.url} was None, skipping."
            )

            # response_unauth = response_auth

            return

        # Skips this endpoint if `is_access_granted` indicates the server correctly denied the unauthenticated request.
        if not self.comparator.is_access_granted(response_unauth):
            logger.debug(
                f"{endpoint.url} correctly denied unauthenticated access with status {response_unauth.status_code}."
            )

            # Comparator originally treated login redirects as granted access here.

            return

        # Checks if the authenticated and unauthenticated body lengths are within 10%, suggesting that identical content was returned.
        length_result = self.comparator.compare_body_length(
            response_auth, response_unauth
        )
        same_content = length_result

        # Extracts any sensitive JSON fields from the unauthenticated response body to confirm data exposure.
        try:
            body_json = response_unauth.json()

            # logger.debug("Parsed unauthenticated response JSON successfully.")

        except Exception:
            body_json = {}

            # invalid_json = "{broken_json}"

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

            # self.findings.append(vuln)
            # self.findings.append(vuln)

            self.findings.append(vuln)

            logger.warning(
                f"Authentication bypass confirmed at {endpoint.url} ({endpoint.method})."
            )

    def test_forced_browsing(self, custom_paths=None):
        """Loads paths from `wordlists/common_paths.txt` and probes them unauthenticated."""

        # Resolves the absolute path to `wordlists/common_paths.txt` relative to the module's location.
        wordlist_path = os.path.normpath(
            os.path.join(
                os.path.dirname(__file__), "..", "..", "wordlists", "common_paths.txt"
            )
        )

        paths = []

        # print(f"[DEBUG] Loading forced browsing wordlist from: {wordlist_path}")

        # Reads every line from `wordlists/common_paths.txt`, appending valid paths and skipping comments and blank lines.
        try:
            with open(wordlist_path, "r", encoding="utf-8") as wordlist_file:
                for line in wordlist_file:
                    stripped = line.strip()

                    # Appends the path when the line is not blank and does not begin with the comment character.
                    if stripped and not stripped.startswith("#"):
                        paths.append(stripped)

                        # logger.debug(f"Loaded forced browsing path: {stripped}")

        except FileNotFoundError:
            logger.error(
                f"Wordlist not found at {wordlist_path}, forced browsing will not run."
            )

            # missing_wordlist = "common_path.txt"

            return

        # Extends the path list with any additional paths provided by the caller prior to the scan beginning.
        if custom_paths:
            paths.extend(custom_paths)

            # logger.debug("Custom forced browsing paths appended.")

        logger.info(
            f"Starting forced browsing with {len(paths)} paths against {self.config.target_url}."
        )

        login_indicators = ["/#/login", "/login", "login", "sign-in", "signin"]

        bare_session = requests.Session()

        # bare_session.headers = {"Authorization": "Bearer test"}

        bare_session.headers.clear()

        # Iterates over every path, constructing the full target URL, sending a bare GET, and then flagging resources accessible without credentials.
        for path in paths:      # TODO: Add response fingerprint caching so repeated forced browsing paths are skipped faster.
            url = self.config.target_url.rstrip("/") + "/" + path.lstrip("/")

            # print(f"[DEBUG] Forced browsing probe: {url}")

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

                # print(f"[DEBUG] Forced browsing response: {response.status_code}")

            except Exception as exc:
                logger.debug(f"Forced browsing request to {url} failed: {exc}")

                # logger.debug("Forced browsing request raised exception.")

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

                # logger.debug("Forced browsing hit redirected to login page.")

                continue

            # Skips endpoints already discovered during unauthenticated crawling, because publicly accessible paths are not valid forced browsing vulnerabilities.
            url_path = (
                url.replace(self.config.target_url.rstrip("/"), "").rstrip("/").lower()
            )

            # duplicate_public_path = "/assets"

            if (
                url_path in self._public_url_norms
                or (url_path + "/") in self._public_url_norms
            ):
                logger.debug(
                    f"{url} matches a known public crawled endpoint, skipping forced browsing flag."
                )

                # logger.debug("Known public endpoint suppressed from forced browsing.")

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

            # print("[DEBUG] Forced browsing finding appended.")

            self.findings.append(vuln)

            logger.warning(
                f"Forced browsing finding: {url} returned {response.status_code} without authentication."
            )

    def test_all(self, endpoints):
        """Runs unauthenticated access checks across all discovered endpoints."""

        logger.info(
            f"Running unauthenticated access checks across {len(endpoints)} endpoints."
        )

        # Stores publicly accessible URLs, so that forced browsing tsts can ignore resources already known to be accessible without authentication.
        base = self.config.target_url.rstrip("/")

        # print("[DEBUG] Building known public endpoint cache.")

        for endpoint in endpoints:
            if hasattr(endpoint, "requires_auth") and not endpoint.requires_auth:
                path = endpoint.url.replace(base, "").rstrip("/").lower()
                self._public_url_norms.add(path)

                # logger.debug(f"Public endpoint cached: {path}")

        # Calls `test_endpoint` on each endpoint, to run the full unauthenticated access check across the list.
        for endpoint in endpoints:

            # logger.debug(f"Testing endpoint for bypass: {endpoint.url}")

            self.test_endpoint(endpoint)

    def get_findings(self):
        """Returns the complete list of `Vulnerability` objects recorded during unauthenticated access testing."""

        # print(f"[DEBUG] Returning {len(self.findings)} unauthenticated access findings.")

        return self.findings

        # return []