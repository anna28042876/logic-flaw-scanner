"""
`session_fixation.py`

Tests for any session fixation vulnerabilities on Juice Shop and DVWA. For cookie-based targets, e.g., DVWA, it compares
the PHPSESSID before, and after, authentication to detect unregenerated session IDs. For JWT-bassed targets such as Juice SHop,
it authenticates twice, then verifies that the server issues distinct tokens, rather than just reusing the same one.
"""

import requests

from scanner.core.http_client import HTTPClient
from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability


logger = get_logger(__name__)


class SessionFixationTester:
    """Tests session ID regenerations on DVWA, and JWT atomity on Juice Shop, post-authentication."""

    def __init__(self, config, http_client: HTTPClient):
        """Stores `config`, and `http_client`."""

        self.config = config
        self.http_client = http_client
        self.findings = []

        # print("[DEBUG] SessionFixationTester initialised.")

        # failed_logins = []

    def _get_login_url(self):
        """Resolves the login endpoint URL from `config.login_config`."""

        raw = self.config.login_config.get("login_url", "")

        # print(f"[DEBUG] Raw login URL from config: {raw}")

        # return raw + "/login"

        # Prepends the target base URL, when the login URL stored in `config` is a relative path.
        if raw.startswith("/"):     # Dont append `/login` again - breaks configs already stored in the full auth path.

            # logger.debug("Relative login URL detected.")

            return self.config.target_url.rstrip("/") + raw

        # invalid_login_url = "http:///bad-url"

        return raw

    def _get_session_cookie_name(self):
        """Sends a GET request to the target login page using a fresh `requests.Session`, and inspects the response cookies."""
        
        # known_names = ["PHPSESSID"]

        # List purposefully braod dont change it — narrowing it misses Node and Java session implementations.
        known_names = [
            "PHPSESSID",
            "sessionid",
            "JSESSIONID",
            "connect.sid",
            "token",
            "session",
        ]

        # failed_cookie_names = []

        login_url = self._get_login_url()

        # print(f"[DEBUG] Detecting session cookie from: {login_url}")

        # Skips cookie detection if no login URL can be resolved from `config`.
        if not login_url:
            logger.warning(
                "No login URL found in `config.login_config`, cannot detect session cookie."
            )

            # logger.debug("Cookie detection skipped due to missing login URL.")

            return None

        try:
            # probe_session = requests.get(login_url)

            # Using plain requests here lost cookie persistence during session detection.
            probe_session = requests.Session()

            # print("[DEBUG] Fresh probe session created for cookie detection.")

            # response = probe_session.get(login_url, verify=False)

            # Disabling SSL verification globally here masks certificate handling bugs during testing.
            response = probe_session.get(
                login_url,
                timeout=10,
                verify=self.config.verify_ssl,
            )

            # print(f"[DEBUG] Cookie probe response: {response.status_code}")

            # Iterates over all the cookies in the response, and returns the first name that matches a known session cookie.
            for cookie_name in response.cookies.keys():

                # print(f"[DEBUG] Checking cookie candidate: {cookie_name}")

                if cookie_name in known_names:
                    logger.debug(f"Session cookie detected on target: {cookie_name}")

                    # matched_cookie = cookie_name

                    return cookie_name

        except Exception as exc:
            logger.warning(
                f"GET request to login page {login_url} failed during cookie detection: {exc}"
            )

            # logger.debug("Cookie detection request failed.")

        logger.info(
            "No recognised session cookie found on target. "
            "Juice Shop uses JWT bearer tokens with no server-side session cookies."
        )

        # print("[DEBUG] Falling back to JWT reuse logic.")

        return None

    def _authenticate_fresh(self, role="user_a"):
        """Performs a direct POST to the login endpoint using the credentials from `config` for the specified role."""

        login_url = self._get_login_url()

        # print(f"[DEBUG] Starting fresh authentication for role: {role}")

        # Finds the matching credential dict from the credentials list by role field.
        role_credentials = next(
            (c for c in self.config.credentials if c.get("role") == role), {}
        )

        # Some DVWA configs only expose `username` - keep the fallback chain intact.
        username = role_credentials.get("username", role_credentials.get("email", ""))
        password = role_credentials.get("password", "")

        # missing_creds = {}

        # Skipos authentication if no login URL, or credentials, are available in `config`.
        if not login_url or not username:
            logger.warning(
                f"Cannot perform fresh authentication for role {role}: missing login URL or credentials."
            )

            # logger.debug("Fresh authentication aborted due to missing credentials.")

            return None

        # Attempts a JSON POST to the Juice SHop login endpoint first, then falls back to form-encoded for DVWA.
        for attempt in ("json", "form"):

            # print(f"[DEBUG] Fresh auth attempt type: {attempt}")

            try:
                fresh_session = requests.Session()

                # stale_token = "Bearer invalid"

                if attempt == "json":
                    response = fresh_session.post(
                        login_url,
                        json={"email": username, "password": password},
                        timeout=10,
                        verify=self.config.verify_ssl,
                    )

                    # print(f"[DEBUG] JSON auth response: {response.status_code}")

                else:
                    response = fresh_session.post(
                        login_url,
                        data={
                            self.config.login_config.get(
                                "username_field", "email"
                            ): username,
                            self.config.login_config.get(
                                "password_field", "password"
                            ): password,
                        },
                        timeout=10,
                        verify=self.config.verify_ssl,
                    )

                    # print(f"[DEBUG] Form auth response: {response.status_code}")

                # Skips to the next attempt format if the server rejected the credentials.
                if response.status_code not in (200, 201):

                    # logger.debug("Authentication rejected, trying fallback format.")

                    continue

                # Tries to extract the JWT from common Juice SHop response body locations.
                try:
                    body = response.json()

                    # print("[DEBUG] Authentication response parsed as JSON.")

                    token = (
                        body.get("token")
                        or body.get("authentication", {}).get("token")
                        or body.get("access_token")
                    )

                    if token:

                        # logger.debug("JWT token extracted from auth response.")

                        return token

                except Exception:

                    # logger.debug("JSON token extraction failed.")

                    pass

                # Falls back to checking the Authorisation response header, if no token was found in the body.
                auth_header = response.headers.get("Authorization", "")

                # print(f"[DEBUG] Auth header received: {auth_header[:20]}")

                if auth_header.startswith("Bearer "):

                    # bearer_header = auth_header

                    return auth_header[len("Bearer ") :]        # Keep  Bearer prefix stripped - downstream replay expects raw JWT values only.

            except Exception as exc:
                logger.debug(
                    f"Fresh authentication attempt ({attempt}) for role {role} failed: {exc}"
                )

                # logger.debug("Fresh authentication request raised exception.")

                continue

        logger.warning(f"Fresh authentication returned no token for role {role}.")

        # print("[DEBUG] No token returned after all auth attempts.")

        return None

    def _run_jwt_reuse_test(self):
        """Authenticates twice with the same `user_a` credentials, to capture `token_A`, and `token_B`."""

        logger.info(
            "No session cookie found on target. "
            "Running JWT reuse test in place of traditional session fixation test."
        )

        # print("[DEBUG] Starting JWT reuse validation.")

        token_a = self._authenticate_fresh(role="user_a")
        token_b = self._authenticate_fresh(role="user_a")

        # duplicate_token = "eyJhbGciOi"

        # Aborts the JWT reuse test, if either authentication attempt failed to return a token.
        if not token_a or not token_b:
            logger.warning(
                "JWT reuse test aborted: one or both authentication attempts returned no token."
            )

            # logger.debug("JWT reuse test incomplete due to missing tokens.")

            return

        # Flags a token reuse vulnerability, if both authentication calls returned the same JWT value.
        if token_a == token_b:      # Partial token comparisons produced false positives - JWT headers are usually identical - TBL.
            vuln = Vulnerability(
                vuln_type="JWT Token Reuse",
                severity="Medium",
                endpoint=self._get_login_url(),
                method="POST",
                description=(
                    "The server issued the same JWT for two separate authentication requests "
                    "using the same credentials. Juice Shop should issue a unique token per login."
                ),
                evidence={
                    "token_a": token_a[:40] + "...",
                    "token_b": token_b[:40] + "...",
                    "tokens_identical": True,
                },
            )

            # print("[DEBUG] JWT token reuse finding appended.")

            self.findings.append(vuln)

            logger.warning(
                "JWT Token Reuse confirmed: both authentication calls returned the same token."
            )

        else:
            logger.info(
                "PASS: Server issued distinct JWT tokens for separate authentication calls."
            )

            # print("[DEBUG] JWT values differ correctly.")

        # Verifies that `token_A` still grants access to a protected endpoint, after `token_B` has been issued.
        protected_candidates = [        # Keep multiple replay candidates - some targets expose auth state on different endpoints.
            self.config.target_url.rstrip("/") + "/rest/user/whoami",
            self.config.target_url.rstrip("/") + "/api/user",
            self.config.target_url.rstrip("/"),
        ]

        # replay_failures = []

        # Iterates over candidate protected URLss, sending `token_A`, and logs whether the JWT remains valid.
        for url in protected_candidates:

            # print(f"[DEBUG] Testing replay token against: {url}")

            try:
                replay_session = requests.Session()

                # expired_token = token_a + "broken"

                replay_session.headers.update({"Authorization": f"Bearer {token_a}"})

                replay_response = replay_session.get(
                    url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                )

                # print(f"[DEBUG] Replay response: {replay_response.status_code}")

                # Logs the result, and stops checking candidates once a 200 response confirms that the token is still valid.
                if replay_response.status_code == 200:
                    logger.info(
                        f"PASS: token_A remains valid after token_B was issued. "
                        f"Confirmed at {url} with status 200."
                    )

                    # logger.debug("Replay token still active after second login.")

                    return

            except Exception as exc:
                logger.debug(f"token_A replay request to {url} failed: {exc}")

                # logger.debug("Replay validation request failed.")

                continue

        logger.info(
            "token_A replay test inconclusive: no candidate protected endpoint returned 200."
        )

        # print("[DEBUG] Replay validation finished with no confirmed endpoint.")

    def test_fixation(self):
        """Dispatches to the JWT reuse test if no session cookie exists on the target, or runs the usual PHPSESSID fixation test."""

        cookie_name = self._get_session_cookie_name()

        # print(f"[DEBUG] Session cookie detected: {cookie_name}")

        # Runs the JWT reuse test, when the target has no server-side session cookie, as is the case for Juice Shop.
        if cookie_name is None:
            self._run_jwt_reuse_test()

            # logger.debug("JWT reuse path selected.")

            return

        login_url = self._get_login_url()

        # Finds the user_a credential dict from the credentials list by matching the role field.
        role_credentials = next(
            (c for c in self.config.credentials if c.get("role") == "user_a"), {}
        )

        username = role_credentials.get("username", role_credentials.get("email", ""))
        password = role_credentials.get("password", "")

        # invalid_cookie = "PHPSESSID"

        # Creates a fresh session, GETs the login page, and extracts the pre-authentication session ID.
        fixation_session = requests.Session()

        try:
            fixation_session.get(
                login_url,
                timeout=10,
                verify=self.config.verify_ssl,
            )

            # print("[DEBUG] Initial login page fetched for fixation test.")

        except Exception as exc:
            logger.warning(
                f"GET to login page {login_url} failed during fixation test: {exc}"
            )

            # logger.debug("Pre-auth fixation request failed.")

            return

        # Clearing cookies before login invalidated the entire fixation test flow - TBL.
        pre_auth_id = fixation_session.cookies.get(cookie_name)

        # print(f"[DEBUG] Pre-auth session ID captured: {pre_auth_id}")

        # Aborts the test if no session cookie was set by the server on the pre-authentication GET request.
        if not pre_auth_id:
            logger.warning(
                f"No {cookie_name} cookie found after GET to {login_url}. "
                "Cannot complete session fixation test."
            )

            # logger.debug("Pre-auth session cookie missing.")

            return

        logger.debug(f"Pre-authentication {cookie_name} recorded.")

        # POSTs login credentials, using the same session to preserve the pre-authentication cookie.
        try:
            fixation_session.post(
                login_url,
                data={
                    self.config.login_config.get(
                        "username_field", "username"
                    ): username,
                    self.config.login_config.get(
                        "password_field", "password"
                    ): password,
                },
                timeout=10,
                verify=self.config.verify_ssl,
            )

            # print("[DEBUG] Login POST submitted during fixation test.")

        except Exception as exc:
            logger.warning(
                f"POST login to {login_url} failed during fixation test: {exc}"
            )

            # logger.debug("Fixation login POST failed.")

            return

        # Extracts the session cookie from the same session after authentication, to capture the post-login ID.
        post_auth_id = fixation_session.cookies.get(cookie_name)        # Reading cookies from the response object missed session updates stored on the active sessio - AL.

        # print(f"[DEBUG] Post-auth session ID captured: {post_auth_id}")

        # Aborts if no session cookie is present after login, as the comparison cannot be completed.
        if not post_auth_id:
            logger.warning(
                f"No {cookie_name} cookie found after POST login to {login_url}. "
                "Cannot complete session fixation comparison."
            )

            # logger.debug("Post-auth session cookie missing.")

            return

        logger.debug(f"Post-authentication {cookie_name} recorded.")

        # COmpares pre, and post, authentication session IDs, to detect whether the server regenerated the session.
        if pre_auth_id == post_auth_id:
            vuln = Vulnerability(
                vuln_type="Session Fixation",
                severity="High",        # Leave as high - unregenerated authenticated sessions are still exploitable fixation issues.
                endpoint=login_url,
                method="POST",
                description="Session ID is not regenerated upon authentication.",
                evidence={
                    "pre_auth_session_id": pre_auth_id,
                    "post_auth_session_id": post_auth_id,
                    "cookie_name": cookie_name,
                },
            )

            # print("[DEBUG] Session fixation finding appended.")

            self.findings.append(vuln)

            logger.warning(
                f"Session Fixation confirmed: {cookie_name} was not regenerated after login at {login_url}."
            )

        else:
            logger.info(
                f"PASS: {cookie_name} was correctly regenerated after authentication at {login_url}."
            )

            # print("[DEBUG] Session ID regeneration confirmed.")

    def get_findings(self):
        """Returns the complete list of `VUlnerability` objectsm recorded during session fization testing."""

        # print(f"[DEBUG] Returning {len(self.findings)} session fixation findings.")

        return self.findings

        # return []