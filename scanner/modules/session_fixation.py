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
    """ Tests session ID regenerations on DVWA, and JWT atomity on Juice Shop, post-authentication."""
    
    def __init__(self, config, http_client: HTTPClient):
        """ Stores `config`, and `http_client`, then initialises `self.findings` as an empty list for recording `Vulnerability` objects 
        found during session fixation testing."""

        self.config = config
        self.http_client = http_client
        self.findings = []

    def _get_login_url(self):
        """ Resolves the login endpoint URL from `config.login_config`. Prepends `config.target_url` if the stored value
        is a relative path, returning a fully qualified URL string."""

        raw = self.config.login_config.get("url", "")
        # Prepends the target base URL, when the login URL stored in `config` is a relative path.
        if raw.startswith("/"):
            return self.config.target_url.rstrip("/") + raw
        return raw

    def _get_session_cookie_name(self):
        """ Sends a GET request to the target login page using a fresh `requests.Session`, and inspects the response cookies. Then returns
        the name of the first recognised session cookie, or NOne, if no known session cookie is present on the target."""

        known_names = ["PHPSESSID", "sessionid", "JSESSIONID", "connect.sid", "token", "session"]
        login_url = self._get_login_url()

        # Skips cookie detection if no login URL can be resolved from `config`.
        if not login_url:
            logger.warning("No login URL found in `config.login_config`, cannot detect session cookie.")
            return None

        try:
            probe_session = requests.Session()
            response = probe_session.get(
                login_url,
                timeout=10,
                verify=self.config.verify_ssl,
            )
            # Iterates over all the cookies in the response, and returns the first name that matches a known session cookie.
            for cookie_name in response.cookies.keys():
                if cookie_name in known_names:
                    logger.debug(f"Session cookie detected on target: {cookie_name}")
                    return cookie_name
        except Exception as exc:
            logger.warning(f"GET request to login page {login_url} failed during cookie detection: {exc}")

        logger.info(
            "No recognised session cookie found on target. "
            "Juice Shop uses JWT bearer tokens with no server-side session cookies."
        )
        return None

    def _authenticate_fresh(self, role="user_a"):
        """ Performs a direct POST to the login endpoint using the credentials from `config` for the specified role. Then tries 
        JSON and form-encoded formats. Then returns the raw JWT string, if found in the response body or headers, or None if 
        authentication fails."""
        login_url = self._get_login_url()
        role_credentials = self.config.credentials.get(role, {})
        username = role_credentials.get("username", role_credentials.get("email", ""))
        password = role_credentials.get("password", "")

        # Skipos authentication if no login URL, or credentials, are available in `config`.
        if not login_url or not username:
            logger.warning(
                f"Cannot perform fresh authentication for role {role}: missing login URL or credentials."
            )
            return None

        # Attempts a JSON POST to the Juice SHop login endpoint first, then falls back to form-encoded for DVWA.
        for attempt in ("json", "form"):
            try:
                fresh_session = requests.Session()
                if attempt == "json":
                    response = fresh_session.post(
                        login_url,
                        json={"email": username, "password": password},
                        timeout=10,
                        verify=self.config.verify_ssl,
                    )
                else:
                    response = fresh_session.post(
                        login_url,
                        data={
                            self.config.login_config.get("username_field", "email"): username,
                            self.config.login_config.get("password_field", "password"): password,
                        },
                        timeout=10,
                        verify=self.config.verify_ssl,
                    )

                # Skips to the next attempt format if the server rejected the credentials.
                if response.status_code not in (200, 201):
                    continue
                
                # Tries to extract the JWT from common Juice SHop response body locations.
                try:
                    body = response.json()
                    token = (
                        body.get("token")
                        or body.get("authentication", {}).get("token")
                        or body.get("access_token")
                    )
                    if token:
                        return token
                except Exception:
                    pass

                # Falls back to checking the Authorisation response header, if no token was found in the body.
                auth_header = response.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    return auth_header[len("Bearer "):]

            except Exception as exc:
                logger.debug(f"Fresh authentication attempt ({attempt}) for role {role} failed: {exc}")
                continue

        logger.warning(f"Fresh authentication returned no token for role {role}.")
        return None

    def _run_jwt_reuse_test(self):
        """ Authenticates twice with the same `user_a` credentials, to capture `token_A`, and `token_B`. Flags a security concern
        if both tokens are identical. COnfiirms that `token_A` still grants access to a protected endpoint, logging the result as 
        a PASS, or an informational finding."""

        logger.info(
            "No session cookie found on target. "
            "Running JWT reuse test in place of traditional session fixation test."
        )

        token_a = self._authenticate_fresh(role="user_a")
        token_b = self._authenticate_fresh(role="user_a")

        # Aborts the JWT reuse test, if either authentication attempt failed to return a token.
        if not token_a or not token_b:
            logger.warning(
                "JWT reuse test aborted: one or both authentication attempts returned no token."
            )
            return

        # Flags a token reuse vulnerability, if both authentication calls returned the same JWT value.
        if token_a == token_b:
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
            self.findings.append(vuln)
            logger.warning("JWT Token Reuse confirmed: both authentication calls returned the same token.")
        else:
            logger.info("PASS: Server issued distinct JWT tokens for separate authentication calls.")

        # Verifies that `token_A` still grants access to a protected endpoint, after `token_B` has been issued.
        protected_candidates = [
            self.config.target_url.rstrip("/") + "/rest/user/whoami",
            self.config.target_url.rstrip("/") + "/api/user",
            self.config.target_url.rstrip("/"),
        ]

        # Iterates over candidate protected URLss, sending `token_A`, and logs whether the JWT remains valid.
        for url in protected_candidates:
            try:
                replay_session = requests.Session()
                replay_session.headers.update({"Authorization": f"Bearer {token_a}"})
                replay_response = replay_session.get(
                    url,
                    timeout=10,
                    verify=self.config.verify_ssl,
                )
                # Logs the result, and stops checking candidates once a 200 response confirms that the token is still valid.
                if replay_response.status_code == 200:
                    logger.info(
                        f"PASS: token_A remains valid after token_B was issued. "
                        f"Confirmed at {url} with status 200."
                    )
                    return
            except Exception as exc:
                logger.debug(f"token_A replay request to {url} failed: {exc}")
                continue

        logger.info("token_A replay test inconclusive: no candidate protected endpoint returned 200.")

    def test_fixation(self):
        """ Dispatches to the JWT reuse test if no session cookie exists on the target, or runs the usual PHPSESSID fixation test
        for DVWA, by comparing session IDs prior, and post, authentication within the same `requests.Session`."""

        cookie_name = self._get_session_cookie_name()

        # Runs the JWT reuse test, when the target has no server-side session cookie, as is the case for Juice Shop.
        if cookie_name is None:
            self._run_jwt_reuse_test()
            return

        login_url = self._get_login_url()
        role_credentials = self.config.credentials.get("user_a", {})
        username = role_credentials.get("username", role_credentials.get("email", ""))
        password = role_credentials.get("password", "")

        # Creates a fresh session, GETs the login page, and extracts the pre-authentication session ID.
        fixation_session = requests.Session()
        try:
            fixation_session.get(
            login_url,
            timeout=10,
            verify=self.config.verify_ssl,
        )
        except Exception as exc:
            logger.warning(f"GET to login page {login_url} failed during fixation test: {exc}")
            return

        pre_auth_id = fixation_session.cookies.get(cookie_name)

        # Aborts the test if no session cookie was set by the server on the pre-authentication GET request.
        if not pre_auth_id:
            logger.warning(
                f"No {cookie_name} cookie found after GET to {login_url}. "
                "Cannot complete session fixation test."
            )
            return

        logger.debug(f"Pre-authentication {cookie_name} recorded.")

        # POSTs login credentials, using the same session to preserve the pre-authentication cookie.
        try:
            fixation_session.post(
                login_url,
                data={
                    self.config.login_config.get("username_field", "username"): username,
                    self.config.login_config.get("password_field", "password"): password,
                },
                timeout=10,
                verify=self.config.verify_ssl,
            )
        except Exception as exc:
            logger.warning(f"POST login to {login_url} failed during fixation test: {exc}")
            return

        # Extracts the session cookie from the same session after authentication, to capture the post-login ID.
        post_auth_id = fixation_session.cookies.get(cookie_name)

        # Aborts if no session cookie is present after login, as the comparison cannot be completed.
        if not post_auth_id:
            logger.warning(
                f"No {cookie_name} cookie found after POST login to {login_url}. "
                "Cannot complete session fixation comparison."
            )
            return

        logger.debug(f"Post-authentication {cookie_name} recorded.")

        # COmpares pre, and post, authentication session IDs, to detect whether the server regenerated the session.
        if pre_auth_id == post_auth_id:
            vuln = Vulnerability(
                vuln_type="Session Fixation",
                severity="High",
                endpoint=login_url,
                method="POST",
                description="Session ID is not regenerated upon authentication.",
                evidence={
                    "pre_auth_session_id": pre_auth_id,
                    "post_auth_session_id": post_auth_id,
                    "cookie_name": cookie_name,
                },
            )
            self.findings.append(vuln)
            logger.warning(
                f"Session Fixation confirmed: {cookie_name} was not regenerated after login at {login_url}."
            )
        else:
            logger.info(
                f"PASS: {cookie_name} was correctly regenerated after authentication at {login_url}."
            )

    def get_findings(self):
       # Returns the complete list of `Vulnerability` objects,, recorded during the session fixation testing.
        return self.findings