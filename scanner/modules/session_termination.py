"""
`session_termination.py`

Tests whether the session tokens are correctly invalidated after logout on Juice SHop and DVWA. For cookie-based
targets, it replays the old credentials after logout to detect live sessions. For JWT-based targets, such as Juice
Shop, it decodes the token  expiry claim and tests whether the server accepts an expired token, flagging the weak
token lifecycle enforcement.
"""

import copy
import base64
import json
import time

from scanner.core.http_client import HTTPClient
from scanner.core.session_manager import SessionManager
from scanner.core.comparator import ResponseComparator
from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability


logger = get_logger(__name__)


class SessionTerminationValidator:
    """Tests session token invalidation after any logouts, across all non-admin roles on JUice-Shop and DVWA."""

    def __init__(
        self,
        config,
        http_client: HTTPClient,
        session_manager: SessionManager,
        comparator: ResponseComparator,
    ):
        """Stores the injected dependencies and initialises `self.findings` as an empty list for recording
        `Vulnerability` objects found during session termination testing."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.findings = []

    def _find_protected_endpoint(self, role):
        """Sends unauthenticated `GET` requests to the base URL, and common profile paths to find an endpoint
        returning 200 for the given role. This returns the first URL that responds with 200, or None if none of
        the paths succeed."""

        candidates = [
            self.config.target_url.rstrip("/"),
            self.config.target_url.rstrip("/") + "/api/user",
            self.config.target_url.rstrip("/") + "/profile",
            self.config.target_url.rstrip("/") + "/account",
            self.config.target_url.rstrip("/") + "/dashboard",
        ]

        # Iterates over each candidate URL, and returns the first that responds with the status 200 for the assigned role.
        for url in candidates:
            try:
                response = self.http_client.send_request("GET", url, session_key=role)[
                    0
                ]
                # Returns the URL immediately if the authenticated request confirms a 200 response.
                if response is not None and response.status_code == 200:
                    logger.debug(f"Protected endpoint confirmed for role {role}: {url}")
                    return url
            except Exception as exc:
                logger.debug(
                    f"Request to candidate protected endpoint {url} failed for role {role}: {exc}"
                )
                continue

        logger.warning(f"No accessible protected endpoint found for role {role}.")
        return None

    def _find_logout_endpoint(self):
        """Sends unauthenticated `GET` requests to common logout paths,  to identify any server-side logout endpoints. Returns the
        first path that produces a non-404 response, or None if there are no server-side logout endpoints existing on the target."""

        logout_candidates = [
            "/logout",
            "/api/logout",
            "/signout",
            "/api/signout",
            "/auth/logout",
        ]

        # Iterates over common logout paths, and returns the first that receives a non-404 response.
        for path in logout_candidates:
            url = self.config.target_url.rstrip("/") + path
            try:
                response = self.http_client.send_request("GET", url)[0]
                # Returns the URL when the server responds with any status other than 404.
                if response is not None and response.status_code != 404:
                    logger.debug(
                        f"Logout endpoint found at {url} with status {response.status_code}."
                    )
                    return url
            except Exception as exc:
                logger.debug(f"Request to logout candidate {url} failed: {exc}")
                continue

        logger.info(
            "No server-side logout endpoint found. "
            "Juice Shop uses client-side JWT deletion with no server-side token revocation."
        )
        return None

    def _decode_jwt_payload(self, token):
        """Decodes the base64-encoded payload segment of a JWT without any signature verification. Then returns
        the payload as a dictionary, or an empty dictionary if decoding fails."""

        try:
            segments = token.split(".")
            # Raises an error early if the token does not have the expected three-segment JWT structure.
            if len(segments) != 3:
                logger.debug("Token does not have a valid three-segment JWT structure.")
                return {}

            payload_segment = segments[1]
            # Adds padding characters to satisfy base64 decoding requirements before decoding.
            padding = 4 - len(payload_segment) % 4
            if padding != 4:
                payload_segment += "=" * padding

            decoded_bytes = base64.urlsafe_b64decode(payload_segment)
            return json.loads(decoded_bytes.decode("utf-8"))
        except Exception as exc:
            logger.debug(f"JWT payload decoding failed: {exc}")
            return {}

    def _run_jwt_fallback(self, role, session_kwargs):
        """Returns the JWT-specific fallback tst when no server-side logout endpoints exist. Decodes the exp claim, waits for the expiry
        if within 300 seconds, then retests the token. Flags Expired JWT Accepted or JWT Without Expiry findings accordingly."""

        # Extracts the raw JWT string from the Authorisation header stored in `session_kwargs`.
        auth_header = session_kwargs.get("headers", {}).get("Authorization", "")
        # Skips the fallback test if the session does not use a Bearer token.
        if not auth_header.startswith("Bearer "):
            logger.debug(
                f"Role {role} does not use a Bearer token, skipping JWT fallback test."
            )
            return

        token = auth_header[len("Bearer ") :]
        payload = self._decode_jwt_payload(token)

        # Flags the token as having no expiry claim, if the decoded payload doesn't have an exp field.
        if "exp" not in payload:
            vuln = Vulnerability(
                vuln_type="JWT Without Expiry",
                severity="Medium",
                endpoint=self.config.target_url,
                method="GET",
                description=(
                    "The JWT issued to this role has no expiry claim. "
                    "Juice Shop uses client-side-only logout with no server-side token revocation. "
                    "A stolen token remains valid indefinitely."
                ),
                evidence={
                    "role": role,
                    "jwt_payload_keys": list(payload.keys()),
                },
            )
            self.findings.append(vuln)
            logger.warning(f"JWT Without Expiry confirmed for role {role}.")
            return

        exp_timestamp = payload["exp"]
        seconds_until_expiry = exp_timestamp - time.time()

        logger.debug(
            f"JWT for role {role} expires in {seconds_until_expiry:.1f} seconds."
        )

        # Skips the expired token replay test when the wait would exceed 300 seconds, keeping the scan practical.
        if seconds_until_expiry > 300:
            logger.info(
                f"JWT for role {role} expires in {seconds_until_expiry:.0f} seconds. "
                "Expiry wait exceeds 300 seconds, skipping expired token replay."
            )
            return

        # Waits for the token to expire before replaying it against a protected endpoint.
        if seconds_until_expiry > 0:
            logger.info(
                f"Waiting {seconds_until_expiry:.1f} seconds for JWT to expire before replay test."
            )
            time.sleep(seconds_until_expiry + 2)

        protected_url = self._find_protected_endpoint(role)
        # Skips the replay if no protected endpoint could be confirmed for this role.
        if not protected_url:
            logger.debug(
                f"No protected endpoint available for expired token replay on role {role}."
            )
            return

        try:
            import requests as _requests

            replay_session = _requests.Session()
            replay_session.headers.update({"Authorization": f"Bearer {token}"})
            replay_response = replay_session.get(
                protected_url,
                timeout=10,
                verify=self.config.verify_ssl,
            )
        except Exception as exc:
            logger.debug(f"Expired token replay request failed: {exc}")
            return

        # Creates and appends an Expired JWT Accepted vulnerability, if the server returns 200 for the expired token.
        if replay_response is not None and replay_response.status_code == 200:
            vuln = Vulnerability(
                vuln_type="Expired JWT Accepted",
                severity="Medium",
                endpoint=protected_url,
                method="GET",
                description=(
                    "The server accepted an expired JWT. "
                    "Juice Shop uses client-side-only logout with no server-side token revocation."
                ),
                evidence={
                    "role": role,
                    "exp_timestamp": exp_timestamp,
                    "replay_status_code": replay_response.status_code,
                    "replay_body_length": len(replay_response.content),
                },
            )
            self.findings.append(vuln)
            logger.warning(
                f"Expired JWT Accepted confirmed for role {role} at {protected_url}."
            )
        else:
            logger.info(
                f"Expired token correctly rejected for role {role} "
                f"with status {getattr(replay_response, 'status_code', 'no response')}."
            )

    def test_logout_invalidation(self, role="user_a"):
        """Tests whether a session token, for the given role, remains usable after a logout. Deep-copies any pre-logout
        credentials, sends the logout request, then replays the old credentials. Falls back to JWT-specific testing on
        Juice SHop."""

        protected_url = self._find_protected_endpoint(role)
        # ABorts the test early if no protected endpoints can be confirmed for the intended role.
        if not protected_url:
            logger.warning(
                f"Skipping session termination test for role {role}: no protected endpoint found."
            )
            return

        session_kwargs = self.session_manager.get_session_kwargs(role)
        old_session_kwargs = copy.deepcopy(session_kwargs)

        # Confirms that the protected endpoint returns 200, before performing the logout and replay sequence.
        try:
            pre_logout_response = self.http_client.send_request(
                "GET", protected_url, session_key=role
            )[0]
        except Exception as exc:
            logger.warning(
                f"Pre-logout request to {protected_url} failed for role {role}: {exc}"
            )
            return

        # Aborts if the pre-logout baseline requests do not return 200, because the test wouldn't be valid.
        if pre_logout_response is None or pre_logout_response.status_code != 200:
            logger.warning(
                f"Pre-logout baseline for role {role} at {protected_url} "
                f"returned {getattr(pre_logout_response, 'status_code', 'no response')}, aborting test."
            )
            return

        logout_url = self._find_logout_endpoint()

        # Runs the JWT-Specific fallback test, when no server-side logout endpoint is available on the target.
        if logout_url is None:
            logger.info(
                f"Running JWT fallback test for role {role} as no server-side logout endpoint was found."
            )
            self._run_jwt_fallback(role, old_session_kwargs)
            return

        # Sends the logout request using the role's active session, to trigger the server-side invalidation.
        try:
            self.http_client.send_request("GET", logout_url, session_key=role)
        except Exception as exc:
            logger.warning(
                f"Logout request to {logout_url} failed for role {role}: {exc}"
            )

        # Replays the old session credentials against the protected endpoint, after logout to test invalidation.
        try:
            import requests as _requests

            replay_session = _requests.Session()

            old_headers = old_session_kwargs.get("headers", {})
            old_cookies = old_session_kwargs.get("cookies", {})

            # Applies all the header, and cookies, from the pre-logout credentials to the replay session.
            if old_headers:
                replay_session.headers.update(old_headers)
            if old_cookies:
                replay_session.cookies.update(old_cookies)

            post_logout_response = replay_session.get(
                protected_url,
                timeout=10,
                verify=self.config.verify_ssl,
            )
        except Exception as exc:
            logger.warning(
                f"Post-logout replay request to {protected_url} failed for role {role}: {exc}"
            )
            return

        # Skips the findings if the server correctly rejects the replayed credentials with 401, 403, or a redirect.
        if post_logout_response is None:
            logger.debug(
                f"Post-logout response for role {role} was None, skipping finding."
            )
            return

        status = post_logout_response.status_code
        # LOgs a pass result, if the server returns an authentication error or login redirect.
        if status in (401, 403) or (
            status in (301, 302)
            and "login" in post_logout_response.headers.get("Location", "").lower()
        ):
            logger.info(
                f"PASS: Session correctly invalidated on logout for role {role} "
                f"at {protected_url} with status {status}."
            )
            return

        # Checks the post-logout response body for user data fields, prior to confirming the finding.
        try:
            body_json = post_logout_response.json()
        except Exception:
            body_json = {}

        sensitive_fields = self.comparator.extract_sensitive_fields(body_json)

        # Creates, and appends, a 'Session Not Invalidated on Logout' vulnerability, if the server returned 200 with user data.
        if status == 200 and (
            sensitive_fields or len(post_logout_response.content) > 200
        ):
            vuln = Vulnerability(
                vuln_type="Session Not Invalidated on Logout",
                severity="Medium",
                endpoint=protected_url,
                method="GET",
                description="Session token remains valid after logout.",
                evidence={
                    "role": role,
                    "post_logout_status_code": status,
                    "post_logout_body_length": len(post_logout_response.content),
                    "sensitive_fields_present": sensitive_fields,
                },
            )
            self.findings.append(vuln)
            logger.warning(
                f"Session Not Invalidated on Logout confirmed for role {role} at {protected_url}."
            )
        else:
            logger.info(
                f"PASS: No user data returned after logout for role {role} "
                f"at {protected_url} with status {status}."
            )

    def test_all_roles(self):
        """Runs `test_logout_invalidation` for every non-admin role defined in `config.credentials`, covering all standard test
        accounts on Juice Shop DVWA."""

        # Extracts role names from the credentials list, excluding the admin role prior to testing.
        roles = [
            cred["role"]
            for cred in self.config.credentials
            if cred.get("role") != "admin"
        ]

        logger.info(
            f"Running session termination tests for {len(roles)} non-admin roles: {roles}."
        )

        # Calls `test_logout_invalidation` for each non-admin role to test the session invalidation behaviour.
        for role in roles:
            self.test_logout_invalidation(role=role)

    def get_findings(self):
        """Returns the completed list of `Vulnerability` objects, recorded during session termination testing."""
        return self.findings
