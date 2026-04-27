"""
`vertical_auth.py`

Identifies administrator-only endpoints across Juice Shop and DVWA, then replays those requests under a normal
user seession, and an unauthenticated session.  Findings are stored as `Vulnerability` objects, and represents
vertical privilege escalation, and unauthorised access.
"""

import re

from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability

logger = get_logger(__name__)


class VerticalAuthTester:
    """Tests for vertical privilege escataion, by sending admin-only endpoint requests under lower-privileged, and unauthenticated sessions.
    Stores all confirmed findings as `Vulnerability` objects in `self.findings`."""

    def __init__(self, config, http_client, session_manager, comparator):
        """Stores  `config`, `http_client`, `session_manager`, and `comparator`. Then initialises `self.findings`, and defines `self.admin_patterns`
        as regex strings, covering common admin route segments on Juice Shop, and DVWA."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.findings = []
        # Tracks the dispatched write request signatures, to prevent duplicate state-changing calls.
        self._sent_write_requests = set()
        # Defines the regex patterns matching common admin route segments on Juice Shop and DVWA.
        self.admin_patterns = [
            r"/admin",
            r"/manage",
            r"/users/create",
            r"/users/delete",
            r"/settings",
            r"/config",
            r"/roles",
            r"/permissions",
            r"/export",
            r"/import",
            r"/backup",
            r"/logs",
            r"/audit",
        ]

    def _identify_admin_endpoints(self, endpoints):
        """Filters `endpoints` to those which URLs match any entry in `self.admin_patterns`, or those who
        `discovered_by_roles` attribute contains only the admin role, meaning the crawl found them exclusively
        via an admin-authenticated session."""

        admin_endpoints = []
        # Checks each endpoint against admin path patterns, and admin-only crawl discovery.
        for endpoint in endpoints:
            url = endpoint.url
            pattern_match = any(
                re.search(pattern, url) for pattern in self.admin_patterns
            )
            admin_only_discovery = hasattr(
                endpoint, "discovered_by_roles"
            ) and endpoint.discovered_by_roles == ["admin"]
            # Appends endpoints that match admin patterns, or were discovered only by the admin role.
            if pattern_match or admin_only_discovery:
                admin_endpoints.append(endpoint)
                logger.debug("Identified admin endpoint: %s", url)
        return admin_endpoints

    def test_vertical_escalation(
        self, endpoint, admin_role="admin", user_role="user_a"
    ):
        """Sends an identical request to `endpoint` as admin, as `user_a`, and unauthenticated. Creates a critical `Vulnerability` if either
        lower session receives a response that `ResponseComparator` classifies as granted."""

        url = endpoint.url
        method = endpoint.method.upper()
        logger.info("Testing vertical escalation on %s %s", method, url)

        # Builds a unique signature, and skips the write request if it was already sent during this scan.
        if method != "GET":
            request_signature = (method, url)
            if request_signature in self._sent_write_requests:
                logger.debug(
                    "Skipping duplicate write request to %s %s, already sent this scan.",
                    method,
                    url,
                )
                return
            self._sent_write_requests.add(request_signature)

        admin_kwargs = self.session_manager.get_session_kwargs(admin_role)
        # Dispatches the request to the admin session, to confirm the endpoint is accessible.
        try:
            if method == "GET":
                response_admin, _ = self.http_client.get(url, **admin_kwargs)
            else:
                response_admin, _ = self.http_client.post(url, **admin_kwargs)
        except Exception as exc:
            logger.warning("Admin request to %s raised an exception: %s", url, exc)
            return

        # Skips this endpoint, if the admin session itself does not receive a 200 response.
        if response_admin is None or response_admin.status_code != 200:
            logger.debug(
                "Admin received %s on %s, skipping vertical escalation test.",
                response_admin.status_code,
                url,
            )
            return

        user_kwargs = self.session_manager.get_session_kwargs(user_role)
        # Dispatches the identical request under the normal user session, for privilege comparison.
        try:
            if method == "GET":
                response_user, _ = self.http_client.get(url, **user_kwargs)
            else:
                response_user, _ = self.http_client.post(url, **user_kwargs)
        except Exception as exc:
            logger.warning("User request to %s raised an exception: %s", url, exc)
            response_user = None

        # Flags a critical finding if the normal user response indicates granted access.
        if response_user is not None and self.comparator.is_access_granted(
            response_user
        ):
            # Creates a Vulnerability for vertical privilege escalation on Juice Shop, or DVWA.
            vuln = Vulnerability(
                vuln_type="Vertical Privilege Escalation",
                severity="Critical",
                endpoint=url,
                method=method,
                # Records both the normal user, and the admin HTTP status codes, as machine readable evidence.
                evidence=(
                    f"Role `{user_role}` received HTTP {response_user.status_code} "
                    f"on admin endpoint {url}. Admin received "
                    f"{response_admin.status_code}."
                ),
                # Describes the privilege escalation failure.
                description=(
                    f"Normal user `{user_role}` accessed an admin-only endpoint "
                    f"({url}) without elevated privileges, indicating missing "
                    f"server-side authorisation enforcement."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "CRITICAL: Vertical privilege escalation confirmed at %s", url
            )

        # Flags a critical finding if the unauthenticated response indicates granted access.
        try:
            if method == "GET":
                response_unauth, _ = self.http_client.get(url)
            else:
                response_unauth, _ = self.http_client.post(url)
        except Exception as exc:
            logger.warning(
                "Unauthenticated request to %s raised an exception: %s", url, exc
            )
            response_unauth = None

        if response_unauth is not None and self.comparator.is_access_granted(
            response_unauth
        ):
            # Constructs a Critical Vulnerability, for unauthenticated admin access on Juice Shop or DVWA.
            vuln = Vulnerability(
                vuln_type="Unauthenticated Access to Admin Endpoint",
                severity="Critical",
                endpoint=url,
                method=method,
                # Records the HTTP status code, and target URL as machine readable evidence.
                evidence=(
                    f"Unauthenticated request received HTTP "
                    f"{response_unauth.status_code} on admin endpoint {url}."
                ),
                # Describes the access control failure.
                description=(
                    f"Admin endpoint {url} is reachable without any authentication "
                    f"credentials, bypassing all access control requirements."
                ),
            )
            # Appends the unauthenticated access finding to `self.findings` for reporting output.
            self.findings.append(vuln)
            # Logs a warning identifying the confirmed unauthenticated admin endpoint by URL.
            logger.warning(
                "CRITICAL: Unauthenticated access confirmed at admin endpoint %s", url
            )

    def test_all_vertical(self, endpoints):
        """Calls `_identify_admin_endpoints` on the provided `endpoints` list, then runs `test_vertical_escalation` on every result,
        accumulating all findings into `self.findings`."""

        admin_endpoints = self._identify_admin_endpoints(endpoints)
        logger.info(
            "Running vertical escalation tests against %d admin endpoint(s).",
            len(admin_endpoints),
        )
        # Iterates through the identified admin endpoints, and tests each for vertical privilege escalations.
        for endpoint in admin_endpoints:
            self.test_vertical_escalation(endpoint)

    def get_findings(self):
        """Returns `self.findings` accumulated accross all vertical escalation tests."""
        return self.findings
