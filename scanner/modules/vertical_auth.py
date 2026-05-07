"""
`vertical_auth.py`

Identifies administrator-only endpoints across Juice Shop and DVWA, then replays those requests under a normal
user session, and an unauthenticated session. Findings are stored as `Vulnerability` objects, and represents
vertical privilege escalation, and unauthorised access.
"""

import re
from urllib.parse import urlsplit

from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability

logger = get_logger(__name__)


class VerticalAuthTester:
    """Tests for vertical privilege escalation, by sending admin-only endpoint requests under lower-privileged, and unauthenticated sessions.
    Stores all confirmed findings as `Vulnerability` objects in `self.findings`."""

    def __init__(self, config, http_client, session_manager, comparator):
        """Stores `config`, `http_client`, `session_manager`, and `comparator`. Then initialises `self.findings`, and defines `self.admin_patterns`
        as regex strings, covering common admin route segments on Juice Shop, and DVWA."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.findings = []
        # Tracks the dispatched write request signatures, to prevent duplicate state-changing calls.
        self._sent_write_requests = set()
        # Tracks URLs for which a Vertical Privilege Escalation finding was already emitted, so that the
        # unauthenticated access check does not produce a second duplicate finding for the same endpoint.
        self._confirmed_endpoint_urls = set()
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
        """Filters `endpoints` to those whose URLs match any entry in `self.admin_patterns`, those whose
        `discovered_by_roles` attribute contains only the admin role, or those listed explicitly under
        `known_admin_endpoints` in the scanner config. The static list covers endpoints that all crawl
        roles discover equally, such as `/api/Users` and `/api/Complaints` on Juice Shop, which would
        otherwise be missed by the `discovered_by_roles` heuristic."""

        # Builds a set of (url, method) pairs from the config's known_admin_endpoints list for O(1) lookup.
        # `getattr` with an empty list default handles configs that do not define this key, such as dvwa.yaml.
        known_admin_pairs = set()
        for entry in getattr(self.config, "known_admin_endpoints", []):
            known_url = entry.get("url", "").rstrip("/").lower()
            known_method = entry.get("method", "GET").upper()
            known_admin_pairs.add((known_url, known_method))

        admin_endpoints = []
        # Checks each endpoint against admin path patterns, admin-only crawl discovery, and the static known list.
        for endpoint in endpoints:
            url = endpoint.url
            method = endpoint.method.upper()

            pattern_match = any(
                re.search(pattern, url) for pattern in self.admin_patterns
            )
            admin_only_discovery = hasattr(
                endpoint, "discovered_by_roles"
            ) and endpoint.discovered_by_roles == ["admin"]

            # Strips the base URL prefix and trailing slash for comparison against the known_admin_pairs set.
            base_url = getattr(self.config, "target_url", "").rstrip("/")
            normalised_path = url.replace(base_url, "").rstrip("/").lower()
            known_static_match = (normalised_path, method) in known_admin_pairs

            # Appends endpoints that match admin patterns, were discovered only by the admin role, or are statically declared.
            if pattern_match or admin_only_discovery or known_static_match:
                admin_endpoints.append(endpoint)
                logger.debug("Identified admin endpoint: %s", url)

        # Issue 8: Deduplicate by stripping query strings. The crawler stores
        # `security.php`, `security.php?phpids=on`, `security.php?phpids=off`, and
        # `security.php?test=...` as distinct DVWA endpoints, all of which match the
        # admin pattern via /security. Without deduplication every variant generates
        # its own finding for the same underlying page.
        seen_base_paths = set()
        deduped = []
        for ep in admin_endpoints:
            base_path = urlsplit(ep.url).path.rstrip("/")
            key = (ep.method.upper(), base_path)
            if key not in seen_base_paths:
                seen_base_paths.add(key)
                deduped.append(ep)
        admin_endpoints = deduped

        return admin_endpoints

    def test_vertical_escalation(
        self, endpoint, admin_role="admin", user_role="user_a"
    ):
        """Sends an identical request to `endpoint` as admin, as `user_a`, and unauthenticated. Creates a critical `Vulnerability` if either
        lower session receives a response that `ResponseComparator` classifies as granted.

        If no authenticated session exists for `user_role`, the user-vs-admin escalation test is
        skipped entirely. This prevents false positives on single-role targets such as DVWA, where
        only `admin` is configured and `user_a` falls back to an unauthenticated request that DVWA
        (at Low security) accepts for every endpoint."""

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
                response_admin.status_code if response_admin else "no response",
                url,
            )
            return

        # Only tests user-vs-admin escalation when a real authenticated session exists for `user_role`.
        # Falling back to unauthenticated produces false positives on targets such as DVWA at Low security
        # that accept every request without a session.
        user_session = self.session_manager.sessions.get(user_role)
        if user_session:
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
                # Tracks the URL so the unauthenticated access check below does not emit a
                # second overlapping finding for the same endpoint in the same scan run.
                self._confirmed_endpoint_urls.add(url)
        else:
            logger.debug(
                "No session found for role '%s' — skipping user-vs-admin escalation test for %s. "
                "Unauthenticated-only test will still run.",
                user_role,
                url,
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
            # Issue 4: Suppresses the unauthenticated access finding when a vertical privilege
            # escalation finding was already emitted for this URL in the same scan run. Emitting
            # both findings for the same endpoint produces a duplicate that cannot match the same
            # ground truth entry, inflating the false positive count unnecessarily.
            if url in self._confirmed_endpoint_urls:
                logger.debug(
                    "Skipping unauthenticated access finding for %s — "
                    "vertical escalation finding already recorded for this URL.",
                    url,
                )
            else:
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
        # Iterates through the identified admin endpoints, and tests each for vertical privilege escalation.
        for endpoint in admin_endpoints:
            self.test_vertical_escalation(endpoint)

    def get_findings(self):
        """Returns `self.findings` accumulated across all vertical escalation tests."""
        return self.findings