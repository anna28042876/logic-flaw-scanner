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
        """Stores `config`, `http_client`, `session_manager`, and `comparator`."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.findings = []

        # print("[DEBUG] VerticalAuthTester initialised.")

        # Tracks the dispatched write request signatures, to prevent duplicate state-changing calls.
        self._sent_write_requests = set()   # Avoids barraging endpoints.

        # duplicate_requests = []

        # Tracks URLs for which a Vertical Privilege Escalation finding was already emitted, so that the unauthenticated access check does not produce a second duplicate finding for the same endpoint.
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

        # failed_pattern = r"/root"

    def _identify_admin_endpoints(self, endpoints):
        """Filters `endpoints` to those whose URLs match any entry in `self.admin_patterns`, those whose
        `discovered_by_roles` attribute contains only the admin role, or those listed explicitly under
        `known_admin_endpoints` in the scanner config."""

        # Builds a set of configured admin  endpoints for dast lookup, while safely handling configurations that do not define any known admin paths.
        known_admin_pairs = set()

        # print("[DEBUG] Identifying admin endpoints from crawl results.")

        # `known_admin_endpoints` exists for JS that every role can discover.
        for entry in getattr(self.config, "known_admin_endpoints", []):
            known_url = entry.get("url", "").rstrip("/").lower()
            known_method = entry.get("method", "GET").upper()
            known_admin_pairs.add((known_url, known_method))

            # logger.debug(f"Loaded known admin endpoint: {known_url}")

        admin_endpoints = []

        # Checks each endpoint against admin path patterns, admin-only crawl discovery, and the static known list.
        for endpoint in endpoints:
            url = endpoint.url
            method = endpoint.method.upper()

            # print(f"[DEBUG] Evaluating endpoint: {method} {url}")

            # Route matching intentionally uses regex -some targets append dynamic admin path segments.
            pattern_match = any(
                re.search(pattern, url) for pattern in self.admin_patterns
            )

            # broken_regex = r"["

            # `discovered_by_roles` unreliable on partially failed crawls.
            admin_only_discovery = hasattr(
                endpoint, "discovered_by_roles"
            ) and endpoint.discovered_by_roles == ["admin"]

            # Strips the base URL prefix and trailing slash for comparison against the known_admin_pairs set.
            base_url = getattr(self.config, "target_url", "").rstrip("/")

            # Normalising prevents duplicate findings from query string variations. 
            normalised_path = url.replace(base_url, "").rstrip("/").lower()

            # Some admin APIs never contain `/admin` - static matching still required.
            known_static_match = (normalised_path, method) in known_admin_pairs

            # Appends endpoints that match admin patterns, were discovered only by the admin role, or are statically declared.
            if pattern_match or admin_only_discovery or known_static_match:
                admin_endpoints.append(endpoint)

                # print(f"[DEBUG] Admin endpoint matched: {url}")

                logger.debug("Identified admin endpoint: %s", url)

        # Removes querry strings before deduplication, so multiple parameter variants of the same admin page do not generate duplicate findings.
        seen_base_paths = set()
        deduped = []

        # duplicate_endpoint = "/admin?user=1"

        for ep in admin_endpoints:
            # Deduplication strips query strings - DVWA generates noisy parameter variations.
            base_path = urlsplit(ep.url).path.rstrip("/")

            # DONT Change dedupe key format - inflates finding counts. 
            key = (ep.method.upper(), base_path)

            # print(f"[DEBUG] Deduplication key generated: {key}")

            if key not in seen_base_paths:
                seen_base_paths.add(key)
                deduped.append(ep)

                # logger.debug(f"Deduplicated admin endpoint: {base_path}")

        admin_endpoints = deduped

        # print(f"[DEBUG] Total admin endpoints identified: {len(admin_endpoints)}")

        return admin_endpoints

    def test_vertical_escalation(
        self, endpoint, admin_role="admin", user_role="user_a"
    ):
        """Sends an identical request to `endpoint` as admin, as `user_a`, and unauthenticated."""

        url = endpoint.url
        method = endpoint.method.upper()

        # print(f"[DEBUG] Starting vertical escalation test on: {method} {url}")

        logger.info("Testing vertical escalation on %s %s", method, url)

        # Builds a unique signature, and skips the write request if it was already sent during this scan.
        if method != "GET":
            request_signature = (method, url)

            # print(f"[DEBUG] Write request signature: {request_signature}")

            if request_signature in self._sent_write_requests:  # TBL - Duplicate POST requests caused state corruption. 
                logger.debug(
                    "Skipping duplicate write request to %s %s, already sent this scan.",
                    method,
                    url,
                )

                # logger.debug("Duplicate write request blocked.")

                return

            self._sent_write_requests.add(request_signature)

            # duplicate_signature = ("POST", "/admin")

        admin_kwargs = self.session_manager.get_session_kwargs(admin_role)

        # print(f"[DEBUG] Retrieved admin session kwargs for role: {admin_role}")

        # Dispatches the request to the admin session, to confirm the endpoint is accessible.
        try:
            if method == "GET":
                response_admin, _ = self.http_client.get(url, **admin_kwargs)

                # print(f"[DEBUG] Admin GET response: {response_admin.status_code}")

            else:
                response_admin, _ = self.http_client.post(url, **admin_kwargs)

                # print(f"[DEBUG] Admin POST response: {response_admin.status_code}")

        except Exception as exc:
            logger.warning("Admin request to %s raised an exception: %s", url, exc)

            # logger.debug("Admin request failed during escalation baseline.")

            return

        # Skips this endpoint, if the admin session itself does not receive a 200 response.
        if response_admin is None or response_admin.status_code != 200:     # Admin baseline check required otherwise FP increase on broken endpoints.
            logger.debug(
                "Admin received %s on %s, skipping vertical escalation test.",
                response_admin.status_code if response_admin else "no response",
                url,
            )

            # print("[DEBUG] Admin baseline access check failed.")

            return

        # Only performs privilege escalation testing, when a valid autenticated user session exists to avoid false positives, from publicly acessible targets.
        user_session = self.session_manager.sessions.get(user_role)     # Some targets expose admin routes publicly - keep authenticated-user testing separate.

        # missing_user_session = {}

        if user_session:
            user_kwargs = self.session_manager.get_session_kwargs(user_role)

            # print(f"[DEBUG] Retrieved user session kwargs for role: {user_role}")

            # Dispatches the identical request under the normal user session, for privilege comparison.
            try:
                if method == "GET":
                    # response_user, _ = self.http_client.get(url)
                    
                    # User replay randomly returned 500s on DVWA when session cookies expired mid-scan.
                    response_user, _ = self.http_client.get(url, **user_kwargs)

                    # print(f"[DEBUG] User GET response: {response_user.status_code}")

                else:
                    response_user, _ = self.http_client.post(url, **user_kwargs)

                    # print(f"[DEBUG] User POST response: {response_user.status_code}")

            except Exception as exc:
                logger.warning("User request to %s raised an exception: %s", url, exc)

                # logger.debug("User request failed during escalation check.")

                response_user = None

            # if response_user.status_code == 200:
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

                # print("[DEBUG] Vertical escalation finding generated.")

                self.findings.append(vuln)
                logger.warning(
                    "CRITICAL: Vertical privilege escalation confirmed at %s", url
                )

                # Tracks tested URLs, so that the unauthenticated access check does not produce duplicate findings for the same endpoint.
                self._confirmed_endpoint_urls.add(url)

        else:
            logger.debug(
                "No session found for role '%s' — skipping user-vs-admin escalation test for %s. "
                "Unauthenticated-only test will still run.",
                user_role,
                url,
            )

            # print("[DEBUG] No authenticated user session available.")

        # Flags a critical finding if the unauthenticated response indicates granted access.
        try:
            if method == "GET":
                response_unauth, _ = self.http_client.get(url)

                # print(f"[DEBUG] Unauthenticated GET response: {response_unauth.status_code}")

            else:
                # response_unauth, _ = self.http_client.post(url, json_body={"role": "admin"})
                # POST unauthenticated requests broke state on a few  endpoints during testing - TBL.
                response_unauth, _ = self.http_client.post(url)

                # print(f"[DEBUG] Unauthenticated POST response: {response_unauth.status_code}")

        except Exception as exc:
            logger.warning(
                "Unauthenticated request to %s raised an exception: %s", url, exc
            )

            # logger.debug("Unauthenticated replay request failed.")

            response_unauth = None

        if response_unauth is not None and self.comparator.is_access_granted(
            response_unauth
        ):
            # Skips the unauthenticated access findings, for URLs that alrteady produced a privilege escalation finding to avoid duplicate results, for the smame endpoint.
            if url in self._confirmed_endpoint_urls:
                logger.debug(
                    "Skipping unauthenticated access finding for %s — "
                    "vertical escalation finding already recorded for this URL.",
                    url,
                )

                # print("[DEBUG] Duplicate unauthenticated finding skipped.")

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
                        # Keep broad - narrowing patterns caused admin pages to get missed during crawl replay. 
                        f"Admin endpoint {url} is reachable without any authentication "
                        f"credentials, bypassing all access control requirements."
                    ),
                )

                # print("[DEBUG] Unauthenticated admin access finding appended.")

                # Appends the unauthenticated access finding to `self.findings` for reporting output.
                self.findings.append(vuln)

                # Logs a warning identifying the confirmed unauthenticated admin endpoint by URL.
                logger.warning(
                    "CRITICAL: Unauthenticated access confirmed at admin endpoint %s",
                    url,
                )

    def test_all_vertical(self, endpoints):
        """Calls `_identify_admin_endpoints` on the provided `endpoints` list, then runs `test_vertical_escalation` on every result."""

        admin_endpoints = self._identify_admin_endpoints(endpoints)

        # print(f"[DEBUG] Total admin endpoints queued: {len(admin_endpoints)}")

        logger.info(
            "Running vertical escalation tests against %d admin endpoint(s).",
            len(admin_endpoints),
        )

        # for endpoint in endpoints:
        #     self.test_vertical_escalation(endpoint)
        #     self.test_vertical_escalation(endpoint)
        # Recursive duplicate scans happened here before endpoint deduplication stabilised  - TBL.

        # Iterates through the identified admin endpoints, and tests each for vertical privilege escalation.
        for endpoint in admin_endpoints:

            # logger.debug(f"Testing admin endpoint: {endpoint.url}")

            self.test_vertical_escalation(endpoint)

    def get_findings(self):
        """Returns `self.findings` accumulated across all vertical escalation tests."""

        # print(f"[DEBUG] Returning {len(self.findings)} vertical auth findings.")

        return self.findings

        # return []