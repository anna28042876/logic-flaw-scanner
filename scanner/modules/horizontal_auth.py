"""
`horizontal_auth.py`

Tests for IDOR and BOLA vulnerabilities across Juice Shop, and DVWA, by comparing responses between `user_a`, and `user_b` sessions.
Implements three test types: reads access using cross-role resource ID substitution, write access using cross-role modification requests,
and sequential ID enumeration. Uses `ResponseComparator`, and `CSRFExtractor` throughout.
"""

import re

from scanner.core.http_client import HTTPClient
from scanner.core.session_manager import SessionManager
from scanner.core.comparator import ResponseComparator
from scanner.core.csrf import CSRFExtractor
from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability

# Compiles module-level regex patterns for UUID detection, numeric ID validation, and numeric URL segment matching.
logger = get_logger(__name__)

# Matches a standard UUID format string, to detect non-sequential IDs that cannot be enumerated.
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Matches a string containing only digits to confirm a resource ID is numeric, and safe to increment.
NUMERIC_ID_PATTERN = re.compile(r"^\d+$")
# Matches a forward slash followed by one or more digits, in a URL path to locate numeric resource ID segments.
URL_NUMERIC_SEGMENT_PATTERN = re.compile(r"/\d+")

# REST collection path patterns whose individual items are user-scoped. Matches Juice Shop API
# collections (/api/Users, /api/BasketItems, /api/Feedbacks, etc.) and DVWA query-param endpoints
# whose responses contain per-user records. The heuristic is intentionally broad: false positives
# are filtered downstream by the ID-extraction strategies in `_get_user_resource_id`.
USER_SCOPED_COLLECTION_PATTERNS = re.compile(
    r"/api/(Users|BasketItems|Feedbacks|Complaints|Recycles|Addresss|Cards|Deliverys)"
    r"|/rest/(user|wallet|order-history|memories)"
    r"|/vulnerabilities/(brute|sqli|sqli_blind|xss_r|xss_s|csrf|captcha|weak_id)",
    re.IGNORECASE,
)


class HorizontalAuthTester:
    """Tests IDOR, and BOLA vulnerabilities by substituting resource IDs across `user_a`, and `user_b` sessions."""

    def __init__(
        self,
        config,
        http_client: HTTPClient,
        session_manager: SessionManager,
        comparator: ResponseComparator,
    ):
        """Stores all the injected dependencies, and initialises `self.findings` as an empty list for recording `Vulnerability`
        objects found during horizontal authorisation testing."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.comparator = comparator
        self.csrf_extractor = CSRFExtractor()
        self.findings = []

    def _identify_user_specific_endpoints(self, endpoints, endpoint_params):
        """Filters through the provided endpoint list, to those likely to involve per-user resources.

        Three criteria are applied in order — any one is sufficient for inclusion:
        1. The URL contains a numeric path segment (e.g. /api/Users/5), indicating a direct
           object reference.
        2. The URL matches a known user-scoped collection pattern (Juice Shop API collections,
           DVWA vulnerability pages with per-user state).
        3. At least one parameter in `endpoint_params` is flagged as `is_id_field`.

        `endpoint_params` is keyed by URL string (as produced by `ParameterEnumerator`), not by
        (method, url) tuple. The previous (method, url) lookup always returned an empty list,
        which caused criterion 3 to never fire."""

        user_specific = []

        # Iterates over all endpoints, and includes those with an ID parameter, or a numeric URL segment.
        for endpoint in endpoints:
            url = endpoint.url

            # Criterion 1: numeric path segment indicates a direct object reference.
            if URL_NUMERIC_SEGMENT_PATTERN.search(url):
                user_specific.append(endpoint)
                continue

            # Criterion 2: URL matches a known user-scoped collection on Juice Shop or DVWA.
            if USER_SCOPED_COLLECTION_PATTERNS.search(url):
                user_specific.append(endpoint)
                continue

            # Criterion 3: at least one known parameter is flagged as an ID field.
            # `endpoint_params` is keyed by URL string, not (method, url) tuple.
            params = endpoint_params.get(url, [])
            if any(getattr(p, "is_id_field", False) for p in params):
                user_specific.append(endpoint)

        logger.info(
            f"Identified {len(user_specific)} user-specific endpoints from {len(endpoints)} total."
        )
        return user_specific

    def _extract_id_from_body(self, body):
        """Searches a parsed JSON response body for a numeric ID value at the top level, or nested
        one level deep under common wrapper keys. Returns the first matching numeric ID as a string,
        or None if no ID field is found.

        Handles two common Juice Shop response shapes: the direct `{"id": N}` shape used by most
        endpoints, and the `{"data": {"id": N}}` and `{"user": {"id": N}}` wrapper shapes used by
        collection endpoints and `/rest/user/whoami` respectively."""

        if not isinstance(body, dict):
            return None

        # Checks the top-level body first for a direct id field.
        for key, value in body.items():
            if key.lower() in ("id", "userid", "user_id") and str(value).isdigit():
                return str(value)

        # Checks one level deeper under common Juice Shop wrapper keys: data, user, and result.
        for wrapper_key in ("data", "user", "result"):
            nested = body.get(wrapper_key)
            if isinstance(nested, dict):
                for key, value in nested.items():
                    if key.lower() in ("id", "userid", "user_id") and str(value).isdigit():
                        return str(value)

        return None

    def _get_user_resource_id(self, endpoint, role):
        """Attempts three strategies to find a resource ID owned by the specified role. Self-referencing API endpoints, crawled JSON
        list endpoints, then config-provided known IDs. Returns the first ID found as a string, or None if all three strategies fail."""

        # Strategy 1 tries Juice Shop and common self-referencing API paths, to extract the role's own numeric ID.
        # `/rest/user/whoami` is tried first because Juice Shop returns `{"user": {"id": N}}` from that endpoint,
        # and in Juice Shop v17.1.1 the basket ID equals the user ID, making the whoami ID directly usable
        # for basket, feedback, and review IDOR tests.
        self_ref_paths = [
            "/rest/user/whoami",
            "/api/Users/whoami",
            "/api/me",
            "/api/profile",
            "/api/user",
        ]

        # Iterates over each self-referencing path, and returns the first numeric ID field found in the JSON response.
        for path in self_ref_paths:
            url = self.config.target_url.rstrip("/") + path
            try:
                response = self.http_client.send_request("GET", url, session_key=role)[0]
                # Skips this path if no response was received, or the server did not return 200.
                if response is None or response.status_code != 200:
                    continue
                try:
                    body = response.json()
                    found_id = self._extract_id_from_body(body)
                    if found_id:
                        logger.debug(
                            f"Resource ID for role {role} found via self-referencing path {path}: {found_id}"
                        )
                        return found_id
                except Exception:
                    pass
            except Exception as exc:
                logger.debug(
                    f"Self-referencing path {path} failed for role {role}: {exc}"
                )

        # Strategy 2 tries the endpoint itself as a list resource, and cross-references returned IDs with the role's email.
        # Finds the matching credential dict from the credentials list by role field.
        role_credentials = next(
            (c for c in self.config.credentials if c.get("role") == role), {}
        )
        role_email = role_credentials.get("email", role_credentials.get("username", ""))

        try:
            response = self.http_client.send_request(
                "GET", endpoint.url, session_key=role
            )[0]
            # Skips strategy 2 if there are no valid JSON array responses returned from the endpoint.
            if response is not None and response.status_code == 200:
                try:
                    body = response.json()
                    # Iterates over items in a JSON array response, then matches each email field against the role's known email.
                    if isinstance(body, list):
                        for item in body:
                            if isinstance(item, dict):
                                item_email = item.get("email", item.get("username", ""))
                                item_id = item.get("id")
                                # Returns the item ID when the email field matches the role's known identifier.
                                if (
                                    item_email
                                    and role_email
                                    and item_email == role_email
                                    and item_id
                                ):
                                    logger.debug(
                                        f"Resource ID for role {role} found via list endpoint {endpoint.url}: {item_id}"
                                    )
                                    return str(item_id)
                    # Also handles a wrapped list response under a `data` key.
                    elif isinstance(body, dict):
                        data = body.get("data", [])
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    item_email = item.get("email", item.get("username", ""))
                                    item_id = item.get("id")
                                    if (
                                        item_email
                                        and role_email
                                        and item_email == role_email
                                        and item_id
                                    ):
                                        logger.debug(
                                            f"Resource ID for role {role} found via wrapped list at {endpoint.url}: {item_id}"
                                        )
                                        return str(item_id)
                except Exception:
                    pass
        except Exception as exc:
            logger.debug(
                f"List endpoint strategy 2 lookup failed for role {role} at {endpoint.url}: {exc}"
            )

        # Strategy 3 falls back to any manually specified IDs in the optional `known_resource_ids` section of config.
        known_ids = getattr(self.config, "known_resource_ids", {})
        # Iterates over all resource type entries for the role in `config.known_resource_ids`, and returns the first found.
        if role in known_ids:
            for resource_type, resource_id in known_ids[role].items():
                if resource_id:
                    logger.debug(
                        f"Resource ID for role {role} found via config known_resource_ids ({resource_type}): {resource_id}"
                    )
                    return str(resource_id)

        # All three strategies failing is expected on single-role targets such as DVWA where user_a and user_b are not configured.
        logger.debug(
            f"All three ID extraction strategies failed for role {role} at {endpoint.url}."
        )
        return None

    def _build_url_with_id(self, endpoint, id_value):
        """Substitutes the first numeric segment in the endpoint URL with `id_value`, then returns the modified URL string, or
        the original URL if no numeric segment is found."""

        substituted = URL_NUMERIC_SEGMENT_PATTERN.sub(
            f"/{id_value}", endpoint.url, count=1
        )
        return substituted

    def test_idor_read(self, endpoint, id_param, role_a="user_a", role_b="user_b"):
        """Tests whether `role_b` can read a resource owned by `role_a`, by substituting `role_a`'s resource ID into a request sent
        with `role_b`'s session. Also tests the reverse, and flags critical IDOR findings when a data leak is confirmed."""

        id_a = self._get_user_resource_id(endpoint, role_a)
        id_b = self._get_user_resource_id(endpoint, role_b)

        # Skips this endpoint if a resource ID cannot be obtained for either role.
        if not id_a or not id_b:
            logger.debug(
                f"Skipping IDOR read test at {endpoint.url}: could not obtain IDs for both roles."
            )
            return

        # Tests cross-role read access in both directions: role_b reading role_a's resource, and vice versa.
        for attacker_role, owner_role, owner_id in [
            (role_b, role_a, id_a),
            (role_a, role_b, id_b),
        ]:
            url_with_id = self._build_url_with_id(endpoint, owner_id)

            # Step a sends the legitimate request as the owner, to establish an authenticated baseline response.
            try:
                response_owner = self.http_client.send_request(
                    "GET", url_with_id, session_key=owner_role
                )[0]
            except Exception as exc:
                logger.debug(
                    f"Owner request to {url_with_id} as {owner_role} failed: {exc}"
                )
                continue

            # Skips this pair if the owner's own request did not return 200.
            if response_owner is None or response_owner.status_code != 200:
                continue

            # Step b sends the exact same URL, using the attacker's session to test for unauthorised access.
            try:
                response_attacker = self.http_client.send_request(
                    "GET", url_with_id, session_key=attacker_role
                )[0]
            except Exception as exc:
                logger.debug(
                    f"Attacker request to {url_with_id} as {attacker_role} failed: {exc}"
                )
                continue

            # Skips this pair if the attacker received no response.
            if response_attacker is None:
                continue

            # Skips this pair if the attacker was correctly denied access.
            if response_attacker.status_code != 200:
                continue

            # Step c uses `ResponseComparator` to determine whether the attacker received the owner's data.
            # `compare_body_length` returns a raw bool — True means lengths are within the configured threshold.
            length_result = self.comparator.compare_body_length(
                response_owner, response_attacker
            )
            same_length = length_result

            # Attempts to parse the attacker's response as JSON, to enable field-level inspection.
            try:
                attacker_body = response_attacker.json()
            except Exception:
                # Falls back to an empty dictionary if the response body is not valid JSON, or is empty.
                attacker_body = {}

            # Scans the attacker's parsed response body for keys matching known sensitive field name patterns.
            sensitive_fields = self.comparator.extract_sensitive_fields(attacker_body)
            # Performs a cross-body comparison, to determine whether the attacker received data belonging to the owner.
            data_leak = self.comparator.is_data_leak(response_owner, response_attacker)

            # Flags a critical IDOR finding when the attacker received matching content, or sensitive field exposure.
            if data_leak or same_length or sensitive_fields:
                vuln = Vulnerability(
                    vuln_type="IDOR/BOLA - Horizontal Privilege Escalation (Read)",
                    severity="Critical",
                    endpoint=url_with_id,
                    method=endpoint.method,
                    description=(
                        f"Role {attacker_role} can read a resource owned by role {owner_role}. "
                        f"Attacker received status {response_attacker.status_code} "
                        f"with {len(response_attacker.content)} bytes."
                    ),
                    # Records both roles, the owner's resource ID, and all three comparator signals as supporting evidence.
                    evidence={
                        "attacker_role": attacker_role,
                        "owner_role": owner_role,
                        "owner_resource_id": owner_id,
                        "attacker_status_code": response_attacker.status_code,
                        "body_within_threshold": same_length,
                        "sensitive_fields_exposed": sensitive_fields,
                        "data_leak_confirmed": data_leak,
                    },
                )
                self.findings.append(vuln)
                logger.warning(
                    f"IDOR read confirmed: {attacker_role} accessed {owner_role} resource at {url_with_id}."
                )

    def test_idor_write(self, endpoint, id_param, role_a="user_a", role_b="user_b"):
        """Tests whether `role_b` can modify a resource owned by `role_a`, by sending a POST, PUT, PATCH, or DELETE request with
        `role_a`'s resource ID, using `role_b`'s session. Flags critical IDOR findings when the server returns 200 or 204."""

        write_methods = ("POST", "PUT", "PATCH", "DELETE")

        # Skips this endpoint if the HTTP method is not a state-changing write operation.
        if endpoint.method.upper() not in write_methods:
            return

        id_a = self._get_user_resource_id(endpoint, role_a)

        # Skips if no resource ID can be obtained for role_a.
        if not id_a:
            logger.debug(
                f"Skipping IDOR write test at {endpoint.url}: could not obtain ID for {role_a}."
            )
            return

        url_with_id = self._build_url_with_id(endpoint, id_a)

        # Sends a write request for role_a's resource using role_b's session to test for unauthorised modification.
        try:
            # Uses `http_client.send_request` for PUT and PATCH as a proxy to test whether the server accepts the modification.
            if endpoint.method.upper() in ("PUT", "PATCH"):
                response = self.http_client.send_request(
                    "POST", url_with_id, session_key=role_b
                )[0]
            elif endpoint.method.upper() == "DELETE":
                # Builds a raw requests.Session for DELETE, because `http_client` does not expose a delete convenience method.
                session_kwargs = self.session_manager.get_session_kwargs(role_b)
                import requests as _requests

                s = _requests.Session()
                headers = session_kwargs.get("headers", {})
                cookies = session_kwargs.get("cookies", {})
                # Applies role_b's authentication headers, and cookies to the bare session before sending the DELETE request.
                if headers:
                    s.headers.update(headers)
                if cookies:
                    s.cookies.update(cookies)
                response = s.delete(
                    url_with_id, timeout=10, verify=self.config.verify_ssl
                )
            else:
                # Falls back to a POST for any other write method not explicitly handled above.
                response = self.http_client.send_request(
                    "POST", url_with_id, session_key=role_b
                )[0]
        except Exception as exc:
            logger.debug(
                f"IDOR write request to {url_with_id} as {role_b} failed: {exc}"
            )
            return

        # Skips if no response was received from the server.
        if response is None:
            return

        # Flags a critical IDOR write finding when the server accepted the cross-role modification request.
        if response.status_code in (200, 201, 204):
            vuln = Vulnerability(
                vuln_type="IDOR/BOLA - Horizontal Privilege Escalation (Write)",
                severity="Critical",
                endpoint=url_with_id,
                method=endpoint.method,
                # Includes the HTTP method in the description to distinguish PUT, PATCH, POST, and DELETE findings.
                description=(
                    f"Role {role_b} successfully performed a {endpoint.method} on a resource "
                    f"owned by role {role_a}. Server returned {response.status_code}."
                ),
                # Records both roles, the owner's resource ID, the status code, and the response body length as evidence.
                evidence={
                    "attacker_role": role_b,
                    "owner_role": role_a,
                    "owner_resource_id": id_a,
                    "response_status_code": response.status_code,
                    "response_body_length": len(response.content),
                },
            )
            self.findings.append(vuln)
            logger.warning(
                f"IDOR write confirmed: {role_b} modified {role_a} resource at {url_with_id} "
                f"with status {response.status_code}."
            )

    def test_idor_enumeration(self, endpoint, id_param, role="user_a"):
        """Enumerates the IDs numerically, above and below the role's own ID, to detect accessible foreign records.
        Skips UUID-format IDs entirely. Stops early after three consecutive 404 responses in either direction, and flags
        critical findings for each accessible record."""

        own_id_str = self._get_user_resource_id(endpoint, role)

        # Skips enumeration if no resource ID can be obtained for the role.
        if not own_id_str:
            logger.debug(
                f"Skipping IDOR enumeration at {endpoint.url}: could not obtain ID for {role}."
            )
            return

        # Skips enumeration entirely when the detected ID is a UUID, as UUIDs cannot be guessed by incrementing.
        if UUID_PATTERN.match(own_id_str):
            logger.info(
                f"UUID-format ID detected for role {role} at {endpoint.url}. "
                "Skipping sequential enumeration."
            )
            return

        # Skips enumeration if the ID is not a plain numeric string.
        if not NUMERIC_ID_PATTERN.match(own_id_str):
            logger.debug(
                f"Non-numeric, non-UUID ID detected for role {role} at {endpoint.url}: {own_id_str}. Skipping."
            )
            return

        own_id = int(own_id_str)
        enum_range = getattr(self.config, "idor_enum_range", 10)

        logger.info(
            f"Starting IDOR enumeration for role {role} at {endpoint.url} "
            f"with own ID {own_id}, range {enum_range}."
        )

        # Builds the list of IDs to probe. `enum_range` values below, and `enum_range` values above the own ID, excluding it.
        ids_to_test = list(range(max(1, own_id - enum_range), own_id)) + list(
            range(own_id + 1, own_id + enum_range + 1)
        )

        consecutive_404s = 0

        # Iterates over candidate IDs, sends GET requests as the role, and flags accessible foreign records.
        for probe_id in ids_to_test:
            url_with_id = self._build_url_with_id(endpoint, probe_id)

            try:
                response = self.http_client.send_request(
                    "GET", url_with_id, session_key=role
                )[0]
            except Exception as exc:
                logger.debug(f"Enumeration request to {url_with_id} failed: {exc}")
                continue

            # Increments the consecutive 404 counter, and stops enumeration after three consecutive misses.
            if response is None or response.status_code == 404:
                consecutive_404s += 1
                if consecutive_404s >= 3:
                    logger.debug(
                        f"Three consecutive 404 responses during enumeration at {endpoint.url}. Stopping early."
                    )
                    break
                continue

            consecutive_404s = 0

            # Skips this probe ID, if the server did not return 200 with a non-trivial response body.
            if response.status_code != 200 or len(response.content) < 50:
                continue

            try:
                body = response.json()
            except Exception:
                body = {}

            sensitive_fields = self.comparator.extract_sensitive_fields(body)

            # Flags a critical enumeration finding, when accessible foreign record data is confirmed within the response.
            if body and probe_id != own_id:
                vuln = Vulnerability(
                    vuln_type="IDOR/BOLA - Horizontal Privilege Escalation (Enumeration)",
                    severity="Critical",
                    endpoint=url_with_id,
                    method="GET",
                    # Includes both the probed ID, and the role's own ID in the description to make the offset clear.
                    description=(
                        f"Role {role} accessed a foreign record at ID {probe_id} "
                        f"(own ID is {own_id}). Server returned {response.status_code} "
                        f"with {len(response.content)} bytes."
                    ),
                    # Records the role, both IDs, the response status, body length, and sensitive fields as evidence.
                    evidence={
                        "role": role,
                        "own_id": own_id,
                        "probed_id": probe_id,
                        "response_status_code": response.status_code,
                        "response_body_length": len(response.content),
                        "sensitive_fields_present": sensitive_fields,
                    },
                )
                self.findings.append(vuln)
                logger.warning(
                    f"IDOR enumeration finding: {role} accessed foreign record at ID {probe_id} "
                    f"via {url_with_id}."
                )

    def test_all_idor(self, endpoints, endpoint_params):
        """Manages all three IDOR test types across every user-specific endpoint identified by `_identify_user_specific_endpoints`.
        Calls `test_idor_read`, `test_idor_write`, and then `test_idor_enumeration` for each endpoint in sequence."""

        # Skips the entire IDOR module when the required user_a and user_b sessions are not present,
        # avoiding failed HTTP requests and warning-level log noise on single-role targets such as DVWA.
        required_roles = ["user_a", "user_b"]
        missing = [r for r in required_roles if r not in self.session_manager.sessions]
        if missing:
            logger.info(
                f"Skipping IDOR tests — no sessions for: {missing}."
            )
            return

        targets = self._identify_user_specific_endpoints(endpoints, endpoint_params)

        logger.info(
            f"Running IDOR tests across {len(targets)} user-specific endpoints."
        )

        # Iterates over all the user-specific endpoints, and runs all three IDOR test types for each one.
        for endpoint in targets:
            params = endpoint_params.get(endpoint.url, [])
            id_params = [p for p in params if getattr(p, "is_id_field", False)]
            id_param = id_params[0] if id_params else None

            self.test_idor_read(endpoint, id_param)
            self.test_idor_write(endpoint, id_param)
            self.test_idor_enumeration(endpoint, id_param)

    def get_findings(self):
        """Returns the complete list of `Vulnerability` objects, recorded during horizontal authorisation testing."""
        return self.findings