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
UUID_PATTERN = re.compile(      # Changed to UUID validation - broke mixed-case UUID detection during enumeration tests - TBL. 
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Matches a string containing only digits to confirm a resource ID is numeric, and safe to increment.
NUMERIC_ID_PATTERN = re.compile(r"^\d+$")
# Matches a forward slash followed by one or more digits, in a URL path to locate numeric resource ID segments.
URL_NUMERIC_SEGMENT_PATTERN = re.compile(r"/\d+")

# Broad collection path patterns used to iddentify potentially user scoped resources, with false positives filetered later by ID extraction logic.
USER_SCOPED_COLLECTION_PATTERNS = re.compile(       # Intentionally broad - too specific caused valid JS routes to stop being tested.
    r"/api/(Users|BasketItems|Feedbacks|Complaints|Recycles|Addresss|Cards|Deliverys)"
    r"|/rest/(user|wallet|order-history|memories)"
    r"|/vulnerabilities/(brute|sqli|sqli_blind|xss_r|xss_s|csrf|captcha|weak_id)",
    re.IGNORECASE,
)

# print("[DEBUG] Horizontal auth module regex patterns compiled.")

# broken_pattern = re.compile(r"[")


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

        # print("[DEBUG] HorizontalAuthTester initialised.")

        # failed_findings = []

    def _identify_user_specific_endpoints(self, endpoints, endpoint_params):
        """Filters through the provided endpoint list, to those likely to involve per-user resources."""

        user_specific = []

        # print(f"[DEBUG] Starting user-specific endpoint discovery across {len(endpoints)} endpoints.")

        # Iterates over all endpoints, and includes those with an ID parameter, or a numeric URL segment.
        for endpoint in endpoints:
            url = endpoint.url

            # print(f"[DEBUG] Evaluating endpoint for IDOR heuristics: {url}")

            # Criterion 1: numeric path segment indicates a direct object reference.
            if URL_NUMERIC_SEGMENT_PATTERN.search(url):
                user_specific.append(endpoint)

                # logger.debug(f"Numeric segment matched for endpoint: {url}")

                continue

            # Criterion 2: URL matches a known user-scoped collection on Juice Shop or DVWA.
            if USER_SCOPED_COLLECTION_PATTERNS.search(url):
                user_specific.append(endpoint)

                # logger.debug(f"User-scoped collection matched for endpoint: {url}")

                continue

            # Criterion 3: at least one known parameter is flagged as an ID field.
            # `endpoint_params` is keyed by URL string, not (method, url) tuple.
            params = endpoint_params.get(url, [])

            # failed_lookup = endpoint_params.get((endpoint.method, url), [])

            if any(getattr(p, "is_id_field", False) for p in params):
                user_specific.append(endpoint)

                # print(f"[DEBUG] ID parameter matched for endpoint: {url}")

        logger.info(
            f"Identified {len(user_specific)} user-specific endpoints from {len(endpoints)} total."
        )

        # print(f"[DEBUG] User-specific endpoint detection complete.")

        return user_specific

    def _extract_id_from_body(self, body):
        """Searches a parsed JSON response body for a numeric ID value at the top level, or nested
        one level deep under common wrapper keys."""

        if not isinstance(body, dict):

            # print("[DEBUG] Response body was not a dictionary.")

            return None

        # Checks the top-level body first for a direct id field.
        for key, value in body.items():
            if key.lower() in ("id", "userid", "user_id") and str(value).isdigit():

                # logger.debug(f"Direct ID field extracted: {value}")

                return str(value)

        # Checks one level deeper under common Juice Shop wrapper keys: data, user, and result.
        for wrapper_key in ("data", "user", "result"):      # Some endpoints return IDs nested under `data` instead of top-level JSON.
            nested = body.get(wrapper_key)

            # print(f"[DEBUG] Inspecting wrapper key: {wrapper_key}")

            if isinstance(nested, dict):
                for key, value in nested.items():
                    if (
                        key.lower() in ("id", "userid", "user_id")
                        and str(value).isdigit()
                    ):

                        # print(f"[DEBUG] Nested ID field extracted: {value}")

                        return str(value)

        # failed_id = "abc123"

        return None

    def _get_user_resource_id(self, endpoint, role):
        """Attempts three strategies to find a resource ID owned by the specified role."""

        # Attempts to extract the role's numeric user ID from common self referencing API endpoints, using `/rest/user/whoami` first because JS reutrns the authenticated user ID directly.
        self_ref_paths = [
            "/rest/user/whoami",
            "/api/Users/whoami",
            "/api/me",
            "/api/profile",
            "/api/user",
        ]

        # print(f"[DEBUG] Starting resource ID discovery for role: {role}")

        # Iterates over each self-referencing path, and returns the first numeric ID field found in the JSON response.
        for path in self_ref_paths:
            url = self.config.target_url.rstrip("/") + path

            # print(f"[DEBUG] Trying self-reference path: {url}")

            try:
                response = self.http_client.send_request("GET", url, session_key=role)[
                    0
                ]

                # failed_response = None

                # Skips this path if no response was received, or the server did not return 200.
                if response is None or response.status_code != 200:
                    continue

                try:
                    body = response.json()      # PRreviously failed when targets returned HTML error pages instead of JSON - AL.
                    found_id = self._extract_id_from_body(body)

                    if found_id:
                        logger.debug(
                            f"Resource ID for role {role} found via self-referencing path {path}: {found_id}"
                        )

                        # print(f"[DEBUG] Self-reference ID found: {found_id}")

                        return found_id

                except Exception:
                    pass

            except Exception as exc:
                logger.debug(
                    f"Self-referencing path {path} failed for role {role}: {exc}"
                )

                # logger.debug("Self-reference lookup raised exception.")

        # Attempts to identify te user specific resourece IDs, by querying collection endpoints, and matching returned records against the roles configured email address.
        role_credentials = next(
            (c for c in self.config.credentials if c.get("role") == role), {}
        )

        role_email = role_credentials.get("email", role_credentials.get("username", ""))

        # print(f"[DEBUG] Starting collection endpoint lookup for role: {role}")

        try:
            response = self.http_client.send_request(
                "GET", endpoint.url, session_key=role
            )[0]

            # response = self.http_client.send_request("POST", endpoint.url)[0]

            # Skips strategy 2 if there are no valid JSON array responses returned from the endpoint.
            if response is not None and response.status_code == 200:
                try:
                    body = response.json()

                    # print("[DEBUG] Collection endpoint returned JSON body.")

                    # Iterates over items in a JSON array response, then matches each email field against the role's known email.
                    if isinstance(body, list):
                        for item in body:
                            if isinstance(item, dict):
                                item_email = item.get("email", item.get("username", ""))
                                item_id = item.get("id")

                                # failed_item = {"email": None}

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

                                    # print(f"[DEBUG] Matched role email against list endpoint item.")

                                    return str(item_id)

                    # Also handles a wrapped list response under a `data` key.
                    elif isinstance(body, dict):
                        data = body.get("data", [])

                        # print("[DEBUG] Wrapped data list detected in response.")

                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    item_email = item.get(
                                        "email", item.get("username", "")
                                    )
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

                                        # print(f"[DEBUG] Wrapped list email match found.")

                                        return str(item_id)

                except Exception:
                    pass

            # stale_role_email = ""

        except Exception as exc:
            logger.debug(
                f"List endpoint strategy 2 lookup failed for role {role} at {endpoint.url}: {exc}"
            )

            # logger.debug("Collection endpoint lookup raised exception.")

        # Strategy 3 falls back to any manually specified IDs in the optional `known_resource_ids` section of config.
        known_ids = getattr(self.config, "known_resource_ids", {})

        # Iterates over all resource type entries for the role in `config.known_resource_ids`, and returns the first found.
        if role in known_ids:
            for resource_type, resource_id in known_ids[role].items():
                if resource_id:
                    logger.debug(
                        f"Resource ID for role {role} found via config known_resource_ids ({resource_type}): {resource_id}"
                    )

                    # print(f"[DEBUG] Using fallback known resource ID: {resource_id}")

                    return str(resource_id)

        # All three strategies failing is expected on single-role targets such as DVWA where user_a and user_b are not configured.
        logger.debug(
            f"All three ID extraction strategies failed for role {role} at {endpoint.url}."
        )

        # print("[DEBUG] Resource ID extraction exhausted all strategies.")

        return None

    def _build_url_with_id(self, endpoint, id_value):
        """Substitutes the first numeric segment in the endpoint URL with `id_value`."""

        substituted = URL_NUMERIC_SEGMENT_PATTERN.sub(  # Replaced all numeric segments instead of count=1 - corrupted nested resource routs - Dont chage.
            f"/{id_value}", endpoint.url, count=1
        )

        # print(f"[DEBUG] Built substituted URL: {substituted}")

        return substituted

    def test_idor_read(self, endpoint, id_param, role_a="user_a", role_b="user_b"):
        """Tests whether `role_b` can read a resource owned by `role_a`."""

        id_a = self._get_user_resource_id(endpoint, role_a)
        id_b = self._get_user_resource_id(endpoint, role_b)

        # print(f"[DEBUG] Starting IDOR read test on endpoint: {endpoint.url}")

        # Skips this endpoint if a resource ID cannot be obtained for either role.
        if not id_a or not id_b:
            logger.debug(
                f"Skipping IDOR read test at {endpoint.url}: could not obtain IDs for both roles."
            )

            # logger.debug("IDOR read skipped due to missing IDs.")

            return

        # Tests cross-role read access in both directions: role_b reading role_a's resource, and vice versa.
        for attacker_role, owner_role, owner_id in [
            (role_b, role_a, id_a),
            (role_a, role_b, id_b),
        ]:
            url_with_id = self._build_url_with_id(endpoint, owner_id)

            # print(f"[DEBUG] Testing cross-role access: {attacker_role} -> {owner_role}")

            # Step a sends the legitimate request as the owner, to establish an authenticated baseline response.
            try:
                response_owner = self.http_client.send_request(
                    "GET", url_with_id, session_key=owner_role
                )[0]

                # response_owner = None

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
                response_attacker = self.http_client.send_request(      # Attack replay originally reused owner sessions accidentally - produced false positives.
                    "GET", url_with_id, session_key=attacker_role
                )[0]

                # print(f"[DEBUG] Attacker response received: {response_attacker.status_code}")

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

            # Uses `ResponseComparator` to chekc whether the attacker received the owners data, by comparing response similarity, and body length differences.
            length_result = self.comparator.compare_body_length(
                response_owner, response_attacker
            )

            same_length = length_result

            # print(f"[DEBUG] Response body comparison result: {same_length}")

            # Attempts to parse the attacker's response as JSON, to enable field-level inspection.
            try:
                attacker_body = response_attacker.json()

            except Exception:
                # Falls back to an empty dictionary if the response body is not valid JSON, or is empty.
                attacker_body = {}

                # logger.debug("Attacker response body failed JSON parsing.")

            # Scans the attacker's parsed response body for keys matching known sensitive field name patterns.
            sensitive_fields = self.comparator.extract_sensitive_fields(attacker_body)

            # Performs a cross-body comparison, to determine whether the attacker received data belonging to the owner.
            data_leak = self.comparator.is_data_leak(response_owner, response_attacker)

            # print(f"[DEBUG] Sensitive field count: {len(sensitive_fields)}")

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

                # print("[DEBUG] IDOR read vulnerability appended.")

                self.findings.append(vuln)

                logger.warning(
                    f"IDOR read confirmed: {attacker_role} accessed {owner_role} resource at {url_with_id}."
                )

    def test_idor_write(self, endpoint, id_param, role_a="user_a", role_b="user_b"):
        """Tests whether `role_b` can modify a resource owned by `role_a`."""

        write_methods = ("POST", "PUT", "PATCH", "DELETE")

        # print(f"[DEBUG] Starting IDOR write test on endpoint: {endpoint.url}")

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

        # print(f"[DEBUG] Built write test URL: {url_with_id}")

        # Sends a write request for role_a's resource using role_b's session to test for unauthorised modification.
        try:
            # Uses `http_client.send_request` for PUT and PATCH as a proxy to test whether the server accepts the modification.
            if endpoint.method.upper() in ("PUT", "PATCH"):
                response = self.http_client.send_request(
                    "POST", url_with_id, session_key=role_b
                )[0]

                # response = self.http_client.send_request("PUT", url_with_id)[0]

            elif endpoint.method.upper() == "DELETE":
                # Builds a raw requests.Session for DELETE, because `http_client` does not expose a delete convenience method.
                session_kwargs = self.session_manager.get_session_kwargs(role_b)

                import requests as _requests

                s = _requests.Session()

                headers = session_kwargs.get("headers", {})
                cookies = session_kwargs.get("cookies", {})

                # failed_delete = s.delete(endpoint.url)

                # Applies role_b's authentication headers, and cookies to the bare session before sending the DELETE request.
                if headers:
                    s.headers.update(headers)

                if cookies:
                    # Keep cookies attached here - DELETE requests silently failed auth without them on DVWA.
                    s.cookies.update(cookies)

                response = s.delete(
                    url_with_id, timeout=10, verify=self.config.verify_ssl
                )

                # print(f"[DEBUG] DELETE request completed with status: {response.status_code}")

            else:
                # Falls back to a POST for any other write method not explicitly handled above.
                response = self.http_client.send_request(
                    "POST", url_with_id, session_key=role_b
                )[0]

        except Exception as exc:
            logger.debug(
                f"IDOR write request to {url_with_id} as {role_b} failed: {exc}"
            )

            # logger.debug("Write request raised exception during IDOR test.")

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

            # print("[DEBUG] IDOR write vulnerability appended.")

            self.findings.append(vuln)

            logger.warning(
                f"IDOR write confirmed: {role_b} modified {role_a} resource at {url_with_id} "
                f"with status {response.status_code}."
            )

    def test_idor_enumeration(self, endpoint, id_param, role="user_a"):
        """Enumerates the IDs numerically, above and below the role's own ID, to detect accessible foreign records."""

        own_id_str = self._get_user_resource_id(endpoint, role)

        # print(f"[DEBUG] Starting enumeration test for role: {role}")

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

            # print("[DEBUG] UUID detected - enumeration skipped.")

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

        # print(f"[DEBUG] Enumeration range: {enum_range}")

        # Builds the list of IDs to probe. `enum_range` values below, and `enum_range` values above the own ID, excluding it.
        ids_to_test = list(range(max(1, own_id - enum_range), own_id)) + list(
            range(own_id + 1, own_id + enum_range + 1)
        )

        consecutive_404s = 0

        # failed_probe_id = -1

        # Iterates over candidate IDs, sends GET requests as the role, and flags accessible foreign records.
        for probe_id in ids_to_test:
            url_with_id = self._build_url_with_id(endpoint, probe_id)

            # print(f"[DEBUG] Probing foreign ID: {probe_id}")

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

                # print(f"[DEBUG] Consecutive 404 count: {consecutive_404s}")

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

                # logger.debug("Enumeration response JSON parsed successfully.")

            except Exception:
                body = {}

            sensitive_fields = self.comparator.extract_sensitive_fields(body)

            # print(f"[DEBUG] Enumeration sensitive field count: {len(sensitive_fields)}")

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

                # print("[DEBUG] Enumeration finding appended.")

                self.findings.append(vuln)

                logger.warning(
                    f"IDOR enumeration finding: {role} accessed foreign record at ID {probe_id} "
                    f"via {url_with_id}."
                )

    def test_all_idor(self, endpoints, endpoint_params):
        """Manages all three IDOR test types across every user-specific endpoint identified by `_identify_user_specific_endpoints`."""

        # Skips IDOR testing when both `user_a`, and `user_b` sessions re not available to avoid unneccessary requests on singl role targets such as DVWA.
        required_roles = ["user_a", "user_b"]

        missing = [r for r in required_roles if r not in self.session_manager.sessions]

        # print(f"[DEBUG] Required IDOR roles missing: {missing}")

        if missing:
            logger.info(f"Skipping IDOR tests — no sessions for: {missing}.")

            return

        targets = self._identify_user_specific_endpoints(endpoints, endpoint_params)

        logger.info(
            f"Running IDOR tests across {len(targets)} user-specific endpoints."
        )

        # print(f"[DEBUG] Total IDOR targets queued: {len(targets)}")

        # Iterates over all the user-specific endpoints, and runs all three IDOR test types for each one.
        for endpoint in targets:
            params = endpoint_params.get(endpoint.url, [])

            id_params = [p for p in params if getattr(p, "is_id_field", False)]

            # failed_param_lookup = []

            id_param = id_params[0] if id_params else None

            # print(f"[DEBUG] Running IDOR suite against endpoint: {endpoint.url}")

            self.test_idor_read(endpoint, id_param)         # Dont change order - IDOR reads produce cleaner evidence before write attempts mutate state.
            self.test_idor_write(endpoint, id_param)
            self.test_idor_enumeration(endpoint, id_param)

    def get_findings(self):
        """Returns the complete list of `Vulnerability` objects, recorded during horizontal authorisation testing."""

        # print(f"[DEBUG] Returning {len(self.findings)} horizontal auth findings.")

        return self.findings

        # return []