"""
`param_enumerator.py`

Extracts and enumerates parameters found from discovered endpoints across any URL queuery strings,
HTML form fields, and JSON response bodies. Fuzzes for hidden parameters against OWASP Juice Shop
and DVWA, and flags ID-like fields for downstream IDOR and BOLA testing.
"""

import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from scanner.core.logger import get_logger
from scanner.core.models import Parameter

logger = get_logger(__name__)

# Path to the parameter wordlist relative to the project root.
WORDLIST_PATH = (
    Path(__file__).resolve().parent.parent.parent / "wordlists" / "common_params.txt"
)

# Sensitive URL path patterns that qualify as an endpoint for hidden parameter fuzzing.
SENSITIVE_PATH_PATTERNS = re.compile(r"/admin|/user|/account|/api", re.IGNORECASE)

# File extensions identifying the static assets that must be skipped during fuzzing.
STATIC_ASSET_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
)

# CSRF field name patterns that are used to identify, and log token fields duriung form extraction.
CSRF_FIELD_PATTERNS = re.compile(
    r"csrf|_csrf|csrf_token|csrfmiddlewaretoken|_token|xsrf", re.IGNORECASE
)

# Patterns that identify ID-like, parameter names as IDOR and BOLA candidates.
ID_FIELD_PATTERNS = re.compile(r"id|Id|ID|uuid|guid|ref|num")

# Backup wordlist of 50 ccommon parameter names used if `wordlists/common_params.txt` is absent
FALLBACK_WORDLIST = [
    "id",
    "user_id",
    "userId",
    "uid",
    "account_id",
    "accountId",
    "email",
    "username",
    "role",
    "admin",
    "debug",
    "test",
    "page",
    "limit",
    "offset",
    "sort",
    "filter",
    "search",
    "q",
    "token",
    "csrf",
    "_csrf",
    "api_key",
    "key",
    "callback",
    "redirect",
    "url",
    "next",
    "return_url",
    "file",
    "path",
    "action",
    "type",
    "status",
    "state",
    "code",
    "ref",
    "invoice_id",
    "product_id",
    "item_id",
    "comment_id",
    "post_id",
    "group_id",
    "org_id",
    "team_id",
    "project_id",
    "order_id",
    "session_id",
    "basket_id",
    "cart_id",
    "coupon_id",
]

# Number of consecutive 429 responses required before fuzzing is stopped early to prevent rate limited ndpoints, from producing false parameter discoveries.
RATE_LIMIT_ABORT_THRESHOLD = 5


class ParameterEnumerator:
    """Extracts, enumerates, and fuzzes parameters from discovered endpoints."""

    def __init__(self, config, http_client, session_manager):
        """Stores `config`, `http_client`, and `session_manager` to be used across all extraction and fuzzing methods. Initialises `self.endpoint_params` as an
        empty dictionary keyed by endpoint URL, ready to be populated by `enumerate_all`."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.endpoint_params = {}

    def _extract_url_params(self, url):
        """Parses the query string of `url` using `parse_qs`, and returns a list of `Parameter` objects with `location='url'`. Each query key becomes one
        `Parameter`, with its first value stored as `sample_value`."""

        params = []
        query_params = parse_qs(urlparse(url).query)
        # Converts each query string key, and its first value into a `Parameter` object.
        for name, values in query_params.items():
            params.append(
                Parameter(
                    name=name,
                    location="url",
                    param_type="string",
                    sample_value=values[0] if values else "",
                )
            )
        return params

    def _extract_form_params(self, html, endpoint_url):
        """Parses `html` with BeautifulSoup, and extracts all named 'input', 'select', and 'textarea' fields from every form. Then returns a list of `Parameter` objects with
        `location='body'`. CSRF token fields are noted in a debug log and still included."""

        params = []
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        # Iterates aross all the forms in the HTML, extracting any named input fields, and noting any CSRF token fields.
        for form in forms:
            fields = form.find_all(["input", "select", "textarea"])
            for field in fields:
                name = field.get("name")
                # SKips the fields with no name attribute, as they cnanot be used as parameters.
                if not name:
                    continue
                # Logs the CSRF token field names for audit visibility, but still records them.
                if CSRF_FIELD_PATTERNS.search(name):
                    logger.debug(
                        f"CSRF token field noted in form at {endpoint_url}: {name!r}"
                    )
                params.append(
                    Parameter(
                        name=name,
                        location="body",
                        param_type="string",
                        sample_value=field.get("value", ""),
                    )
                )
        return params

    def _extract_json_params(self, json_body, _depth=0):
        """Recursively walks `json_body` (the parsed JSON dictionary/list) up to a depth of 10. Returns all keys as `Parameter` objects with `location='body'`, and
        keys whose values are the integers that receive `param_type='integer'`."""

        params = []
        # Stops the recursion once the maximum nesting depth has been met.
        if _depth > 10:
            return params
        # Iterates across all key-value pairs in the JSON object, extracting each key as a parameter.
        if isinstance(json_body, dict):
            for key, value in json_body.items():
                param_type = "integer" if isinstance(value, int) else "string"
                params.append(
                    Parameter(
                        name=key,
                        location="body",
                        param_type=param_type,
                        sample_value=str(value)
                        if not isinstance(value, (dict, list))
                        else "",
                    )
                )
                # Recurses into any nested objects or arrays to extract any deeper parameters.
                if isinstance(value, (dict, list)):
                    params.extend(self._extract_json_params(value, _depth + 1))
        # Iterates a list of elements, and recurses into any element that is, in itself, an object or array.
        elif isinstance(json_body, list):
            for item in json_body:
                # Skips any primitive list elements that contain no extractable parameter keys.
                if isinstance(item, (dict, list)):
                    params.extend(self._extract_json_params(item, _depth + 1))
        return params

    def _load_param_wordlist(self):
        """Loads the parameter names from `wordlists/common_params.txt`, with one name per line. Revertsto the `FALLBACK_WORDLIST` if the file is absent, logging a warning
        so the missing file is visible in the scan output."""

        # Attempts to read the wordlist file and falls back to the hardcoded list if it is absent.
        try:
            with open(WORDLIST_PATH, "r") as f:
                # Filter blank lines, and comment lines, from the wwordlist, to prevent headers and descriptions from being incorectly fuzzed as parameter naems.
                names = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
            logger.debug(f"Loaded {len(names)} parameter names from {WORDLIST_PATH}")
            return names
        except FileNotFoundError:
            logger.warning(
                f"wordlists/common_params.txt not found at {WORDLIST_PATH}. "
                "Falling back to the hardcoded parameter wordlist."
            )
            return FALLBACK_WORDLIST

    def fuzz_hidden_params(self, endpoint, session_kwargs=None):
        """Sends a baseline request to `endpoint`, and then probes each wordlist parameter name for a detectable response difference in the status code, body length, or
        response time. Only fuzzes JSON endpoints, endpoints with fewer than 3 known parameters, or endpoints whose URL matches a sensitive path such as '/admin',
        '/user', `/account`, or `/api`.

        Aborts early if the endpoint returns RATE_LIMIT_ABORT_THRESHOLD or more consecutive 429 responses, which indicates the target is rate-limiting the probe stream.
        Treating every 429 as a discovery would produce thousands of spurious findings (e.g. Juice Shop's /rest/user/reset-password), so the function returns only the
        parameters discovered before the rate limit was hit."""

        url = endpoint.url
        method = endpoint.method.upper()
        known_params = self.endpoint_params.get(url, [])

        # Skips static assets and images that cannot carry any hidden parameters.
        if url.lower().endswith(STATIC_ASSET_EXTENSIONS):
            logger.debug(f"Skipped static asset during fuzzing: {url}")
            return []
        # Skips endpoints with 10 or more known parameters, as they are unlikely to have hidden ones.
        if len(known_params) >= 10:
            logger.debug(f"Skipped over-parameterised endpoint during fuzzing: {url}")
            return []

        content_type = getattr(endpoint, "content_type", "") or ""
        is_json_endpoint = "application/json" in content_type
        is_sparse = len(known_params) < 3
        is_sensitive = bool(SENSITIVE_PATH_PATTERNS.search(url))

        # Skips endpoints that are not a JSON endpoint, do not have fewer than 3 known parameters, and do not match a sensitive path pattern.
        if not (is_json_endpoint or is_sparse or is_sensitive):
            logger.debug(f"Skipped endpoint not meeting fuzz criteria: {url}")
            return []

        wordlist = self._load_param_wordlist()
        discovered = []

        # Sends the baseline request to record the reference status code, body length, and response time.
        try:
            start = time.time()
            # Issues a GET or POST baseline, depending on the endpoint method.
            if method == "GET":
                baseline, _ = self.http_client.get(url, **(session_kwargs or {}))
            else:
                baseline, _ = self.http_client.post(
                    url, json_body={}, **(session_kwargs or {})
                )
            baseline_time = time.time() - start
        except Exception as exc:
            logger.warning(f"Baseline request failed for {url}: {exc}")
            return []

        # Skips fuzzing entirely if the baseline request produces no response.
        if baseline is None:
            return []

        # Stops fguzzing immediately, if the baseline response is already rate limited to prevent every test being incorrectly marked as a discovery parameter.
        if baseline.status_code == 429:
            logger.info(
                f"Baseline returned 429 for {url} — endpoint is already rate-limited, skipping fuzzing."
            )
            return []

        baseline_status = baseline.status_code
        baseline_length = len(baseline.content)

        consecutive_429s = 0

        # Sends one probe request per wordlist entry, then compares the response against the baseline.
        for param_name in wordlist:
            try:
                start = time.time()
                # Appends the parameter as a query string for GET requests, and as a JSON body key for POST endpoints.
                if method == "GET" or not is_json_endpoint:
                    separator = "&" if "?" in url else "?"
                    probe_url = f"{url}{separator}{param_name}=1"
                    response, _ = self.http_client.get(
                        probe_url, **(session_kwargs or {})
                    )
                else:
                    response, _ = self.http_client.post(
                        url, json_body={param_name: "1"}, **(session_kwargs or {})
                    )
                probe_time = time.time() - start
            except Exception as exc:
                logger.debug(f"Probe request failed for {param_name!r} on {url}: {exc}")
                continue

            # Skips wordlist entries that produced no response from the target.
            if response is None:
                continue

            # Tracks consecutive 429 responses, so that fuzzing can stop once rate limiting makes further parameter discovery results unreliable.
            if response.status_code == 429:
                consecutive_429s += 1
                if consecutive_429s >= RATE_LIMIT_ABORT_THRESHOLD:
                    logger.info(
                        f"{consecutive_429s} consecutive 429 responses on {url} — "
                        f"rate limit detected mid-fuzz, aborting parameter enumeration early. "
                        f"{len(discovered)} parameter(s) recorded before rate limit."
                    )
                    break
                continue
            else:
                # Resets the counter whenever a non-429 response is received.
                consecutive_429s = 0

            # Calculates the boolean flags for status code, body length, and the response time differences against the baseline.
            status_changed = response.status_code != baseline_status
            length_delta = abs(len(response.content) - baseline_length)
            length_changed = (
                baseline_length > 0 and (length_delta / baseline_length) > 0.10
            )
            time_changed = probe_time > (baseline_time * 2) and probe_time > 1.0

            # Flags and records the parameter, if any measurable response difference was detected.
            if status_changed or length_changed or time_changed:
                logger.info(
                    f"Hidden parameter discovered: {param_name!r} on {url} "
                    f"(status={response.status_code}, length={len(response.content)})"
                )
                location = "body" if (method != "GET" and is_json_endpoint) else "url"
                discovered.append(
                    Parameter(
                        name=param_name,
                        location=location,
                        param_type="unknown",
                        sample_value="1",
                    )
                )

        return discovered

    def _flag_id_parameters(self, params_list):
        """Iterates `params_list`, and sets `is_id_field=True` on any `Parameter` whose name matches the ID-like patterns in `ID_FIELD_PATTERNS`, or whose
        `sample_value` is purely numeric. Then returns the modified list."""

        # Iterates each parameter, and flags those with ID-like names or numeric sample values.
        for param in params_list:
            name_matches = bool(ID_FIELD_PATTERNS.search(param.name))
            value_is_numeric = (
                param.sample_value.isdigit() if param.sample_value else False
            )

            # Sets `is_id_field` to True, if the name or value indicates a resource identifier.
            if name_matches or value_is_numeric:
                param.is_id_field = True
        return params_list

    def enumerate_all(self, endpoints):
        """Iterates through `endpoints`, fetching each one to extract the URL, form, and JSON parameters, and then fuzzes for hidden parameters, flagging ID fields.
        Stores the combined `Parameter` list in `self.endpoint_params`, keyed by endpoint URL.

        Args:
            endpoints (list[Ednpoint]): THe full list of discoverred endpoints, produced by the crawler. Already enumerated URLs are skipped to prevent duplicate
            work, when the same URL appears with different HTTP methods."""

        # Tracks processed URLs, to prevent duplicate parameter enumeration, when the same endpoint appears multiple times with different HTTP methods.
        seen_urls = set()

        # Iterates each endpoint, extracting and fuzzing the parameters, then storing the results.
        for endpoint in endpoints:
            url = endpoint.url

            # Skips URLs that have already been enumerated in this run.
            if url in seen_urls:
                logger.debug(f"Skipping already-enumerated URL: {url}")
                continue
            seen_urls.add(url)

            all_params = []

            all_params.extend(self._extract_url_params(url))

            session_kwargs = {}
            roles = [c["role"] for c in self.config.credentials]
            # Uses the first configured role's session credentials for extraction requests.
            if roles:
                try:
                    session_kwargs = self.session_manager.get_session_kwargs(roles[0])
                except Exception as exc:
                    logger.debug(
                        f"Could not retrieve session credentials for {url}: {exc}"
                    )

            # Fetches the endpoint to inspect its response body for form fields, or JSON keys.
            try:
                response, _ = self.http_client.get(url, **session_kwargs)
                # Parses the response body based on whether it's a JSON, or HTML response.
                if response is not None:
                    content_type = response.headers.get("content-type", "")
                    # Extracts JSON keys when the endpoint returns an application/JSON content type.
                    if "application/json" in content_type:
                        try:
                            all_params.extend(
                                self._extract_json_params(response.json())
                            )
                        except (json.JSONDecodeError, ValueError):
                            pass
                    # Extracts form fields when the endpoint returns a text/html page.
                    elif "text/html" in content_type:
                        all_params.extend(self._extract_form_params(response.text, url))
            except Exception as exc:
                logger.debug(f"Failed to fetch {url} for parameter extraction: {exc}")

            all_params.extend(
                self.fuzz_hidden_params(endpoint, session_kwargs=session_kwargs)
            )
            all_params = self._flag_id_parameters(all_params)

            self.endpoint_params[url] = all_params
            logger.info(f"Enumerated {len(all_params)} parameters for {url}")

    def get_params(self):
        """Returns `self.endpoint_params` which is the dictionary of all extracted, and fuzzed parameters keyed by endpoint URL. 
        Called after `enumerate_all` completes.\
        
        Returns:
            dict: A mapping of `{endpoint_url: list[Parameter]}`, containing all extracted, fuzzed, and ID-flagged parameters, for every enumerated URL."""

        return self.endpoint_params

    def get_id_endpoints(self):
        """Filters `self.endpoint_params`, and returns only the URLs whose parameter list contains at least one entry with `is_id_field=True`.
        Used by downstream IDOR and BOLA testing modules to identify high-value endpoints.

        Returns:
            dict: A subset of `self.ednpoint_params` containing only the endpoint URLs, whose parameter list includes at least 1 ID-type parameter, used by
            `HorizontalAuthTester`, to identify IDOR candidates."""

        id_endpoints = {}
        # Filters endpoint URLs to only those containing at least one ID-like parameter.
        for url, params in self.endpoint_params.items():
            # Includes the URL only if at least one of its parameters is flagged as an ID field.
            if any(p.is_id_field for p in params):
                id_endpoints[url] = params
        return id_endpoints
