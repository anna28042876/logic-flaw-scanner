"""
`rate_limit_bypass.py`

Attempts to circumvent rate limiting on Juice Shop, and DVWA endpoints that were identified by `RateLimitDetector`.
Bypass techniques include IP header spoofing, user agent rotation, URL case variation, HTTP method switching, and
parameter pollution. Tests are run against all endpoints, regardless of  whether rate limiting was detected, in order
to generate evidence for both bypass confirmed, and missing rate limiting findings.
"""

import random
import string

from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability

logger = get_logger(__name__)

# Threshold that is used to determine whether a bypass technique produced signficantly fewer 429 responses, than the baseline.
BYPASS_SUCCESS_RATIO = 0.5


class RateLimitBypassTester:
    """Runs a set of rate limit bypass techniques against endpoints recorded in `detection_Results` from
    `RateLimitDetector`. Stores all confirmed bypass findings as `Vulnerability` objects in `self.findings`."""

    def __init__(self, config, http_client, detection_results):
        """Stores `config`, `http_client`, and `detection_Results` from `RateLimitDetector`. Initialises
        `self.findings` as an empty list, ready to accumulate the bypass findings."""
        self.config = config
        self.http_client = http_client
        # Holds the per-endpoint detection outcomes, produced by `RateLimitDetector`, for baseline comparisons.
        self.detection_results = detection_results
        # Accumulates all confirmed bypass findings as `Vulnerability` objects.
        self.findings = []

    def _generate_random_ip(self):
        """Generates a random IPv4 address in the public range, avoiding reserved prefixes, for use as a spoofed
        value in IP bypass header tests."""

        # Keeps the first octet between 1-223, to stay within the bounds of public unicast range.
        return (
            f"{random.randint(1, 223)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(1, 254)}"
        )

    def _generate_user_agent(self):
        """Returns a random real browser user agent string, from a hardcoded list
        of 20 entries covering Chrome, Firefox, Safari, and Edge, across WIndows,
        macOS, and Linux."""

        # Covers a broad range of real browsers and operating systems to avoid pattern-based detection.
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
            "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Vivaldi/6.7.3329.21",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        ]
        return random.choice(user_agents)

    def _count_429s(self, responses):
        """Counts the number of 429 status codes in a list of response objects, returning
        the integer total for comparison against a baseline count."""

        # Guards against NOne entries in the list, which occurs when a request raises an exception.
        return sum(1 for r in responses if r is not None and r.status_code == 429)

    def _get_baseline_429_count(self, endpoint_url):
        """Retrieves the number of 429 responses recorded during `RateLimitDetector` dectection for `endpoint_url`,
        from `self.detection_results`. Returns zero if no entry exists."""

        result = self.detection_results.get(endpoint_url, {})

        # Returns zero baseline, wehn the endpoint was not rate limited during detection.
        if not result.get("rate_limited"):
            return 0
        # Uses `first_429_at` as a proxy for the baseline 429 count, recorded during detection.
        return result.get("first_429_at") or 0

    def test_xff_bypass(self, endpoint_url, total_requests=200):
        """Sends `total_requests` POST requests, to `endpoint_url`, rotating the `X-Forwarded-For` header to a new,
        random IP each time. Flags a 'High' `Vulnerability`, if significantly fewer 429 responses are returned compared
        to the amount captured in the baseline."""

        responses = []
        # Sends each request with a freshly generated random IP, in the `X-Forwarded-For` header.
        for _ in range(total_requests):
            try:
                response, _ = self.http_client.post(
                    endpoint_url,
                    headers={"X-Forwarded-For": self._generate_random_ip()},
                )
                responses.append(response)
            except Exception as exc:
                logger.warning(
                    "XFF bypass request to %s raised an exception: %s",
                    endpoint_url,
                    exc,
                )
                # Appends None, so the response list length matches the total request count.
                responses.append(None)

        count_429 = self._count_429s(responses)
        baseline = self._get_baseline_429_count(endpoint_url)

        # Flags a 'High' finding if the 429 count dropped below half the baseline, indicating a successful bypass.
        if baseline > 0 and count_429 < baseline * BYPASS_SUCCESS_RATIO:
            vuln = Vulnerability(
                vuln_type="Rate Limit Bypass via X-Forwarded-For",
                severity="High",
                endpoint=endpoint_url,
                method="POST",
                # Records the baseline, and bypass 429 counts.
                evidence=(
                    f"Baseline 429 count: {baseline}. "
                    f"X-Forwarded-For rotation produced only {count_429} 429 responses "
                    f"across {total_requests} requests."
                ),
                # Describes the baseline, and bypass 429 counts.
                description=(
                    f"The rate limiter on {endpoint_url} uses the X-Forwarded-For "
                    f"header to identify clients. Rotating this header to a new "
                    f"random IP per request reduces 429 responses by more than 50%, "
                    f"allowing an attacker to bypass the limit."
                ),
            )
            self.findings.append(vuln)
            logger.warning("HIGH: XFF bypass confirmed on %s.", endpoint_url)

    def test_ip_header_variants(self, endpoint_url):
        """Tests seven alternative IP identification headers, individually agains `endpoint_url`, sending 50 requests per header.
        Then flags a 'High' `Vulnerability`, for any header that reduces 429 responses below the bypass success threshold."""

        # Lists all seven alternative IP headers, to test individually for rate limit bypass.
        ip_headers = [
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Client-IP",
            "X-Real-IP",
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Forwarded-Host",
        ]
        baseline = self._get_baseline_429_count(endpoint_url)

        # Iterates through each IP header variant, and sends 50 requests with a random IP valuje, to test for bypass.
        for header_name in ip_headers:
            responses = []
            for _ in range(50):
                try:
                    response, _ = self.http_client.post(
                        endpoint_url,
                        headers={header_name: self._generate_random_ip()},
                    )
                    responses.append(response)
                except Exception as exc:
                    logger.warning(
                        "IP header variant test (%s) on %s raised an exception: %s",
                        header_name,
                        endpoint_url,
                        exc,
                    )
                    responses.append(None)

            count_429 = self._count_429s(responses)
            # Flags a 'High' finding, if this header variant reduced 429 responses, below the bypass threshold.
            if baseline > 0 and count_429 < baseline * BYPASS_SUCCESS_RATIO:
                vuln = Vulnerability(
                    vuln_type="Rate Limit Bypass via IP Header Variant",
                    severity="High",
                    endpoint=endpoint_url,
                    method="POST",
                    evidence=(
                        f"Header `{header_name}` rotation produced {count_429} 429 responses "
                        f"against a baseline of {baseline}."
                    ),
                    description=(
                        f"The rate limiter on {endpoint_url} trusts the `{header_name}` "
                        f"header for client identification. Spoofing this header per "
                        f"request bypasses the limit."
                    ),
                )
                self.findings.append(vuln)
                logger.warning(
                    "HIGH: IP header variant bypass confirmed on %s using %s.",
                    endpoint_url,
                    header_name,
                )

    def test_user_agent_rotation(self, endpoint_url):
        """Sends 100 POST requests, to `endpoint_url`, rotating the `User-Agent` header on every request.
        Flags a 'High' `Vulnerability`, if significantly fewer 429 responses are captured compared to the
        number within the baseline."""

        responses = []
        # Sends each request with a randomly slected real browser user agent string.
        for _ in range(100):
            try:
                response, _ = self.http_client.post(
                    endpoint_url,
                    headers={"User-Agent": self._generate_user_agent()},
                )
                responses.append(response)
            except Exception as exc:
                logger.warning(
                    "User agent rotation request to %s raised an exception: %s",
                    endpoint_url,
                    exc,
                )
                responses.append(None)

        count_429 = self._count_429s(responses)
        baseline = self._get_baseline_429_count(endpoint_url)

        # FLags a 'High' finding, if user agent rotation reduced 429 responses below the bypass threshold.
        if baseline > 0 and count_429 < baseline * BYPASS_SUCCESS_RATIO:
            vuln = Vulnerability(
                vuln_type="Rate Limit Bypass via User-Agent Rotation",
                severity="High",
                endpoint=endpoint_url,
                method="POST",
                evidence=(
                    f"User-Agent rotation produced {count_429} 429 responses "
                    f"against a baseline of {baseline} across 100 requests."
                ),
                description=(
                    f"The rate limiter on {endpoint_url} uses the User-Agent "
                    f"header as part of client identification. Rotating the "
                    f"User-Agent per request reduces 429 responses below the "
                    f"bypass threshold."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "HIGH: User-Agent rotation bypass confirmed on %s.", endpoint_url
            )

    def test_url_case_variation(self, endpoint_url):
        """Extracts the path from `endpoint_url`, and generates six case and punctuation variants. Sends a
        POST request to each, and flags a 'High' `Vulnerability` for any variant that returns 200, which indicates
        the rate limiting is not normalising the URL."""

        from urllib.parse import urlparse

        parsed = urlparse(endpoint_url)
        # Reconstructs the base URL, without the path, so that variants can be appended.
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")

        # Generates case , and punctuation variants, of the endpoint path to test the URL normalisation in the rate limiter.
        variants = [
            base + path.capitalize(),
            base + path.upper(),
            base + path + "/",
            base + path + "?",
            base + path + "#",
            base + path + "%20",
        ]

        # Sends a POST request to each URL variant, and flags any that return 200 - indicates a bypass.
        for variant_url in variants:
            try:
                response, _ = self.http_client.post(variant_url)
                # Flags a 'High' finding, if the variant URL returned 200, bypassing the rate limiter.
                if response is not None and response.status_code == 200:
                    vuln = Vulnerability(
                        vuln_type="Rate Limit Bypass via URL Case Variation",
                        severity="High",
                        endpoint=variant_url,
                        method="POST",
                        evidence=(
                            f"URL variant `{variant_url}` returned HTTP 200 "
                            f"where the canonical URL is rate limited."
                        ),
                        description=(
                            f"The rate limiter on {endpoint_url} does not "
                            f"normalise the request URL. The variant `{variant_url}` "
                            f"bypasses rate limiting by routing to the same handler "
                            f"via a differently cased or suffixed path."
                        ),
                    )
                    self.findings.append(vuln)
                    logger.warning(
                        "HIGH: URL case variation bypass confirmed on %s.", variant_url
                    )
            except Exception as exc:
                logger.warning(
                    "URL case variation request to %s raised an exception: %s",
                    variant_url,
                    exc,
                )

    def test_method_switching(self, endpoint_url):
        """Sends 50 PUT, and 50 PATCH requests to `endpoint_url`, and compares the 429 count against the POST baseline.
        FLags a 'High' `Vulnerability`, if either of the alternative methods bypass rate limiting."""

        baseline = self._get_baseline_429_count(endpoint_url)
        # Iterates PUT, and PATCH, as alternative methods to check whether rate-limiting is POST-specific.
        for alt_method in ["PUT", "PATCH"]:
            responses = []
            for _ in range(50):
                try:
                    # Uses `X-HTTP-Method-Override` to send the alternative method, via the POST channel.
                    response, _ = self.http_client.post(
                        endpoint_url,
                        headers={"X-HTTP-Method-Override": alt_method},
                    )
                    responses.append(response)
                except Exception as exc:
                    logger.warning(
                        "Method switching test (%s) on %s raised an exception: %s",
                        alt_method,
                        endpoint_url,
                        exc,
                    )
                    responses.append(None)

            count_429 = self._count_429s(responses)
            if baseline > 0 and count_429 < baseline * BYPASS_SUCCESS_RATIO:
                # Flags a 'High' finding, if the alternative method produced significantly fewer 429 responses.
                vuln = Vulnerability(
                    vuln_type="Rate Limit Bypass via Method Switching",
                    severity="High",
                    endpoint=endpoint_url,
                    method=alt_method,
                    evidence=(
                        f"{alt_method} requests produced {count_429} 429 responses "
                        f"against a POST baseline of {baseline}."
                    ),
                    description=(
                        f"The rate limiter on {endpoint_url} applies only to POST "
                        f"requests. Sending {alt_method} requests to the same "
                        f"endpoint bypasses the limit."
                    ),
                )
                self.findings.append(vuln)
                logger.warning(
                    "HIGH: Method switching bypass confirmed on %s using %s.",
                    endpoint_url,
                    alt_method,
                )

    def test_parameter_pollution(self, endpoint_url):
        """Sends 100 POST requests to `ednpoint_url`, appending a unique dunmmy query parameter to each URL. Will
        falg a 'High' `VUlnerability` if the 429 responses see a significant drop below the baseline, therefore,
        indicating that the rate limiter keys on the full URL, rather than on the path."""

        responses = []
        # Sends each request with a unique cache-busting query parameter, thats appended to the URL.
        for i in range(100):
            # Generates a random 8-character alphabetic string to ensure that each cache-bust value is unique.
            cache_bust = "".join(random.choices(string.ascii_lowercase, k=8))
            polluted_url = f"{endpoint_url}?_={i}&cachebust={cache_bust}"
            try:
                response, _ = self.http_client.post(polluted_url)
                responses.append(response)
            except Exception as exc:
                logger.warning(
                    "Parameter pollution request to %s raised an exception: %s",
                    polluted_url,
                    exc,
                )
                responses.append(None)

        count_429 = self._count_429s(responses)
        baseline = self._get_baseline_429_count(endpoint_url)
        # FLags a 'High' finding, if the parameter pollution reduces 429 response below that of the bypass threshold.
        if baseline > 0 and count_429 < baseline * BYPASS_SUCCESS_RATIO:
            vuln = Vulnerability(
                vuln_type="Rate Limit Bypass via Parameter Pollution",
                severity="High",
                endpoint=endpoint_url,
                method="POST",
                evidence=(
                    f"Parameter pollution produced {count_429} 429 responses "
                    f"against a baseline of {baseline} across 100 requests."
                ),
                description=(
                    f"The rate limiter on {endpoint_url} keys on the full URL "
                    f"including query parameters. Appending unique dummy parameters "
                    f"to each request causes the limiter to treat them as distinct "
                    f"URLs, bypassing the limit."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "HIGH: Parameter pollution bypass confirmed on %s.", endpoint_url
            )

    def test_all_bypasses(self, endpoint_url):
        """Runs all six bypass techniques agains `endpoint_url` in sequence, including XFF rotation,
        IP header variants, user agent rotation, URL case variation, method switching, and parameter
        pollution."""

        logger.info("Running all bypass techniques against %s.", endpoint_url)
        # Runs each bypass method in sequence, so all techniques are tested regardless of earlier results.
        self.test_xff_bypass(endpoint_url)
        self.test_ip_header_variants(endpoint_url)
        self.test_user_agent_rotation(endpoint_url)
        self.test_url_case_variation(endpoint_url)
        self.test_method_switching(endpoint_url)
        self.test_parameter_pollution(endpoint_url)

    def test_all_endpoints(self, all_detection_results):
        """Iterates every ednpoint in `all_detection_results`, regardless of `rate_limited` status, and runs
        `test_all_bypasses` on each. This generates bypass evidence for rate-limited endpoints, and additional
        confirmation evidence for endpoints with no rate-limiting detected."""

        logger.info(
            "Running bypass tests against all %d detected endpoint(s).",
            len(all_detection_results),
        )
        # Iterates every endpoint in the detection results, and runs all bypass techniques against it.
        for endpoint_url in all_detection_results:
            self.test_all_bypasses(endpoint_url)

    def get_findings(self):
        """Returns `self.findings` accumulated across all the rate-limit bypass tests."""
        return self.findings