"""
`rate_limit_detector.py`

Sends repeated requests to critical Juice Shop, and DVWA endpoints at a configured rate. Records response status code,
and headers, and flags a 'Medium' `Vulnerability`, when no rate limiting is detected. A non-existent email address is
used on login endpoints to avoid corrupting test account states, or generated any valid JWT tokens.
"""

import statistics
import time

from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability

logger = get_logger(__name__)

# Sent as the email credential on all login endpoint rate limit tests, to avoid valid JWT generations, or account lockouts.
# Clearly anonymous, dummy info.
RATE_LIMIT_TEST_EMAIL = "janedoe@fake.local"
RATE_LIMIT_TEST_PASSWORD = "RateLimitTestPass1!"


class RateLimitDetector:
    """Sends bursts of requests to critical endpoints on Juice SHop, and DVWA. Analyses the responses codes, and headers,
    for rate-limiting evidence, and stores all confirmed missing-rate-limit findings in `self.findings`."""

    def __init__(self, config, http_client):
        """Stores `config`, and `http_client`. Initialises `self.findings`, and `self.detection_results` as an empty dictionary
        keyed by endpoint URL for use by `RateLimitBypassTester`."""

        self.config = config
        self.http_client = http_client
        # Accumulates the confirmed missing rate limit findings as `Vulnerability` objects.
        self.findings = []
        # Stores per-endpoint detection outcomes for use by `RateLimitBypassTester`.
        self.detection_results = {}

    def detect_rate_limit(
        self, endpoint_url, method="POST", body=None, total_requests=None, rps=None
    ):
        """Sends `total_requests`, requests, to `endpoint_url` at `rps` requests per second, recording status codes, elapsed
        time, and rate limit headers. Creates a 'Medium' `Vulnerability` when no rate limiting is detected, and stores the outcome
        in `self.detection_results`."""

        # Falls back to the configuration defaults, when `total_requests`, or `rps`, are not provided by the caller.
        if total_requests is None:
            total_requests = getattr(self.config, "rate_limit_config", {}).get(
                "total_requests", 100
            )
        if rps is None:
            rps = getattr(self.config, "rate_limit_config", {}).get("rps", 10)

        # Uses the safe test, dummy email on login-pattern endpoints, to avoid JWT generation, of account lockouts.
        if body is None and any(
            pattern in endpoint_url
            for pattern in ["/login", "/signin", "/auth", "/token"]
        ):
            body = {
                "email": RATE_LIMIT_TEST_EMAIL,
                "password": RATE_LIMIT_TEST_PASSWORD,
            }

        # Calculates the sleep interval from `rps`, so that requests are spaced evenly across each second.
        sleep_interval = 1 / rps
        # Collects the per-request result dictionaries, for post-loop analysis.
        results = []
        logger.info(
            "Starting rate limit detection on %s: %d requests at %d req/s.",
            endpoint_url,
            total_requests,
            rps,
        )

        # Sends each request in sequence, recording status, elapsed time, and rate limit headers per response.
        for request_number in range(1, total_requests + 1):
            try:
                if method.upper() == "GET":
                    response, _ = self.http_client.get(endpoint_url)
                else:
                    response, _ = self.http_client.post(endpoint_url, json_body=body)
            except Exception as exc:
                logger.warning(
                    "Request %d to %s raised an exception: %s",
                    request_number,
                    endpoint_url,
                    exc,
                )
                # Sleeps before continuing, so that the request pacing is maintained despite the exception.
                time.sleep(sleep_interval)
                continue

            # Converts the elapsed time from seconds, to milliseconds, for consistent results storage.
            elapsed_ms = response.elapsed.total_seconds() * 1000
            headers = response.headers

            # Logs a warning when a response, other than 401 or 429, is returned on a login endpoint test.
            if body and body.get("email") == RATE_LIMIT_TEST_EMAIL:
                if response.status_code not in (401, 429):
                    logger.warning(
                        "Anomalous status %s on login rate limit test at request %d for %s.",
                        response.status_code,
                        request_number,
                        endpoint_url,
                    )

            # Records the full result for the request, including all the rate limit response headers.
            results.append(
                {
                    "request_number": request_number,
                    "status_code": response.status_code,
                    "elapsed_ms": elapsed_ms,
                    "x_ratelimit_remaining": headers.get("X-RateLimit-Remaining"),
                    "x_ratelimit_limit": headers.get("X-RateLimit-Limit"),
                    "x_ratelimit_reset": headers.get("X-RateLimit-Reset"),
                    "retry_after": headers.get("Retry-After"),
                }
            )

            time.sleep(sleep_interval)

        # Analyses the collected results, to determine whether rate-limiting was enforced.
        count_429 = sum(1 for r in results if r["status_code"] == 429)
        # Finds the request number at which the first 429 response was returned.
        first_429_at = next(
            (r["request_number"] for r in results if r["status_code"] == 429),
            None,
        )

        # Defaults to 'False', and only sets to 'True' when the average post-threshold response times indicate soft throttling.
        response_time_anomaly = False
        # Calculates the average response times before, and after, the 429 threshold to detect soft rate limiting.
        if first_429_at is not None and first_429_at > 1:
            times_before = [
                r["elapsed_ms"] for r in results if r["request_number"] < first_429_at
            ]
            times_after = [
                r["elapsed_ms"] for r in results if r["request_number"] >= first_429_at
            ]
            # FLags a response time anomaly, when the post-threshold responses are at least twice as slow.
            if times_before and times_after:
                avg_before = statistics.mean(times_before)
                avg_after = statistics.mean(times_after)
                # Uses a 2x multiplier as the threshold, for a meaningful response time slowdown.
                if avg_after > avg_before * 2:
                    response_time_anomaly = True
                    logger.info(
                        "Response time anomaly detected on %s: avg before threshold %.1fms, after %.1fms.",
                        endpoint_url,
                        avg_before,
                        avg_after,
                    )

        # COmbines the 429 count, and response time anomaly into a single boolean, rate-limited result.
        rate_limited = count_429 > 0 or response_time_anomaly

        # Flags a 'Medium' finding, when no rate-limiting evidence was detected across all requests.
        if not rate_limited:
            vuln = Vulnerability(
                vuln_type="Missing Rate Limiting",
                severity="Medium",
                endpoint=endpoint_url,
                method=method.upper(),
                # Records the total request count, and rate as machine readable evidence.
                evidence=(
                    f"Zero 429 responses and no response time anomaly detected "
                    f"across {total_requests} requests at {rps} req/s."
                ),
                # Describes the missing rate-limiting, and its risk in plain language for the report.
                description=(
                    f"No rate limiting detected on {endpoint_url} after "
                    f"{total_requests} requests at {rps} req/s. Endpoints without "
                    f"rate limiting are vulnerable to credential stuffing and "
                    f"brute force attacks."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "MEDIUM: Missing rate limiting confirmed on %s.", endpoint_url
            )

        # Stores the detection verdict, and threshold position for use by `RateLimitBypassTester`.
        self.detection_results[endpoint_url] = {
            "rate_limited": rate_limited,
            "threshold": first_429_at,
            "first_429_at": first_429_at,
        }
        logger.info(
            "Rate limit detection complete for %s: rate_limited=%s, first_429_at=%s.",
            endpoint_url,
            rate_limited,
            first_429_at,
        )

    def _identify_critical_endpoints(self, endpoints):
        """Filters `endpoints` to those whose URL paths matches common authentication, and credential-handling route
        segments on Juice SHop, and DVWA. Then returns a list of matching `Endpoint` objects."""

        # Defines the path patterns that identify authentication, and credential endpoints on Juice Shop, and DVWA.
        critical_patterns = [
            "/login",
            "/signin",
            "/auth",
            "/password",
            "/reset",
            "/otp",
            "/verify",
            "/register",
            "/signup",
            "/token",
            "/api/auth",
        ]
        critical = []
        # Checks each endpoint URL against the critical path patterns, and collects matches.
        for endpoint in endpoints:
            # Appends the endpoint if any critical pattern is found within its URL.
            if any(pattern in endpoint.url for pattern in critical_patterns):
                critical.append(endpoint)
                logger.debug(
                    "Identified critical endpoint for rate limit testing: %s",
                    endpoint.url,
                )
        return critical

    def detect_all(self, endpoints):
        """Calls '_identify_critical_endpoints` on `endpoints`, then runs `detect_rate_limit` on each result, populating
        `self.findings`, and `self.detection_results`."""

        critical_endpoints = self._identify_critical_endpoints(endpoints)
        logger.info(
            "Running rate limit detection against %d critical endpoint(s).",
            len(critical_endpoints),
        )
        # Iterates each critical endpoint, and runs rate-limiting detection against it.
        for endpoint in critical_endpoints:
            self.detect_rate_limit(endpoint.url, method=endpoint.method)

    def get_findings(self):
        """Returns `self.findings` accumulated acrosds all the rate-limiting detection tests."""
        return self.findings