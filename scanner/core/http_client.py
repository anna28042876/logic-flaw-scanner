# `scanner/core/http_client.py`.

import copy
import time
import urllib3
from datetime import datetime, UTC

import requests
import requests.exceptions

from scanner.core.logger import get_logger

# Disable `SSL` warnings so the scanner can operate cleanly against lab targets that commonly use self-signed
# certificates (e.g., Dockerised vulnerable apps).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)

# Default browser-like user agent to avoid WAFs or apps returning simplified responses.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class HTTPClient:
    # Central HTTP abstraction for the scanner.
    # Every request from the module (Auth, crawling, IDOR testing, etc.,) flows through here.
    # Thius ensures consistent handling of throttling, logging, retries, and session isolation.

    def __init__(self, config):
        # Config object is shared across the scanner (target URL, proxy, SSL behaviour, etc.,).
        self.config = config
        self.verify_ssl = config.verify_ssl
        self.throttle_delay = config.throttle_delay

        # Stores structured request/response logs and used later for reporting and analysis.
        self.request_log = []

        # Session pool keyed by role (ew.g., `userA`, `userB`).
        # Critical for IDOR testing so that authenticated contexts never mix.
        self.sessions = {}
        self.sessions["default"] = self._build_session()

    def _build_session(self) -> requests.Session:
        # Creates a clean requests session with the base configuration applied.
        # Used for default traffic and duplicated per authenticated role.
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        # Optional proxy support (e.g., Burp Suite) for manual inspection/debugging.
        if self.config.proxy is not None:
            session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }

        return session

    def register_session(self, role: str, session: requests.Session):
        # Called by `SessionManager` after successful authentication.
        # Stores a fully authenticated session tied to a specific role.
        self.sessions[role] = session

    def send_request(
        self,
        method: str,
        url: str,
        headers=None,
        cookies=None,
        data=None,
        json_body=None,
        allow_redirects=True,
        timeout=30,
        session_key: str = "default",
    ):
        # GLobal throttling to prevent overwhelming the target.
        # This is important for realism but also to avoid rate-limiting during scans.
        time.sleep(self.throttle_delay)

        # Selects sessions based on roles; fallbacks to the default role for unauthenticated requests.
        session = self.sessions.get(session_key, self.sessions["default"])

        try:
            # Core HTTP execution point used by all the scanner modules.
            response = session.request(
                method,
                url,
                headers=headers,
                cookies=cookies,
                data=data,
                json=json_body,
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=self.verify_ssl,
            )

            # Structured logging for later vulnerability analysis and reporting.
            # Includes truncated response bodies to keep memory usage manageable.
            log_entry = {
                "method": method,
                "url": url,
                "request_headers": dict(response.request.headers),
                "request_body": data or json_body,
                "status_code": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response.text[:5000],
                "response_length": len(response.content),
                "elapsed_ms": response.elapsed.total_seconds() * 1000,
                "timestamp": datetime.now(UTC).isoformat(),
            }

            # Persists request/response pairs for full scan traceability.
            self.request_log.append(log_entry)
            return (response, log_entry)

        # Network-level failures (target offline, containers not running, etc.,)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {e}")
            return (None, {"error": "Connection refused", "url": url})

        # Timeout handling for slow or intentionally delayed endpoints.
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout for {url}: {e}")
            return (None, {"error": "Timeout", "url": url})

        # Catch-all for any other request-related failures.
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return (None, {"error": str(e), "url": url})

    def send_request_with_retry(
        self,
        method: str,
        url: str,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        **kwargs,
    ):
        # Retry wrapper used by higher-level modules when stability is required.
        # Implements exponential backoffs to handle unreliable endpoints or rate-limiting.
        last_result = (None, {"error": "No attempts made", "url": url})

        for attempt in range(max_retries):
            response, log_entry = self.send_request(method, url, **kwargs)

            # Success path: immediately return to usable responses.
            if response is not None:
                return (response, log_entry)

            # Backoffs increase per attempt (1s, 2s, 4s, etc., by default).
            wait = backoff_factor * (2**attempt)
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries} failed for {url} - retrying in {wait}s"
            )
            time.sleep(wait)
            last_result = (response, log_entry)

        # All retries exhausted, returns last failure for caller handling.
        logger.error(f"All {max_retries} attempts failed for {url}")
        return last_result

    def get(self, path: str, **kwargs):
        # Convenience wrapper that builds full URLs from relative paths.
        # Passes absolute URLs through unchanged, so callers can use either format.
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = self.config.target_url.rstrip("/") + "/" + path.lstrip("/")
        return self.send_request("GET", url, **kwargs)

    def post(self, path: str, **kwargs):
        # Same abstraction as `GET` but for `POST` requests.
        # Passes absolute URLs through unchanged, so callers can use either format.
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = self.config.target_url.rstrip("/") + "/" + path.lstrip("/")
        return self.send_request("POST", url, **kwargs)

    def get_full_log(self):
        # Returns a deep copy to protect internal states.
        # Used by reporting/export modules at the end of a scan.
        return copy.deepcopy(self.request_log)

    def get_request_count(self) -> int:
        # Useful for metrics, progress tracking, and scan summaries.
        return len(self.request_log)