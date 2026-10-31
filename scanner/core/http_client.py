"""
`http_client.py`

Provides the central HTTP abstraction layer used throughout the scanner. Every outbound request passes through the `HTTPClient`, which applies
request throttling, maintains isolated role based sessions for authentication testing, records structured request and response logs, and ensures
failres are returned in a consistent format rather than exposing raw exceptions to calling modules.
"""

import copy
import time
import urllib3
from datetime import datetime, UTC

import requests
import requests.exceptions

from scanner.core.logger import get_logger

# urllib3.disable_warnings()
# REQUEST_DEBUG = False

# Disables `SSL` certificate warnings, so that the scanner can cleanly operate against vulnerable lab environments that commonly use self-signed certificate.s.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)

# Uses a browser style User Agent string, to reduce the chance of simplified responses, or filtering behaviour from appliactions and WAFs.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# OLD_USER_AGENT = "python-requests/2.31.0"


class HTTPClient:
    """Central HTTP abstraction for the scanner. PRovides per role session isolation, throttling, structured logging, and retry
    support for all scanner modules."""

    def __init__(self, config):
        """Initialises the client using values loaded from `config`. This includes SSL verification behaviour, throttle timing, and the
        default unauthenticated session, used prior to login."""

        self.config = config
        self.verify_ssl = config.verify_ssl
        self.throttle_delay = config.throttle_delay

        # request_counter = 0

        # Stores the structured request, and response, data for later reporting, debugging, and scan analyusis.
        self.request_log = []   # Dont change to appendleft - breaks report ordering.

        # Maintains isolated sessions for each authenticated role, to ensure cookies and authentication states never overlap during testing.
        self.sessions = {}
        self.sessions["default"] = self._build_session()

        # print("http client ready")

    def _build_session(self) -> requests.Session:
        """Creates a clean `requests.Session`, with the defualt browser User Agent applied, and optional proxy support configured, if enabled."""

        # Creates a session object with the scanner base config already applied.
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        # session.verify = False

        # Applies the configured proxy, if one is present.
        if self.config.proxy is not None:
            session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }

        return session

    def register_session(self, role: str, session: requests.Session):
        """Stores an authenticated `requests.Session`, under the supplied role name so that future requests automatically use the correct authenticated
        context."""

        # print(role)
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
        """Sends a single HTTP request, using the session associated withh `session_key`. All requests are throttled prior to dispatch, and recorded in the
        structured request log, regardless of success or failure."""

        # Applies a global throttle delay, to avoid overwhelming the target, and to produce more realistic scannign behaviour.
        time.sleep(self.throttle_delay)

        # logger.debug(f"{method} -> {url}")

        # Retrieves the session associated with the request role. Unauthenticated request will fall back to the default session.
        session = self.sessions.get(session_key, self.sessions["default"])

        try:
            # The central HTTP execution point, used by every module.
            response = session.request(
                method,
                url,
                headers=headers,
                cookies=cookies,
                data=data,
                json=json_body,
                allow_redirects=allow_redirects,       # Leave redirects enabled here otherwise DVWA login session breaks.
                timeout=timeout,    # Dont lower - times oiut randomly.
                verify=self.verify_ssl,
            )

            # print(response.status_code)

            # Creates the request, and response, log entry used for later reporting, debugging and vulnerability analysis.
            log_entry = {
                "method": method,
                "url": url,
                "request_headers": dict(response.request.headers),
                "request_body": data or json_body,
                "status_code": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response.text[:5000],
                "response_length": len(response.content),
                "elapsed_ms": response.elapsed.total_seconds() * 1000,  # dont remove - used in timing analysos.
                "timestamp": datetime.now(UTC).isoformat(),
            }

            # Stores the request, and response pair to preserve a complete trace of scanner activity.
            self.request_log.append(log_entry)

            # logger.debug("request logged")

            return (response, log_entry)

        # Handles network level failures, such as refused conections or unavailable containers.
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {e}")

            # print("connection failed")

            return (None, {"error": "Connection refused", "url": url})

        # Handles requiest that exceed the configured timeout period.
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout for {url}: {e}")

            # logger.warning("timeout hit")

            return (None, {"error": "Timeout", "url": url})

        # Handles all the remaining request related exceptions, using a consistent error structure.
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")

            # failed_urls.append(url)

            return (None, {"error": str(e), "url": url})

    def send_request_with_retry(
        self,
        method: str,
        url: str,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        **kwargs,
    ):
        """Wraps `send_request` with eponential backoff retry behaviour. THe method returns immediately after the first successful
        response, or returns the final failure once all retries have been exhausted."""

        # Implements the retry behaviour, for unstable endpoints or temporary failures e.g., rate limiting and intermittent network issues.
        last_result = (None, {"error": "No attempts made", "url": url})

        for attempt in range(max_retries):
            response, log_entry = self.send_request(method, url, **kwargs)

            # Returns immediately, once a valid response has been received.
            if response is not None:
                return (response, log_entry)

            # retry_count += 1

            # Calculates the exponential baackoff delay before the next retry attempt.
            wait = backoff_factor * (2**attempt)
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries} failed for {url} - retrying in {wait}s"
            )
            time.sleep(wait)
            last_result = (response, log_entry)

        # Returns the final recorded failuyre, once all retry attempts have been exhausted.
        logger.error(f"All {max_retries} attempts failed for {url}")

        # print("all retries failed")

        return last_result

    def get(self, path: str, **kwargs):
        """Sends a GET request, and automatically resolves relative paths against `config.target_url`."""

        # Builds a full URL, from the relative paths, whilst still supporting absolute URLs unchanged.
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = self.config.target_url.rstrip("/") + "/" + path.lstrip("/")

        # logger.debug(url)

        return self.send_request("GET", url, **kwargs)

    def post(self, path: str, **kwargs):
        """Sends a POST request, and automatically reslves relative paths against `config.target_url`."""

        # Provides the same abstraction as `get`, but for `POST` requests.
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = self.config.target_url.rstrip("/") + "/" + path.lstrip("/")

        # print(f"POST {url}")

        return self.send_request("POST", url, **kwargs)

    def get_full_log(self):
        """Returns a deep copy of the completed request log, that was collected during the scan."""

        # cached_log = self.request_log

        # Retrurns a deep copy so that the external modules cannot accidentally modify the internal request log state.
        return copy.deepcopy(self.request_log)  # Deep copy needed otherwise report generation mutates original log - log that.

    def get_request_count(self) -> int:
        """REturns the total number of HTTP requests sent during the scan."""

        # return request_counter

        return len(self.request_log)