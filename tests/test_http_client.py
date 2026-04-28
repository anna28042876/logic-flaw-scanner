"""
`tests/test_http_client.py`

Unit tests for `scanner/core/http_client.py`.Verifies that `send_requests_with_retry`, retries corectly
when `send_request` returns `None`, and returns the successful response once one arrives. Uses `unittest.mock.patch`
to avoid real HTTP requests against JS, or DVWA duriung the test run.
"""

import pytest
from unittest.mock import MagicMock, patch

from scanner.core.http_client import HTTPClient


def _make_config(
    target_url="http://localhost:3000",
    verify_ssl=False,
    throttle_delay=0.0,
    proxy=None,
):
    """ Builds, and returns, a `ScanConfig` mock up, for use in `HTTPClient` tests."""
    # Uses `MagicMock` to avoid loading a real YAML file, whilst still satisfying the attribute access pattern in `HTTPClient.__init__`.
    config = MagicMock()
    config.target_url = target_url
    # `verify_ssl` is set to `False` in order to match the Docker lab environment, where containers use self-signed certificates.
    config.verify_ssl = verify_ssl
    # `throttle_delay` is set to 0, to prevent test slowdown from the inter-request wait that `send_request` applies.
    config.throttle_delay = throttle_delay
    # `proxy` is set to `None` in order to disable Burp Suite routing, which is not needed during unit tests.
    config.proxy = proxy
    return config


class TestSendRequestWithRetry:
    """ Tests that `send_request_with_retry` retries on `None` responses, and returns the first successful."""

    def test_returns_immediately_on_first_success(self):
        """ Verifies that `send_request_with_retry` returns after one call, when the first attempt succeeds."""
        config = _make_config()
        client = HTTPClient(config)

        # Builds a mock response tnhat represents a successful JS API response.
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Patches `send_request` to return a successful response on the first attempt, - sims stable connection.
        with patch.object(client, "send_request", return_value=(mock_response, {})) as mock_send:
            response, log = client.send_request_with_retry("GET", "http://localhost:3000/api/Products")
            # Confirms that the response status code matches the mocked 200 return value.
            assert response.status_code == 200
            # Confirms that `send_request` was called exactly once, meaning that no retries were attempted.
            assert mock_send.call_count == 1

    def test_retries_on_none_response_then_succeeds(self):
        """ Verifies that `send_request_with_retry` retries twice on `None`, and then returns the third successful response."""
        config = _make_config()
        client = HTTPClient(config)

        # Builds a mock up  response that represents a successful recovery after two connection failures.
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Defines three sequential return values - two failures returning `None`, followed by one success.
        side_effects = [
            (None, {"error": "Connection refused", "url": "http://localhost:3000/api/Products"}),
            (None, {"error": "Connection refused", "url": "http://localhost:3000/api/Products"}),
            (mock_response, {}),
        ]
        # Patches `send_request` with the subsequent side effects, and patches `time.sleep` to skip the backoff delay.
        with patch.object(client, "send_request", side_effect=side_effects) as mock_send:
            with patch("time.sleep"):
                response, log = client.send_request_with_retry(
                    "GET",
                    "http://localhost:3000/api/Products",
                    max_retries=3,
                    backoff_factor=0.0,
                )
            # Confirms that the successful response from the third attempt is actually returned.
            assert response.status_code == 200
            # Confirms `send_request` was called exactly three times, matching the two failures plus one success.
            assert mock_send.call_count == 3

    def test_returns_last_failure_when_all_retries_exhausted(self):
        """ Verifies `send_request_with_retry` returns `None`, for the response when all the attempts fail."""
        config = _make_config()
        client = HTTPClient(config)

        # Patches `send_request` to return `None`, on every attempt - completely unreachable endpoint.
        with patch.object(client, "send_request", return_value=(None, {"error": "Timeout", "url": ""})):
            with patch("time.sleep"):
                response, log = client.send_request_with_retry(
                    "GET",
                    "http://localhost:3000/api/Products",
                    max_retries=3,
                    backoff_factor=0.0,
                )
            # Confirms that `response` is still `None` after all retries are exhausted, allowing the caller to handle the failure.
            assert response is None

    def test_retry_count_does_not_exceed_max_retries(self):
        """ Verifies that `send_request_with_retry` calls `send_request`, at most `max_retries` times when all fail"""
        config = _make_config()
        client = HTTPClient(config)

        # Patches `send_request` to always return `None`- every attempt fails and all retries are consumed.
        with patch.object(client, "send_request", return_value=(None, {})) as mock_send:
            with patch("time.sleep"):
                client.send_request_with_retry(
                    "GET",
                    "http://localhost:3000/api/Products",
                    max_retries=3,
                    backoff_factor=0.0,
                )
            # Confirms that `send_request` was called exactly three times, and that no additional attempts were made.
            assert mock_send.call_count == 3


class TestRequestCount:
    """ Tests that `get_request_count` accurately reflects the number of requests, logged by `HTTPClient`."""

    def test_request_count_starts_at_zero(self):
        """ Verifies that a newly created `HTTPClient` reports zero requests, before any are sent."""
        config = _make_config()
        client = HTTPClient(config)
        # Confirms the request log is empty immediately after construction, prior scan activity beginning.
        assert client.get_request_count() == 0