"""
`test/test_comparator.py`

Unit tests for `scanner/core/comparator.py`. Verifies that `ResponseComparator` correctly identifies status code matches, 
body-length differences withi the 10% threshold,  and that `extract_sensitive_fields` detects known sensitive field names,
such as `email`, `token`, and `password` in JSON structures.
"""

import pytest
from unittest.mock import MagicMock

from scanner.core.comparator import ResponseComparator


def _make_response(status_code=200, content=b"", text=""):
    """ Builds a mock response object with `status_code`, `content`, and `text` attributes."""

    # Uses `MagicMock` to avoid real HTTP requests, whilst satisfing the attribute access pattern in `ResponseComparator.`
    resp = MagicMock()
    resp.status_code = status_code
    # `content` is set as bytes, to match the `requests.Response.content` type used in `compare_body_length`.
    resp.content = content
    resp.text = text
    return resp


class TestCompareStatus:
    """ Tests that `compare_status` correctly identifies matching, and mismatching, HTTP status codes."""

    def test_same_status_returns_true(self):
        """ Verifies that two responses, with identical status codes, return `True` from `compare_status`."""

        # Both responses return 200 OK.
        resp_a = _make_response(status_code=200)
        resp_b = _make_response(status_code=200)
        assert ResponseComparator.compare_status(resp_a, resp_b) is True

    def test_different_status_returns_false(self):
        """ Verifies that two responses with a different status code returns `False` from `compare_status"""

        # SImulates a role comparison. One user receives 200, the other 403, indicating an access control difference.
        resp_a = _make_response(status_code=200)
        resp_b = _make_response(status_code=403)
        assert ResponseComparator.compare_status(resp_a, resp_b) is False


class TestCompareBodyLength:
    """ Tests `compare_body_length` edge cases, including empty bodies and responses, within and outside the 10% threshold. """

    def test_identical_lengths_return_true(self):
        """ Verifies that two responses with identical body sizes returns `True`."""

        # Uses 500 bytes of repeated characters to represent two structurally similar API responses.
        resp_a = _make_response(content=b"a" * 500)
        resp_b = _make_response(content=b"b" * 500)
        assert ResponseComparator.compare_body_length(resp_a, resp_b) is True

    def test_both_empty_returns_true(self):
        """ Verifies that one empty, and one non-empty response are treated as different."""

        # An empty response with a 500-byte response indicates a content difference. 
        resp_a = _make_response(content=b"")
        resp_b = _make_response(content=b"")
        assert ResponseComparator.compare_body_length(resp_a, resp_b) is True

    def test_one_empty_returns_false(self):
        """ Verifies that two responses within the 10% size threshold return `True`."""

         # 1000 bytes vs 1050 bytes is a 4.8% difference, which is within the default 10% threshold.
        resp_a = _make_response(content=b"")
        resp_b = _make_response(content=b"a" * 500)
        assert ResponseComparator.compare_body_length(resp_a, resp_b) is False

    def test_within_threshold_returns_true(self):
        """ Verifies that two responses within the 10% size threshold return `True`."""

         # 1000 bytes vs 1050 bytes is a 4.8% difference, which is within the default 10% threshold.
        resp_a = _make_response(content=b"a" * 1000)
        resp_b = _make_response(content=b"b" * 1050)
        assert ResponseComparator.compare_body_length(resp_a, resp_b) is True

    def test_outside_threshold_returns_false(self):
        """ Verifies that two responses where the size difference exceeds 10% will `False`."""
       
        # 1000 bytes vs 2000 bytes is a 50% difference, far out the 10% threshold.
        resp_a = _make_response(content=b"a" * 1000)
        resp_b = _make_response(content=b"b" * 2000)
        assert ResponseComparator.compare_body_length(resp_a, resp_b) is False


class TestExtractSensitiveFields:
    """ Tests that `extract_sensitive_fields` detects known sensitive key names in flat, and nested, JSON structures."""

    def test_detects_email_field(self):
        """ Verifies that a JSON body containing an `email` key is detected as a sensitive field."""

        # Represents a partial JS user object where `email` is a PI field.
        body = {"email": "user_a@test.com", "username": "user_a"}
        result = ResponseComparator.extract_sensitive_fields(body)
        # Confirms `email` is returned as a detected sensitive field.
        assert "email" in result

    def test_detects_token_field(self):
        """ Verifies that a JSON body containing a `token` key is detected as a sensitive field."""

        # Represents a JS login response where `token` holds the JWT bearer credential.
        body = {"token": "eyJhbGciOiJSUzI1NiJ9", "status": "success"}
        result = ResponseComparator.extract_sensitive_fields(body)
        # Confirms that `token` is returned ad a detected sensitive field.
        assert "token" in result

    def test_detects_password_field(self):
        """ Verifies that a JSON body containing a `password` key is detected as a sensitive field."""

        # Represents a scenario where a hashed password is inadvertently exposed, in an API response body.
        body = {"password": "hashed_value", "role": "customer"}
        result = ResponseComparator.extract_sensitive_fields(body)
        assert "password" in result

    def test_non_sensitive_fields_not_returned(self):
        """ Verifies that a JSON body with no sensitive field names returns an empty dictionary."""

        # All keys in this body are generic ans non-sensitive metadata fields.
        body = {"status": "ok", "count": 5, "page": 1}
        result = ResponseComparator.extract_sensitive_fields(body)
        # Confirms that no sensitive fields are detected, when none are present.
        assert result == {}

    def test_detects_sensitive_field_nested_in_json(self):
        """ Verifies that `extract_sensitive_fields` detects sensitive keys, nested inside a `data` wrapper object."""

        # Represents the JS `authentication` response, where user data is wrapped under `data` key.
        body = {"data": {"id": 1, "email": "user_a@test.com"}}
        result = ResponseComparator.extract_sensitive_fields(body)
    # Confirms the recursive walk in `extract_sensitive_fields` reached the nested `email` key.
        assert "email" in result


class TestIsAccessGranted:
    """ Tests that `is_access_granted` correctly distinguishes real access, from any denial responses or empty bodies."""

    def test_200_with_content_grants_access(self):
        """ Verifies that a 200 response with sufficient conten, and no denial phrases, returns `True`."""

        # Builds a response with 300 bytes of content, exceeding the `MIN_CONTENT_LENGTH` threshold of 200.
        resp = _make_response(
            status_code=200,
            content=b"x" * 300,
            text="x" * 300,
        )
        comparator = ResponseComparator()
        assert comparator.is_access_granted(resp) is True

    def test_403_denies_access(self):
        """ Verifies that 403 response returns `False`, from `is_access_granted`."""
        # A 403 is the standard JS response when a non-admin user attempts to access an admin-only endpoint.
        resp = _make_response(status_code=403, content=b"forbidden", text="forbidden")
        comparator = ResponseComparator()
        assert comparator.is_access_granted(resp) is False

    def test_200_with_denial_phrase_denies_access(self):
        """ Verifies  a 200 response containing `access denied` returns `False`."""
        # Simulates a server that wraps denial messages in a 200 envelope - common pattern on some targets.
        resp = _make_response(
            status_code=200,
            content=b"access denied" * 20,
            text="access denied" * 20,
        )
        comparator = ResponseComparator()
        assert comparator.is_access_granted(resp) is False

    def test_200_with_too_little_content_denies_access(self):
        """ Verifies that  200 response, with fewer than `MIN_CONTENT_LENGTH` bytes, returns `False`."""
        # Four bytes is way below the 200-byte `MIN_CONTENT_LENGTH`.
        resp = _make_response(status_code=200, content=b"tiny", text="tiny")
        comparator = ResponseComparator()
        assert comparator.is_access_granted(resp) is False