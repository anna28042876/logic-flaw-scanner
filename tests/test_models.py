"""
`tests/test_models.py`

Unit tests for `scanner/core/models.py`. Verifies the that `Endpoint`, `Vulnerability`, and `ScanResult` dataclasses are created with the 
corect default values, and that `to_dict()` produces full serialisable dictionaries that match the expected structure for downuse by 
`html_report.py`, and `json_report.py`.
"""


import pytest

from scanner.core.models import Endpoint, Vulnerability, ScanResult


class TestEndpoint:
    """ Test `Endpoint` creation with required, and default field values and `to_dict()` output."""

    def test_endpoint_requires_url(self):
        """ Verifies that an `ENdpoint` can be created with only a URL, and receives the correct method and content type defaults."""

        # Uses the JS products API path, as a representativbe real endpoint URL.
        endpoint = Endpoint(url="http://localhost:3000/api/Products")
        #  COnfirms that the URL was stored correctly on the dataclass.
        assert endpoint.url == "http://localhost:3000/api/Products"
        # Confirms that the default HTTP method is `GET`, which is tyhe method used by all forced browsing checks.
        assert endpoint.method == "GET"
        # Confirms that the default content type is `text/html`, which is the crawler assumption before a response is received.
        assert endpoint.content_type == "text/html"

    def test_endpoint_default_requires_auth_is_false(self):
        """ Verifies that `requires_auth` defaults to `False`, on a newly created `Endpoint`."""

        #JS exposes several unauthenticated endpoints, so `requires_auth` must default to `False`.
        endpoint = Endpoint(url="http://localhost:3000/api/Products")
        assert endpoint.requires_auth is False

    def test_endpoint_default_parameters_is_empty_list(self):
        """ Verifies that `parameters` defaults to an empty list, rather than a shared mutable default."""

        # Uses the `whoami` endpoint, which the scanner checks to confirm authenticated access.
        endpoint = Endpoint(url="http://localhost:3000/rest/user/whoami")
        # COnfirms that `parameters` is an empty l;ist, before the `PArameterEnumerator` runs against the endpoint.
        assert endpoint.parameters == []

    def test_endpoint_to_dict_returns_dict(self):
        """ Verifies that `to_dict()` returns a plain dictionary, containing the `url` key."""
        # Uses the JS API path as the test endpoint.
        endpoint = Endpoint(url="http://localhost:3000/api/Users")
        result = endpoint.to_dict()
        # Confirms that `to_dict()` reutnrs a plain Python dictionary, not a dataclass instance.
        assert isinstance(result, dict)
        # COnfirms that the `url` key, in the dictionary, matches the value passed at construction.
        assert result["url"] == "http://localhost:3000/api/Users"

    def test_endpoint_discovered_by_roles_is_empty_by_default(self):
        """ Verifies that `discovered_by_roles` defaults to an empty list on a newly created `Endpoint`."""

        #`discovered_by_rates` is populated by the crawler, when multiple roles visit the same endpoint.
        endpoint = Endpoint(url="http://localhost:3000/api/Feedbacks")
        assert endpoint.discovered_by_roles == []


class TestVulnerability:
    """ Tests `Vulnerability` creation with required fields, and `to_dict()` output structure."""

    def test_vulnerability_creation_with_required_fields(self):
        """ Verifies that a `VUlnerability` can be created with all five required fields, and correct defaults."""

        # Constructs a vulnerability matching the forced browsing finding, produced by `unauth_access.py`.
        vuln = Vulnerability(
            vuln_type="Forced Browsing - Unprotected Resource",
            severity="Medium",
            endpoint="http://localhost:3000/api/Products",
            method="GET",
            description="Path accessible without authentication.",
        )
        # Confirms that `vuln_type` was stored correctly, and matches the string used in the reporting output.
        assert vuln.vuln_type == "Forced Browsing - Unprotected Resource"
        # Confirms that the severity is `Medium`, consistent with the `unauth_access.py` finding severity. 
        assert vuln.severity == "Medium"
        # Confirms that `remediation` defaults to an empty string, when no guidance is provided. 
        assert vuln.remediation == ""
        #Confirms that `request_log` defaults to an empty list, before any requests are attached.
        assert vuln.request_log == []

    def test_vulnerability_to_dict_contains_all_fields(self):
        """ Verifies that `to_dict()` includes `vuln_type`, `severity`, `endpoint`, `method`, and `description` keys."""

        # Builds a vulnerability matching the session termination finding produced by `session_termination.py`.
        vuln = Vulnerability(
            vuln_type="Session Not Invalidated on Logout",
            severity="Medium",
            endpoint="http://localhost:3000",
            method="GET",
            description="Session token remains valid after logout.",
        )
        result = vuln.to_dict()
        # Confirms the result is a plain dictionary suitable for the JSON serialisation, in `json_report.py`.
        assert isinstance(result, dict)
        # Iterates through the five required report fields, and confirms that each is present in the serialised dictionary.
        for key in ("vuln_type", "severity", "endpoint", "method", "description"):
            assert key in result

    def test_vulnerability_to_summary_format(self):
        """ Verifies that `to_summary()` returns the expected bracket-prefixed string format."""

        # Constructs a vulnerability matching the JWT token reuse finding, produced by `session_fixation.py`.
        vuln = Vulnerability(
            vuln_type="JWT Token Reuse",
            severity="Medium",
            endpoint="http://localhost:3000/rest/user/login",
            method="POST",
            description="Server issued identical JWT for two separate logins.",
        )
        summary = vuln.to_summary()
        # Confirms that the summary string follows the `[Severity] Type at Method URL` format printed in console output.
        assert summary == "[Medium] JWT Token Reuse at POST http://localhost:3000/rest/user/login"

    def test_vulnerability_evidence_defaults_to_empty_dict(self):
        """ Verifies that `evidence` defaults to an empty dictionary, when no evidence is supplied."""\

        # Creates a workflow bypass vulnerability without passing an `evidence` argument.
        vuln = Vulnerability(
            vuln_type="Workflow Bypass - Step Skip",
            severity="High",
            endpoint="http://localhost:3000/rest/basket/1/checkout",
            method="POST",
            description="Final step succeeded without intermediate steps.",
        )
        # Confirms that `evidence` is an empty dictionary, rather than just `None` when not provided.
        assert vuln.evidence == {}


class TestScanResult:
    """ Tests `ScanResult` creation with the required fields, default values, and the `to_dict()` output."""
    
    def _make_scan_result(self):
        """ Builds, and returns, a `ScanResult` with the six required fields populated."""
        # Uses timestamps, and a duration, that emulates a real JS run, for representative values.
        return ScanResult(
            target_url="http://localhost:3000",
            scan_start="2026-04-24T12:54:06.099119",
            scan_end="2026-04-24T12:54:11.659619",
            scan_duration_seconds=5.56,
            endpoints_discovered=0,
            parameters_found=0,
        )

    def test_scan_result_creation(self):
        """ Verifies that a `ScanResult` is created with the correct `target_url`, and zero discovery counts."""
        result = self._make_scan_result()
        # Confirms that the `target_url` matches the Juice Shop base URL, passed at construction.
        assert result.target_url == "http://localhost:3000"
        # Confirms `endpoints_discovered` is zero, which is the expected value for the JS static crawler run.
        assert result.endpoints_discovered == 0

    def test_scan_result_default_vulnerabilities_is_empty_list(self):
        """ Verifies that `vulnerabilities` defaults to an empty list, rather than JUST a shared mutable default."""
        result = self._make_scan_result()
        # Confirms that `vulnerabilities` is an empty list, prior to any modules appending their findings.
        assert result.vulnerabilities == []

    def test_scan_result_default_total_requests_is_zero(self):
        """ Verifies that `total_requests` defaults to 0, on a newly created `ScanResult`."""
        result = self._make_scan_result()
        # Confirms that `total_requests` starts at 0, prior to `HTTPClient.get_request_count()` being read at the end of the scan.
        assert result.total_requests == 0

    def test_scan_result_scan_id_defaults_to_empty_string(self):
        """ Verifies that `scan_id` defaults to an empty string on a newly created `ScanResult`."""
        result = self._make_scan_result()
        # Confirms that `scan_id` is an empty string, rather than just `None`, matching the field definition in `models.py`.
        assert result.scan_id == ""

    def test_scan_result_to_dict_contains_target_url(self):
        """ Verifies that `to_dict()` returns a dictionary containing the `target_url` key."""
        result = self._make_scan_result()
        as_dict = result.to_dict()
        # Confirms that the result is a plain dictionary - the format expected by `json_report.py`.
        assert isinstance(as_dict, dict)
        # Confirms that `target_url` is present in the dictionary ,and matches the JS base URL.
        assert as_dict["target_url"] == "http://localhost:3000"

    def test_scan_result_vulnerabilities_appended_correctly(self):
        """ Verifies that thje `Vulnerability` objects appended to `vulnerabilities`, are also present in `to_dict()` output."""
        result = self._make_scan_result()
        # Constructs a representative forced browsing vulnerability, to append to the scan result.
        vuln = Vulnerability(
            vuln_type="Forced Browsing - Unprotected Resource",
            severity="Medium",
            endpoint="http://localhost:3000/api/Products",
            method="GET",
            description="Path accessible without authentication.",
        )
        result.vulnerabilities.append(vuln)
        # Confirms that one vulnerability was appended to the in-memory list.
        assert len(result.vulnerabilities) == 1
        as_dict = result.to_dict()
        # Confirms that the apended vulnerability is included in the serialised output used by the reporting modules.
        assert len(as_dict["vulnerabilities"]) == 1