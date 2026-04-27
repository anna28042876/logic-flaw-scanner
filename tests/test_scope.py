"""
`tests/test_scope.py`

Unit tests for `scanner/core/scpope.py`. Verifies that `ScopeEnforcer.is_in_scope()` accepts in-scope URLs
on the target domain, as it should, rejects out-of-scope external domains, enforces `excluded_paths` regex 
patterns, nd restricts crawling to `allowed_paths` prefixes, when configured.
"""
import pytest
from unittest.mock import MagicMock

from scanner.core.scope import ScopeEnforcer


def _make_config(
    target_url="http://localhost:3000",
    excluded_paths=None,
    allowed_paths=None,
    include_subdomains=False,
    robots_txt=False,
    verify_ssl=False,
):
    """ Builds and returns a mock `ScanConfig`, for use in `ScopeEnforcer` tests."""
    # Uses `MagicMock` to avoid loading a real YAML file, whilst satisfying the attribute access pattern in `ScopeEnforcer.__init__`.
    config = MagicMock()
    config.target_url = target_url
    # `verify_ssl` is set to `False` to match the lab environment, where Docker containers use self-signed certificates.
    config.verify_ssl = verify_ssl
    # `excluded_paths` defaults to an empty list when not provided, meaning that no paths are excluded from scope.
    config.excluded_paths = excluded_paths or []
    # Builds the `scope` dictionary in the same structure that `ScanConfig.scope` returns from the YAML.
    config.scope = {
        "include_subdomains": include_subdomains,
        "allowed_paths": allowed_paths or [],
        "robots_txt": robots_txt,
    }
    return config


class TestIsInScopeBasicDomain:
    """ Tests that `is_in_scope` accepts URLs on the target domain, and rejects any external domains."""

    def test_target_url_root_is_in_scope(self):
        """ Verifies that the root path on the JS target domain passes the scope check."""

        # Configures the scope with no restrictions, matching the default JS configuration.
        config = _make_config(target_url="http://localhost:3000")
        enforcer = ScopeEnforcer(config)
        # Confirms that the root path is accepted as in-scope for the JS target.
        assert enforcer.is_in_scope("http://localhost:3000/") is True

    def test_api_path_on_target_is_in_scope(self):
        """ Verifies that a JS REST endpoint on `localhost:3000` passes the scope check."""

        config = _make_config(target_url="http://localhost:3000")
        enforcer = ScopeEnforcer(config)
        # Confirms the JS products API path, a ground-truth endpoint, is accepted as in-scope.
        assert enforcer.is_in_scope("http://localhost:3000/api/Products") is True

    def test_external_domain_is_out_of_scope(self):
        """ Verifies that a URL on an external domain is rejected by the scope check."""

        config = _make_config(target_url="http://localhost:3000")
        enforcer = ScopeEnforcer(config)
        # Confirms that an external domain is rejected, preventing the scanner from accidentally leaving the lab environment.
        assert enforcer.is_in_scope("http://example.com/api/Products") is False

    def test_different_port_is_out_of_scope(self):
        """ Verifies that a URL on `localhost:8080`, is rejected when the target is `localhost:3000`."""
        config = _make_config(target_url="http://localhost:3000")
        enforcer = ScopeEnforcer(config)
        # Confirms that DVWA, at port 8080, is correctly rejected when scoping against the JS target at port 3000.
        assert enforcer.is_in_scope("http://localhost:8080/login.php") is False


class TestExcludedPaths:
    """ Tests that `is_in_scope` rejects any URLs matching any of the `excluded_paths`."""

    def test_logout_path_is_excluded(self):
        """ Verifies that the JS logout endpoint is rejected, when listed in `excluded_paths`."""
        # Excludes the logout endpoint to prevent the scanner from invalidating any active sessions mid-scan.

        config = _make_config(
            target_url="http://localhost:3000",
            excluded_paths=["^/rest/user/logout"],
        )
        enforcer = ScopeEnforcer(config)
        # Confirms that the logout endfdpoint is rejected by the scope check.
        assert enforcer.is_in_scope("http://localhost:3000/rest/user/logout") is False

    def test_non_excluded_path_passes(self):
        """ Verifies that a path not matching any `excluded_paths` pattern still passes the scope check."""
        # Sets the logout path as excluded, but tests the login path as it should remain in scope.
        config = _make_config(
            target_url="http://localhost:3000",
            excluded_paths=["^/rest/user/logout"],
        )
        enforcer = ScopeEnforcer(config)
        # Confirms the login endpoint is in fact still accepted, even though the logout endpoint is excluded.
        assert enforcer.is_in_scope("http://localhost:3000/rest/user/login") is True


class TestAllowedPaths:
    """ Tests that `is_in_scope` restricts crawling to the `allowed_paths` only prefixes, when the list is non-empty."""

    def test_url_matching_allowed_prefix_passes(self):
        """ Verifies that a URL beginning with `/api/` passes the scope check, when `allowed_paths` contains `/api/`"""
        #Restricts thee scope to `/api/`, and `/rest/` prefixes, which are the two primary JS API path groups.
        config = _make_config(
            target_url="http://localhost:3000",
            allowed_paths=["/api/", "/rest/"],
        )
        enforcer = ScopeEnforcer(config)
        # Confirms that the products API path is accepted, because it begins with the `/api/` prefix.
        assert enforcer.is_in_scope("http://localhost:3000/api/Products") is True

    def test_url_not_matching_allowed_prefix_fails(self):
        """ Verifies that a URL outside all the `allowed_paths` prefixes is still rejected by the scope check."""
        config = _make_config(
            target_url="http://localhost:3000",
            allowed_paths=["/api/", "/rest/"],
        )
        enforcer = ScopeEnforcer(config)
        # Confirms that the JS static assets path is rejected, because it does not match `/api/` or `/rest/`.
        assert enforcer.is_in_scope("http://localhost:3000/assets/public/images/") is False

    def test_empty_allowed_paths_permits_all(self):
        """ Verifies that an empty `allowed_paths` list creates no path restrictions on in-scope URLs."""
        # An empty `allowed_paths` list matches the default JS configuration, where all paths are in scope.
        config = _make_config(
            target_url="http://localhost:3000",
            allowed_paths=[],
        )
        enforcer = ScopeEnforcer(config)
        #Confirms that any path on the target domain is accepted, even when `allowed_paths` is empty.
        assert enforcer.is_in_scope("http://localhost:3000/anything/at/all") is True


class TestFilterUrls:
    """ Tests that `filter_urls` will remove out-of-scope URLs, from a mixed input list."""

    def test_filter_removes_external_urls(self):
        """ Verifies that `filter_urls` returns only the in-scope URLs, when passed a list containing external domains."""

        config = _make_config(target_url="http://localhost:3000")
        enforcer = ScopeEnforcer(config)
        # Builds a mixed list containing 2 in-scope JS URLs,and 1 external exfiltration domain.
        urls = [
            "http://localhost:3000/api/Products",
            "http://example.com/exfil",
            "http://localhost:3000/rest/user/login",
        ]
        result = enforcer.filter_urls(urls)
        # Confirms that the JS API path is still retained in the filtered list.
        assert "http://localhost:3000/api/Products" in result
        #  Confirms that the external exfiltration domain is removed from the filtered list
        assert "http://example.com/exfil" not in result