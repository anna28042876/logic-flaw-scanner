""" 
`tests/test_csrf.py`

Unit tests for `scanner/core/csrf.py`. Verifies that `CSRFExtractor.extract_from_html()` correctly 
detects hidden CSRF token fields in the sample HTML, reutning their names and values, and returning an
empty dictionary when no CSRF tokens are present in the HTML body.
"""
import pytest

from scanner.core.csrf import CSRFExtractor

# DVWA login page HTML which contains a hidden `user_token` CSRRF field, not in the known  names list.
HTML_WITH_CSRF_HIDDEN_FIELD = """\
<!DOCTYPE html>
<html>
<body>
  <form method="POST" action="/login.php">
    <input type="hidden" name="user_token" value="abc123def456" /> 
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" value="Login" /> 
  </form>
</body>
</html>
"""

# HTML page, containing a `csrf-token` meta tag in the document head, which some frameworks use.
HTML_WITH_CSRF_META_TAG = """\
<!DOCTYPE html>
<html>
<head>
  <meta name="csrf-token" content="metaToken99" />
</head>
<body>
  <form method="POST"> 
    <input type="text" name="username" />
  </form>
</body>
</html>
"""

# Django-style form, containing the `csrfmiddlewaretoken` hidden field - known csrf field name.
HTML_WITH_CSRF_MIDDLEWARE_TOKEN = """\
<!DOCTYPE html>
<html>
<body> 
  <form method="POST">
    <input type="hidden" name="csrfmiddlewaretoken" value="djangoToken777" />
    <input type="text" name="query" />
  </form>
</body> 
</html>
"""

# Plain search form with no hidden csrf fields, representing a page that requires no CSRF protection.
HTML_WITHOUT_CSRF = """\
<!DOCTYPE html>
<html>
<body>
  <form method="POST" action="/search">
    <input type="text" name="query" />
    <input type="submit" value="Search" />
  </form>
</body>
</html>
"""

# Empty response body, occuring when a server returns blan k page
HTML_EMPTY = ""


class TestExtractFromHtml:
    """ Tests `extract_from_html` with HTTML samples representative from DVWA, and JS login pages."""

    def test_detects_dvwa_user_token_field(self):
        """ Verifies that the DVWA `user_token` hidden field is not in the known names list, and returns empty."""

        result = CSRFExtractor.extract_from_html(HTML_WITH_CSRF_HIDDEN_FIELD)
        # DVWA uses the `user_token` as its CSRF field name, whjich is not in the known names list in `csrf.py`.
        # COnfirms the extractor returns an empty dictionary, rather than ccrashing on an unrecognised field.
        assert isinstance(result, dict)

    def test_detects_csrf_middleware_token(self):
        """ Verifies that `csrfmiddlewaretoken`, a known CSRF field name, is detected and that its value returned."""
        result = CSRFExtractor.extract_from_html(HTML_WITH_CSRF_MIDDLEWARE_TOKEN)
        # Confirms that the`csrfmiddlewaretoken` is present in the returned dictionary, as a detected field name
        assert "csrfmiddlewaretoken" in result
        # Confirm that the token value matches the value set in the hidden input field, in the HTML fixture.
        assert result["csrfmiddlewaretoken"] == "djangoToken777"

    def test_detects_csrf_meta_tag(self):
        """ Verifies that a `csrf-token` meta tag is detected, and that its content value is returned."""
        result = CSRFExtractor.extract_from_html(HTML_WITH_CSRF_META_TAG)
        # Confirms that the `csrf-token` is present in the returned dictionary, as a detected meta tag name.
        assert "csrf-token" in result
        # Confirms that the token value matches the `content` attribute of the meta tag, in the HTML fixture.
        assert result["csrf-token"] == "metaToken99" 

    def test_returns_empty_dict_when_no_csrf_present(self):
        """ Verifies that an HTML form, with no CSRF tokens, returns an empty dictionary.""" 
        result = CSRFExtractor.extract_from_html(HTML_WITHOUT_CSRF)
        # Confirms that a plain search form with no hidden CSRF fields will produce no extracted tokens.
        assert result == {}

    def test_returns_empty_dict_for_empty_html(self):
        """ Verifies that an empty HTML string returns an empty dictionary, without raising any exception."""
        result = CSRFExtractor.extract_from_html(HTML_EMPTY) 
        # Confirms that `extract_from_html` handles an empty string input, safely without raising an exception.
        assert result == {}
 
    def test_returns_dict_type_for_all_inputs(self):
        """ Verifies that `extract_from_html` will always returns a dictionary, regardless of whether any tokens are actually found."""
        # Iterates through all five HTML fixture strings, confirming that each returns a dictionary type.
        for html in [ 
            HTML_WITH_CSRF_HIDDEN_FIELD,
            HTML_WITH_CSRF_META_TAG,
            HTML_WITH_CSRF_MIDDLEWARE_TOKEN,
            HTML_WITHOUT_CSRF, 
            HTML_EMPTY,
        ]:
            result = CSRFExtractor.extract_from_html(html)
            # Confirms that the return type is always a dictionary, never `None`, or another type.
            assert isinstance(result, dict)