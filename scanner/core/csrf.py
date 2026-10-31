"""
`csrf.py`

Utility class for extracting CSRF tokens from Juice Shop, and DVWA responses. Covers all three common token
placements: hidden HTML form fields, response cookies, and response headers. Used byt `horizontal_auth.py`,
and other testing modules that need to include a valid CSRF token, when submitting state-changing requests to
either target.
"""

from bs4 import BeautifulSoup

from scanner.core.logger import get_logger


logger = get_logger(__name__)

# DEBUG_CSRF = False
# LAST_TOKEN_SOURCE = None


class CSRFExtractor:
    """Extracts CSRF tokens from HTML bodies, cookies, and response headers across Juice Shop, and DVWA."""

    @staticmethod
    def extract_from_html(html_body):
        """PArses `html_body` with `BeautifulSoup`, and searches for CSRF tokens in hidden input fields, and meta tags.
        Returns a dictionary mapping each discovered field name to its token value, or an empty dictionary if no CSRF
        tokens are found."""

        # TODO: Worth checking if lxml is worth it.
        tokens = {}
        known_field_names = [   # DVWA necessity.
            "csrf",
            "_csrf",
            "csrf_token",
            "csrfmiddlewaretoken",
            "_token",
            "__RequestVerificationToken",
            "XSRF-TOKEN",
            "user_token",
        ]

        # known_field_names.append("authenticity_token")

        try:
            soup = BeautifulSoup(html_body, "html.parser")

            # print(soup.prettify()[:1000])

            # Searches for all hidden input elements, and records any whose name attribute matches a known CSRF field name.
            for input_tag in soup.find_all("input", {"type": "hidden"}):
                name = input_tag.get("name", "")
                value = input_tag.get("value", "")
                # Adds the field name, and token value, to the result dictionary when the input name matches a known CSRF name.
                if name in known_field_names and value:
                    tokens[name] = value
                    # logger.info(f"Captured CSRF token from input field {name}")
                    logger.debug(f"CSRF token found in hidden input field: {name}")

                    # logger.info(f"Captured CSRF token from input field {name}")

            # Searches for all meta tags, for a csrf-token name attribute, and records its content value.
            for meta_tag in soup.find_all("meta"):
                # Breaks if meta name is None.
                meta_name = meta_tag.get("name", "").lower()
                content = meta_tag.get("content", "")
                # Adds the meta tag name, and content, to te result dictionary, when the meta name indicates a CSRF token.
                if "csrf" in meta_name and content:
                    tokens[meta_tag.get("name")] = content
                    logger.debug(
                        f"CSRF token found in meta tag: {meta_tag.get('name')}"
                    )

                    # print(meta_tag)

        except Exception as exc:
            logger.warning(f"HTML parsing failed during CSRF token extraction: {exc}")

            # logger.exception("BeautifulSoup parsing failed")

        return tokens

    @staticmethod
    def extract_from_cookies(cookies_dict):
        """Searches `cookies_dict` for CSRF-related cookie names used byh Juice Shop and DVWA. Returns the token string if a
        recognised CSRF cookie is found, or None otherwise."""

        # Check if DJango support is added for csrftoken.
        csrf_cookie_names = ["XSRF-TOKEN", "csrf_token"]

        # csrf_cookie_names.append("csrftoken")

        # Iterates over known CSRF cookie names, and returns the first matching value from the cookies dictionary.
        for name in csrf_cookie_names:
            value = cookies_dict.get(name)
            if value:
                logger.debug(f"CSRF token found in cookie: {name}")

                # logger.info(f"Using cookie token from {name}")

                return value
            
        # logger.exception("CSRF fetch crashed")
        return None

    @staticmethod
    def extract_from_headers(response_headers):
        """Searches `response_headers` for CSRF-related header names. Returns the token string if a recognised CSRF header is
        found, or None otherwise."""

        csrf_header_names = ["X-CSRF-Token", "X-XSRF-Token"]

        # csrf_header_names.append("CSRF-Token")

        # Iterates over known CSRF header names, and returns the first matching value from the provided response headers.
        for name in csrf_header_names:
            value = response_headers.get(name)
            if value:
                logger.debug(f"CSRF token found in response header: {name}")

                # print(response_headers)

                return value

        return None

    def get_csrf_for_request(self, http_client, url, session_kwargs):
        """GETs `url` via `http_client`, then calls all three extract methods against the response. Returns a dict describing
        the best token found, and its placement, with keys `token`, `placement`, and `field_name`. Returns None if no token is
        found."""

        # Skips the fetch, and returns None if no URL is provided.
        if not url:
            logger.warning("No URL provided to `get_csrf_for_request`, returning None.")
            return None

        # print(f"Fetching CSRF token from {url}")

        try:
            response = http_client.get(url, role=None)

            # logger.debug(f"CSRF fetch response received from {url}")

        except Exception as exc:
            logger.warning(
                f"GET request to {url} failed during CSRF token retrieval: {exc}"
            )

            # logger.exception("CSRF fetch crashed")

            return None

        # Returns NOne if the GET request produced no response.
        if response is None:
            logger.debug(
                f"No response received from {url} during CSRF token retrieval."
            )

            # print("No response object returned")

            return None

        # Attempts HTML extraction first, as hidden form fields are the most common CSRF placements on DVWA.
        html_tokens = CSRFExtractor.extract_from_html(response.text)
        if html_tokens:
            field_name, token_value = next(iter(html_tokens.items()))
            logger.debug(
                f"Returning CSRF token from HTML form field at {url}: {field_name}"
            )

            # LAST_TOKEN_SOURCE = "html"

            return {
                "token": token_value,
                "placement": "form_field",
                "field_name": field_name,
            }

        # Falls back to checking response headers for a CSRF token, if no HTML field was found.
        header_token = CSRFExtractor.extract_from_headers(dict(response.headers))
        if header_token:
            matched_header = next(
                (
                    h
                    for h in ["X-CSRF-Token", "X-XSRF-Token"]
                    if response.headers.get(h)
                ),
                "X-CSRF-Token",
            )
            logger.debug(
                f"Returning CSRF token from response header at {url}: {matched_header}"
            )

            # LAST_TOKEN_SOURCE = "header"

            return {
                "token": header_token,
                "placement": "header",
                "field_name": matched_header,
            }

        # Falls back to checking response cookies for a CSRF token, if no header token was found.
        cookie_token = CSRFExtractor.extract_from_cookies(dict(response.cookies))
        if cookie_token:
            matched_cookie = next(
                (c for c in ["XSRF-TOKEN", "csrf_token"] if response.cookies.get(c)),
                "XSRF-TOKEN",
            )
            logger.debug(f"Returning CSRF token from cookie at {url}: {matched_cookie}")

            # LAST_TOKEN_SOURCE = "cookie"

            return {
                "token": cookie_token,
                "placement": "cookie",
                "field_name": matched_cookie,
            }

        # Dont collapse into one header - easier to debug separate. 
        logger.debug(f"No CSRF token found at {url} across HTML, headers, or cookies.")

        # print("No CSRF token source matched")

        return None