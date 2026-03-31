"""
`spa_crawler.py`

Launches a headless Chromium browser via Playwright to crawl JavaScript-rendered
SPAs, and intercept XHR + Fetch API calls that the static HTML `crawler.py`
cannot detect. The primary target is OWASP Juice Shop's Angular frontend on port 3000.
"""

from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from scanner.core.logger import get_logger
from scanner.core.models import Endpoint

logger = get_logger(__name__)


class SPACrawler:
    # Playwright-based crawler for Javascript-rendered SPAs.

    def __init__(self, config, session_manager, scope_enforcer):
        """ Stores `config`, `session_manager`, and `scope_enforcer` for use across
        all crawl methods. Initialises `self.api_calls`, and
        `self.discovered_endpoints` as empty lists, so they're ready for population by
        `crawl_with_browser`. """
        
        self.config = config
        self.session_manager = session_manager
        self.scope_enforcer = scope_enforcer
        self.api_calls = []
        self.discovered_endpoints = []

    def _setup_request_interceptor(self, page):
        """Registers `_on_request` and `_on_response` as Playwright event handlers
        on the given `page`, so that all outgoing and incoming browser network
        traffic is captured during the crawl session."""

        page.on("request", self._on_request)
        page.on("response", self._on_response)

    def _on_request(self, request):
        """ Executed on every outgoing browser request. Logs any in-scope URLs and appends
        XHR, and Fetch calls (Juice Shop's Angular API traffic) to `self.api_calls`
        as dictionaries containing url, method, headers, and post_data."""

        url = request.url
        # Skips out-of-scope requests, and only processes URLs within the configured target domain.
        if self.scope_enforcer.is_in_scope(url):
            logger.debug(f"Intercepted request: {request.method} {url}")
            # Captures only XHR and Fetch calls, ignoring static assets.
            if request.resource_type in ["xhr", "fetch"]:
                self.api_calls.append({
                    "url": url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                })

    def _on_response(self, response):
        """ Executes on every incoming browser response. Logs status codes, and
        content-types for any URLs already captured in `self.api_calls`, giving
        visibility into what Juice Shop returns for each intercepted API call."""

        url = response.url
        is_api_response = any(call["url"] == url for call in self.api_calls)
        # Logs responses metadata exclusively for URLs already recorded in `self.api_calls`.
        if is_api_response:
            content_type = response.headers.get("content-type", "unknown")
            logger.debug(f"API response: {response.status} {content_type} {url}")

    def _convert_cookies_for_playwright(self, cookies_dict, target_url):
        """ Converts the `{name: value}` cookies dictionary returned by `session_manager`
        into Playwright's required list-of-dictionaries format, using the target domain
        and root path. Used for form-based auth targets such as DVWA."""

        # Returns early if no cookies were provided, which avoids unnecessary processing.
        if not cookies_dict:
            return []
        domain = urlparse(target_url).hostname
        # Converts each cookies name and value pair into a Playwright-compatible dictionary.
        return [
            {"name": k, "value": v, "domain": domain, "path": "/"}
            for k, v in cookies_dict.items()
        ]

    def crawl_with_browser(self, role=None):
        """ Launches headless Chromium, injects credentials for the given `role`
        (Authorization header for Juice Shop bearer auth, context cookies for
        DVWA form auth), clicks all safe interactive elements, and records unique
        SPA routes visited. Then populates `self.api_calls` and
        `self.discovered_endpoints`."""

        # Destrucive action keywords whose matching elements are skipped to prevent irreversible state changes on JS or DVWA during discoveru.
        destructive_keywords = [
            "delete", "remove", "cancel", "logout", "sign out",
            "deactivate", "destroy", "reset", "clear all", "unsubscribe",
        ]

        target_url = self.config.target_url
        visited_routes = set()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # Injects role credentials into the browser context prior to crawling. 
            if role is not None:
                session_kwargs = self.session_manager.get_session_kwargs(role)
                auth_type = self.config.login_config.get("type", "form")

                # Uses the Authorization header for Juice Shop bearer auth, instead of cookies.
                if auth_type == "bearer":
                    token = session_kwargs.get("headers", {}).get("Authorization", "")
                    # Sets the Authorization header, only if a JWT token was successfully retrieved.
                    if token:
                        page.set_extra_http_headers({"Authorization": token})
                else:
                    # Converts and injects DVWA session cookies into the Playwright browser context.
                    cookies = session_kwargs.get("cookies", {})
                    playwright_cookies = self._convert_cookies_for_playwright(
                        cookies, target_url
                    )
                    # Adds cookies to the context, only if the conversion produced a non-empty list.
                    if playwright_cookies:
                        context.add_cookies(playwright_cookies)

            self._setup_request_interceptor(page)

            logger.info(f"Navigating to {target_url} as role={role!r}")
            try:
                page.goto(target_url, wait_until="networkidle", timeout=30000)
            except Exception as exc:
                logger.warning(f"Initial navigation timed out or failed: {exc}")

            # Records the landing route before any interactions with the elements begin.
            visited_routes.add(page.url)

            # Queries all interactive elements: anchors, buttons, onclick attributes, 'role=button' elements, and navigation links.
            elements = page.query_selector_all(
                "a, button, [onclick], [role='button'], nav a, .nav-link"
            )
            logger.info(f"Found {len(elements)} interactive elements to evaluate")

            # Iterates each element, skipping destructive or submit stypes, clicking the remainder, and recording any new SPA routes that appear after each click.
            for element in elements:
                try:
                    text = (element.inner_text() or "").strip().lower()
                    element_type = element.get_attribute("type") or ""

                    # Skips the elements whose visible text matches a destructive keyword.
                    if any(kw in text for kw in destructive_keywords):
                        logger.debug(f"Skipped destructive element: {text!r}")
                        continue

                    # Skips any submit buttons to avoid sending POST form data during discovery.
                    if element_type == "submit":
                        logger.debug(f"Skipped submit element: {text!r}")
                        continue

                    element.scroll_into_view_if_needed()
                    element.click()
                    page.wait_for_load_state("networkidle", timeout=5000)

                    current_url = page.url
                    # Logs and stores any new Angular routes triggered by the click.
                    if current_url not in visited_routes:
                        logger.info(f"New SPA route discovered: {current_url}")
                        visited_routes.add(current_url)

                except Exception as exc:
                    logger.debug(f"Skipped stale or unclickable element: {exc}")

            logger.info(
                f"Crawl complete: {len(visited_routes)} routes visited, "
                f"{len(self.api_calls)} API calls captured"
            )
            browser.close()

        self.discovered_endpoints = self.get_api_endpoints()

    def get_api_endpoints(self):
        """ Converts each entry in `self.api_calls` into an `Endpoint` dataclass, and
        returns the full list. Called after `crawl_with_browser` to hand the discovered
        Juice Shop API endpoints to the rest of the scanner pipeline."""

        endpoints = []
        # Converts each captured XHR/Fetch call dictionary into a typed `Endpoint` object.
        for call in self.api_calls:
            endpoint = Endpoint(
                url=call["url"],
                method=call["method"],
            )
            endpoints.append(endpoint)
        return endpoints