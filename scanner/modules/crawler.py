"""
`crawler.py`

Implements a BFS-based crawler that maps the attack surface of the target application (OWASP JS/DVWA) before
vulnerability probes are deployed. Discovers reachable HTML pages, form submission endpoints, and REST API
paths, via parsing link tags, inline scripts, link headers, and JSON responses.

Crawler is role-aware, runnning once unauthenticated and one per configured role e.g., `user`, `admin` in the
Juice Shop, then compares the two discovery sets to flag endpoints that are only reachable whilst authenticated.
Those endpoints bnecome primary candidates fort IDOR/BOLA + broken access control tests in later phases.

HTTPClient provides the rate limited, session aware request wrapper. SessionManager provides per-role auth
headers/cookies. ScopeEnforcer enforces the configured target host/prefix so that the crawler never leaves the
lab target (JS/DVWA) or touches live targets.
"""

import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from scanner.core.http_client import HTTPClient
from scanner.core.session_manager import SessionManager
from scanner.core.scope import ScopeEnforcer
from scanner.core.logger import get_logger
from scanner.core.models import Endpoint


class Crawler:
    """Stores injected pipeline dependencies and initialises the three shared data structures, (discovered endpoints,
    `visisted_urls`, forms) that all subsequent crawl methods read and write."""

    def __init__(
        self,
        config,
        http_client: HTTPClient,
        session_manager: SessionManager,
        scope_enforcer: ScopeEnforcer,
    ):

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.scope_enforcer = scope_enforcer
        # shared acreoss all crawl phases so that deduplication works right
        self.discovered_endpoints: list[Endpoint] = []
        # resets between sessions in `crawl_all_session`, not here.
        self.visited_urls: set[str] = set()
        # Raw form metadata passe to auth-workflow and form-injection
        self.forms: list[dict] = []
        self.logger = get_logger(__name__)

    # Overkill for some pages but handles malformed JS html better than alternatives.
    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Parses an HTML page with BeautifulSoup and returns every URL found across anchor, link, scrippt, image,
        and iframe tags. All relative paths are resolved to absolute URLs against `bare_url` so every entry entering the
        BFS queue is ready for `ScopeEnforcer checking`."""
        soup = BeautifulSoup(html, "lxml")
        # Anchors, stylesheets, scripts, images, and embedded frames.
        tag_attr_pairs = [
            ("a", "href"),
            ("link", "href"),
            ("script", "src"),
            ("img", "src"),
            ("iframe", "src"),
        ]
        # Iterates tag/attribute pairs, strips whitespace, resolves relative paths, and returns absolute URLs.
        urls = []
        for tag, attr in tag_attr_pairs:
            for element in soup.find_all(tag, **{attr: True}):
                raw = element[attr].strip()
                if raw:
                    # Resolve relative paths against `base_url` so that every URL entering the BSF queue is absolute.
                    urls.append(urljoin(base_url, raw))
        return urls

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        """Finds every <form> element on a page and returns it action URL, HTTP method, encoding type, and named fields as
        a dictionary. Action URLs are reesolved to absolute paths. The returned list feeds self.forms, which is then later
        cvonsumed by the auth-workflow and form-injection modules. """

        soup = BeautifulSoup(html, "lxml")
        forms = []
        # Iterates all forms, and for each, collects named fields with their field type and default value.
        for form in soup.find_all("form"):
            action = form.get("action", "")
            # Resolve relative action paths so that the probe modules receive ready-to-use absolute URLS.
            action_url = urljoin(page_url, action) if action else page_url
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            fields = []
            for field in form.find_all(["input", "select", "textarea"]):
                name = field.get("name")
                if not name:
                    # Skips anonymous fields as they carry no parameter names to probe.
                    continue
                fields.append(
                    {
                        "name": name,
                        "type": field.get("type", "text"),
                        # Preserves CSRF tokens and hidden defaults.
                        "value": field.get("value", ""),
                    }
                )
            forms.append(
                {
                    "action": action_url,
                    "method": method,
                    "enctype": enctype,
                    "fields": fields,
                    # Kept so that probes can track a form back to its originating location.
                    "source_page": page_url,
                }
            )
        return forms

    # JS hides a lot of routes via inline scripts rather than anhor tags
    def _extract_api_hints(self, html: str, response_headers: dict) -> list[str]:
        """Mines four sources (inline script literals, raw HTML URLs RFC 5988 Link headers, and `data-url`/`data-api-endpoint` attributes)
        for REST API paths not reachable via the standard anchor tags. Results are deduplicated, filtered to remove static assets, and checked
        against `ScopeENforcer` before being returned. Primarily targets Juicee Shops Angular routes and DVWA widgets."""

        soup = BeautifulSoup(html, "lxml")
        # Dont care about static assets.
        false_positives = re.compile(
            r"^/(js|css|img|images|fonts|static|assets)/", re.IGNORECASE
        )
        raw_hints = []

        # Extracts path-like string literals from each inline script block.
        for script in soup.find_all("script"):
            script_text = script.string or ""
            for match in re.findall(r"""["'](\/[a-zA-Z0-9_\-/]+)["']""", script_text):
                raw_hints.append(match)

        # Collects all absolute URLs embedded anywhere in the raw HTML.
        for match in re.findall(r'https?://[^\s"\'<>]+', html):
            raw_hints.append(match)

        # Parses the link header, extracting URLs from RFC 5988 angle-bracket syntax.
        link_header = response_headers.get("Link", "") or response_headers.get(
            "link", ""
        )
        if link_header:
            for part in link_header.split(","):
                m = re.search(r"<([^>]+)>", part)
                if m:
                    raw_hints.append(m.group(1))

        # Collects `data-url` attribute values from DVWA widget elements.
        for el in soup.find_all(attrs={"data-url": True}):
            raw_hints.append(el["data-url"])
        for el in soup.find_all(attrs={"data-api-endpoint": True}):
            raw_hints.append(el["data-api-endpoint"])

        filtered = []
        seen: set[str] = set()
        # Filters, deduplicates, and scope-checks each raw hint before adding to the results.
        for hint in raw_hints:
            hint = hint.strip()
            if len(hint) < 3:
                # Discards any single-character or empty matches from the scripts regex.
                continue
            if false_positives.match(hint):
                continue
            # Resolves root-relative paths against `config.target_url` before scope checks.
            absolute = (
                urljoin(self.config.target_url, hint) if hint.startswith("/") else hint
            )
            if absolute not in seen and self.scope_enforcer.is_in_scope(absolute):
                filtered.append(absolute)
                seen.add(absolute)
        return filtered

    def _mine_linked_js(
        self, html: str, base_url: str, session_kwargs: dict
    ) -> list[str]:
        """Finds every linked `<script src>` on the target domain in `html`, fetches each bundle
        that has not already been visited, and extracts path-like string literals from the raw JS
        source. Returns deduplicated absolute URLs that pass `ScopeEnforcer`, so that API routes
        embedded in SPA bundles reach the BFS queue without relaxing the configured scope.  """

        soup = BeautifulSoup(html, "lxml")
        target_netloc = urlparse(self.config.target_url).netloc
        # Matches single or double quoted forward-slash paths in minified JS source.
        path_pattern = re.compile(r"""["'](\/[a-zA-Z0-9_\-/]+)["']""")
        # Excludes static asset path prefixes from extracted bundle hints.
        false_positives = re.compile(
            r"^/(js|css|img|images|fonts|static|assets)/", re.IGNORECASE
        )
        hints = []
        seen: set[str] = set()

        # Iterates all linked script tags, fetching only those on the target domain.
        for script in soup.find_all("script", src=True):
            script_url = urljoin(base_url, script["src"])
            parsed = urlparse(script_url)
            # Skips scripts hosted on external domains to stay within the target.
            if parsed.netloc != target_netloc:
                continue
            # Skips already-visited bundles to avoid redundant fetches within the same session.
            if script_url in self.visited_urls:
                continue
            # Marks the bundle as visited so sibling pages do not re-fetch the same file.
            self.visited_urls.add(script_url)
            try:
                response, _ = self.http_client.get(script_url, **session_kwargs)
                if response is None:
                    continue
                # Extracts path-like string literals directly from the raw JS bundle source.
                for match in path_pattern.findall(response.text):
                    if false_positives.match(match):
                        continue
                    absolute = urljoin(self.config.target_url, match)
                    # Scope-checks each extracted path before adding it to the results.
                    if absolute not in seen and self.scope_enforcer.is_in_scope(
                        absolute
                    ):
                        hints.append(absolute)
                        seen.add(absolute)
            except Exception as exc:
                self.logger.debug(f"Failed to mine JS bundle {script_url}: {exc}")
        return hints

    def crawl(
        self, start_url: str = None, max_depth: int = None, role: str = None
    ) -> None:
        """Executes a single BFS crawl session from `start_url` using credentials for the given `role` ('none' means unauthenticated).
        Fetches each page via `HTTPClient`, branches on Content-Type to handle HTML and JSON responses differently, and registers every
        discovered URL/method pair as an `Endpoint`. Respects `max_depth`, and `max_pages` limits from `crawl_config`."""

        if start_url is None:
            start_url = self.config.target_url
        if max_depth is None:
            # Falls back to `crawl_config` value, the default of which is 3 and sufficient for Juice Shop and DVWA.
            max_depth = self.config.crawl_config.get("max_depth", 3)
        max_pages = self.config.crawl_config.get("max_pages", 500)

        # Attaches the correct authg headers/cookies for this `role` via `SessionManager`.
        session_kwargs = self.session_manager.get_session_kwargs(role)
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        crawled_count = 0

        # Main BFS loop.
        # Dequeues URLs, applies guard checks, fetches, parses, and enqueues any discovered links -- should works as standard BFS.
        while queue:
            url, depth = queue.popleft()

            # Guard clauses. Skips before making any HTTP request.
            if url in self.visited_urls:
                continue
            if depth > max_depth:
                continue
            if len(self.visited_urls) >= max_pages:
                self.logger.info(
                    f"Reached max_pages limit ({max_pages}), stopping crawl."
                )
                break
            if not self.scope_enforcer.is_in_scope(url):
                # `ScopeEnforcer` prevents the crawler from leaving the configured lab host.
                continue

            self.visited_urls.add(url)
            crawled_count += 1

            response, _ = self.http_client.get(url, **session_kwargs)
            if response is None:
                # `HTTPClient` logs the failure and skips silently to avoid breaking the BFS loop.
                continue

            content_type = response.headers.get("Content-Type", "")

            if "text/html" in content_type:
                html = response.text
                links = self._extract_links(html, url)
                page_forms = self._extract_forms(html, url)
                api_hints = self._extract_api_hints(html, dict(response.headers))
                # Fetches linked JS bundles and extracts API paths from their raw source.
                js_hints = self._mine_linked_js(html, url, session_kwargs)

                self.forms.extend(page_forms)
                self._add_endpoint(url, "GET", role)

                """ Registers each form's action URL as a distinct `Endpoint`. Covers POST-only targets like Juice Shop's 
                checkout and DVWA's login that never appears as anchor links."""
                for form in page_forms:
                    # Scope-checks the form action before registering, so out-of-scope actions are never added as endpoints.
                    if self.scope_enforcer.is_in_scope(form["action"]):
                        self._add_endpoint(form["action"], form["method"], role)

                # Enqueues unvisitied links and API hints for the next BFS depth level.
                for link in links + api_hints + js_hints:
                    if link not in self.visited_urls:
                        queue.append((link, depth + 1))

            elif "application/json" in content_type:
                # Juice Shop's '/rest/products` and similar endpoints return JSON direcly. Walks payload for further paths.
                self._add_endpoint(url, "GET", role)
                try:
                    data = response.json()
                    for found_url in self._extract_json_urls(data):
                        absolute = urljoin(url, found_url)
                        if absolute not in self.visited_urls:
                            queue.append((absolute, depth + 1))
                except (ValueError, TypeError):
                    # Malformed JSON from the target is not a scanner error, so it skips and continues.
                    pass
            
            # Reassuring to see if this moving during long JS scans
            if crawled_count % 20 == 0:
                # Periuodic progress log to confirm that the crawl is actually running during long Juice Shop sessions.
                self.logger.info(
                    f"Crawled {crawled_count}/{max_pages} pages, "
                    f"found {len(self.discovered_endpoints)} endpoints so far."
                )

    # JS returns nestyed json on some endpoints, with urls buried a few levels down.
    def _extract_json_urls(self, data, _depth: int = 0) -> list[str]:
        """Recursively walks a parsed JSON value and collects strings starting with '/' or 'http' as potential URL paths.
        Depth is capped at 10 to prevent stack exhaustion  or deeply nested Juice Shop API responses such as `/rest/products`
        pagination data.

        Args:
            data (dict, list, or str): The parsed JSON value to inspect.
            _depth (int): Current recursion depth, capped at 10, to prevent stack exhaustion on deeply nestedd JS API responses.

        Returns:
            list[str]: All string values, starting with `/`,  or `http` found anywhere in the JSON structure up to depth 10."""
        if _depth > 10:
            # Caps recursion to prevent stack exhaustion on deeply nested Juice API responses.
            return []
        urls = []
        if isinstance(data, dict):
            # Recurses into each dictionary value to find nested URL strings.
            for value in data.values():
                urls.extend(self._extract_json_urls(value, _depth + 1))
        elif isinstance(data, list):
            # Recurses into each list item to find nested URL strings.
            for item in data:
                urls.extend(self._extract_json_urls(item, _depth + 1))
        elif isinstance(data, str):
            # Only collects strings that are plausible URL paths or absolute URL paths.
            if data.startswith("/") or data.startswith("http"):
                urls.append(data)
        return urls

    def _add_endpoint(self, url: str, method: str, role: str = None) -> None:
        """Registers a URL and HTTP method as an `Endpoint` in `discovered_endpoints`, deduplicating by (method, url)
        pairs so that the same route is never added twice. This prevents duplicate probing across the unauthenticated
        and role-based crawl sessions that `crawl_all_sessions` manages. """

        key = (method.upper(), url)
        for ep in self.discovered_endpoints:
            if (ep.method.upper(), ep.url) == key:
                # Already registered. Skips to avoid probing the same route twice in later phases.
                return
        self.discovered_endpoints.append(Endpoint(url=url, method=method.upper()))

    # Unauthenticated first, then once per role - diff between them flags auth-gated endpoints.
    def crawl_all_sessions(self) -> None:
        """Runs a full multi-session discovery pass. One unauthenticated crawl, followed by one crawl per configured role
        (e.g., 'user', 'admin' for Juice Shop). COmpares `discovered_endpoints` sets between passes using set diffs to
        determine which URLs were gated behind authentication, then sets `required_auth` on those `Endpoints`, marking them
        as primary IDOR/BOLA targets.

        Raises:
            No exception is raised, all HTTP failures are handled by `HTTPClient`, and logged at `WARNING` level, with thw crawl continuing to the next URL."""

        # Pulls all the configured role names e.g., 'user', 'admin', from `SessionManager`.
        roles = (
            list(self.session_manager.sessions.keys())
            if hasattr(self.session_manager, "sessions")
            else []
        )

        self.logger.info("Starting unauthenticated crawl...")
        self.visited_urls = set()
        before_unauth = {(ep.method, ep.url) for ep in self.discovered_endpoints}
        self.crawl(role=None)
        after_unauth = {(ep.method, ep.url) for ep in self.discovered_endpoints}
        # Diffs the sets to identify which `Endpoint`s the unauthenticated pass found.
        unauth_found = after_unauth - before_unauth

        # Tags each newly discovered `Endpoint` with the `unauthenticated` role label.
        for ep in self.discovered_endpoints:
            if (ep.method, ep.url) in unauth_found:
                if "unauthenticated" not in ep.discovered_by_roles:
                    ep.discovered_by_roles.append("unauthenticated")
        # Crawls as each configured role. Diffs endpoint sets and tags newly found `Endpoint`s with the role name.
        for role in roles:
            self.logger.info(f"Starting crawl as role: {role}...")
            self.visited_urls = set()
            before_role = {(ep.method, ep.url) for ep in self.discovered_endpoints}
            self.crawl(role=role)
            after_role = {(ep.method, ep.url) for ep in self.discovered_endpoints}
            # The diff identifies `Endpoint`s exclusively reachable under this role.
            role_found = after_role - before_role

            for ep in self.discovered_endpoints:
                if (ep.method, ep.url) in role_found:
                    if role not in ep.discovered_by_roles:
                        ep.discovered_by_roles.append(role)

        # Sets `required_auth` on `Endpoint`s neven discovered during the authenticated path.
        for ep in self.discovered_endpoints:
            ep.requires_auth = "unauthenticated" not in ep.discovered_by_roles

        self.logger.info(
            f"All crawl sessions complete. "
            f"{len(self.discovered_endpoints)} total endpoints discovered."
        )

    # Returns the full list of discovered `Endpoint` objects for the IDOR, auth-bypass, and rate-limit probe modules.
    def get_endpoints(self) -> list[Endpoint]:
        """Returns the full list of `Endpoint` objects, discovered across all crawl sessions.

        Returns:
            list[Endpoint]: All deduplicted endpoints found during unauthenticated, and role-authenticated crawl passes."""
        return self.discovered_endpoints

    # Returns raw form metadata collected across all crawled pages for the auth-workflow and form-injection modules.
    def get_forms(self) -> list[dict]:
        """Returns the raw form metadata, collected across all crawled pages.

        Returns:
            list[dict]: All form dicts extracted by `_extract_forms` across every page visited during all crawl sessions."""
        return self.forms
