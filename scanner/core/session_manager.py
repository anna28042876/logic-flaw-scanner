# `scanner/core/session_manager.py`.

"""Responsible for handling all authentication logic for the scanner.
Supports multiple authentication mechanisms (`form`, `bearer/JWT`, `basic`, `API key`) and abstracts them behind a
single interface so that the rest of the scanner does not need to care how authentication is implemented for each role.

Each "role" e.g., admin, user_a, user_b, gets its own fully isolated session state, which is important for vulnerability
testing (especially IDOR), and therefore ensuring no cookies, headers, or tokens leak between roles during concurrent
scanning."""

import base64

import requests
from bs4 import BeautifulSoup

from scanner.core.logger import get_logger

logger = get_logger(__name__)


class SessionManager:
    # Central manager that authenticates all the configured roles and stores their session states.
    # Works closely with `HTTPClient`, which actually sends requests using these sessions.

    def __init__(self, config, http_client):
        # `config:` is the global scanner configuration (`target URL`, `credentials`, `auth config`, etc.,)
        # `http_client`: is the shared HTTP layer used across the scanner.
        self.config = config
        self.http_client = http_client

        """ Stores the authenticated session data per role:
        {
            "admin": {cookies, headers, auth_type, ...},
            "user_a": {...}
        } """
        self.sessions = {}

    def _authenticate_form(self, cred: dict) -> bool:
        # Handles the traditional HTML form login (e.g., DVWA style apps).
        # Uses a dedicated `requests.Session` to persist cookies per role.

        login_cfg = self.config.login_config

        # Creates a fresh isolated session for this role.
        fresh_session = requests.Session()

        # Apply proxy settings if the scanner is routing traffic through one (e.g., Burp).
        if self.config.proxy is not None:
            fresh_session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }

        # Constructs full login URL safely.
        # Uses the login URL directly if it is already absolute, otherwise prepends the base target URL.
        raw_login_url = login_cfg["login_url"]
        if raw_login_url.startswith("http://") or raw_login_url.startswith("https://"):
            login_url = raw_login_url
        else:
            login_url = (
                self.config.target_url.rstrip("/") + "/" + raw_login_url.lstrip("/")
            )

        # First reqests the login page to extract the `CSRF` tokens, if present.
        try:
            get_resp = fresh_session.get(
                login_url, verify=self.config.verify_ssl, timeout=15
            )
            soup = BeautifulSoup(get_resp.text, "lxml")
        except Exception as e:
            logger.warning(f"Could not GET login page for CSRF extraction: {e}")
            soup = None

        # Base payload with `username/password` mapped to the configured field names.
        payload = {
            login_cfg["username_field"]: cred["username"],
            login_cfg["password_field"]: cred["password"],
        }

        # Collects all named input fields from the login form, including submit buttons and hidden
        # fields. This handles DVWA's `Login=Login` submit requirement (login.php only processes
        # the POST when `isset($_POST['Login'])` is true) and any hidden CSRF token fields, without
        # needing them to be explicitly configured. Credentials set above are not overwritten.
        if soup:
            login_form = soup.find("form")
            if login_form:
                for field in login_form.find_all("input"):
                    name = field.get("name")
                    if not name:
                        continue
                    # Credentials are already set and must not be overwritten by form defaults.
                    if name in (login_cfg["username_field"], login_cfg["password_field"]):
                        continue
                    field_type = field.get("type", "text").lower()
                    value = field.get("value", "")
                    # Include submit buttons (always) and any field carrying a non-empty default
                    # value (covers CSRF tokens, user_token, and similar hidden fields).
                    if field_type == "submit" or value:
                        payload[name] = value
                        logger.debug(
                            f"Form field '{name}' (type={field_type}) added to payload for {cred['role']}"
                        )

            # Also supports frameworks that expose `CSRF` via the meta tags.
            meta_csrf = soup.find("meta", {"name": "csrf-token"})
            if meta_csrf and meta_csrf.get("content"):
                payload["_csrf"] = meta_csrf["content"]
                logger.debug(f"CSRF token found in meta tag for {cred['role']}")

        # Submits the login request with redirects followed so that DVWA's PHP session is fully
        # established after the server processes the redirect chain to `/index.php`.
        # Stopping at the 302 (allow_redirects=False) leaves `fresh_session` holding a pre-auth
        # PHPSESSID that DVWA has already invalidated server-side, causing every subsequent
        # crawler request to receive the login page regardless of credentials.
        try:
            response = fresh_session.post(
                login_url,
                data=payload,
                verify=self.config.verify_ssl,
                timeout=15,
                allow_redirects=True,
            )
        except Exception as e:
            logger.error(f"Form login POST failed for role '{cred['role']}': {e}")
            return False

        success_indicator = str(login_cfg.get("success_indicator", "200"))

        # With allow_redirects=True, the final response status is the post-redirect page (e.g., 200
        # for index.php). Check `response.history` for the expected intermediate status code instead.
        got_expected_redirect = any(
            str(r.status_code) == success_indicator for r in response.history
        )

        # Confirm the final URL is not a login or setup page, which would indicate auth failure.
        # A 302 to /setup.php (DVWA not initialised) or a stay at /login.php (wrong credentials /
        # bad CSRF token) are both caught here, regardless of the intermediate status code.
        final_url_lower = response.url.lower()
        ended_at_auth_page = any(
            indicator in final_url_lower for indicator in ("login", "setup")
        )

        body_lower = response.text.lower()
        no_error = not any(
            kw in body_lower for kw in ("invalid", "incorrect", "failed", "error")
        )

        # Primary success path: redirect chain contained the expected status and the final page is
        # not a login or setup page. Fallback covers apps that return 200 directly on success (no
        # redirect), where the body also contains no error keywords.
        auth_succeeded = (got_expected_redirect and not ended_at_auth_page) or (
            no_error and not ended_at_auth_page
        )

        if auth_succeeded:
            # Stores the session data for later use. `fresh_session.cookies` is captured after the
            # full redirect chain has completed, so the snapshot reflects the live authenticated state.
            self.sessions[cred["role"]] = {
                "cookies": dict(fresh_session.cookies),
                "session_obj": fresh_session,
                "auth_type": "form",
                "username": cred["username"],
            }

            # Registers this session with `HTTPClient` so that all future requests will reuse it.
            self.http_client.register_session(cred["role"], fresh_session)

            logger.info(
                f"Form auth succeeded for role '{cred['role']}' ({cred['username']})"
            )

            # Executes any post-authentication steps using the admin session, e.g. setting DVWA security level to Low.
            post_auth_steps = login_cfg.get("post_auth_steps", [])
            if post_auth_steps and cred.get("role") == "admin":
                # Iterates each configured post-auth step and dispatches a POST request using the authenticated admin session.
                for step in post_auth_steps:
                    step_url = step.get("url", "")
                    step_method = step.get("method", "POST").upper()
                    step_data = step.get("data", {})
                    try:
                        if step_method == "POST":
                            fresh_session.post(
                                step_url,
                                data=step_data,
                                verify=self.config.verify_ssl,
                                timeout=15,
                                allow_redirects=True,
                            )
                        logger.info(
                            f"Post-auth step completed for admin role: {step_method} {step_url}"
                        )
                    except Exception as exc:
                        logger.warning(
                            f"Post-auth step failed for admin role at {step_url}: {exc}"
                        )

            return True

        logger.warning(
            f"Form auth failed for role '{cred['role']}' - final URL: {response.url}, status: {response.status_code}"
        )
        return False

    def _authenticate_bearer(self, cred: dict) -> bool:
        # Handles the token-based authentication (e.g., `JWT APIs` like OWASP Juice Shop).
        # Extracts tokens from the JSON response, and then stores it for a header injection.

        login_cfg = self.config.login_config
        raw_login_url = login_cfg["login_url"]
        # Uses the login URL directly if it is already absolute, otherwise prepends the base target URL.
        if raw_login_url.startswith("http://") or raw_login_url.startswith("https://"):
            login_url = raw_login_url
        else:
            login_url = (
                self.config.target_url.rstrip("/") + "/" + raw_login_url.lstrip("/")
            )

        try:
            response = self.http_client.send_request(
                "POST",
                login_url,
                json_body={"email": cred["username"], "password": cred["password"]},
            )[0]
        except Exception as e:
            logger.error(f"Bearer login request failed for role '{cred['role']}': {e}")
            return False

        if response is None:
            logger.warning(
                f"Bearer login returned no response for role '{cred['role']}'"
            )
            return False

        # Parse the JSON response safely.
        try:
            body = response.json()
        except Exception:
            logger.warning(
                f"Bearer login response was not valid JSON for role '{cred['role']}'"
            )
            return False

        # Tries multiple common token fields across frameworks.
        extracted_token = None
        for key in ("token", "access_token", "jwt", "auth_token"):
            if key in body:
                extracted_token = body[key]
                break
            if "authentication" in body and isinstance(body["authentication"], dict):
                if key in body["authentication"]:
                    extracted_token = body["authentication"][key]
                    break

        if not extracted_token:
            logger.warning(
                f"Could not extract bearer token for role '{cred['role']}' - keys found: {list(body.keys())}"
            )
            return False

        # Stores tokens and pre-built authorisation headers.
        self.sessions[cred["role"]] = {
            "cookies": {},
            "token": extracted_token,
            "auth_header": {"Authorization": f"Bearer {extracted_token}"},
            "auth_type": "bearer",
            "username": cred["username"],
        }
        logger.info(
            f"Bearer auth succeeded for role '{cred['role']}' ({cred['username']})"
        )
        return True

    def _authenticate_basic(self, cred: dict) -> bool:
        # Handles HTTP Basic authentication.
        # Encodes credentials and verifies its access via a test endpoint.

        encoded = base64.b64encode(
            f"{cred['username']}:{cred['password']}".encode()
        ).decode()

        auth_header = {"Authorization": f"Basic {encoded}"}

        # Verifies the credentials against a known endpoint.
        test_url = self.config.target_url.rstrip("/") + "/api/"
        response, _ = self.http_client.send_request(
            "GET", test_url, headers=auth_header
        )

        if response is None or response.status_code not in (200, 201, 204):
            logger.warning(f"Basic auth test request failed for role '{cred['role']}'")
            return False

        self.sessions[cred["role"]] = {
            "cookies": {},
            "auth_header": auth_header,
            "auth_type": "basic",
            "username": cred["username"],
        }
        logger.info(
            f"Basic auth succeeded for role '{cred['role']}' ({cred['username']})"
        )
        return True

    def _authenticate_api_key(self, cred: dict) -> bool:
        # Handles the `API` key authentication by storing the key in a header.
        # No verification request is made here (its assumed valid if provided.)

        api_key = cred.get("api_key")

        if not api_key:
            logger.warning(f"No api_key field found for role '{cred['role']}'")
            return False

        api_key_header = cred.get("api_key_header", "X-API-Key")

        self.sessions[cred["role"]] = {
            "cookies": {},
            "auth_header": {api_key_header: api_key},
            "auth_type": "api_key",
            "username": cred.get("username", ""),
        }
        logger.info(f"API key auth stored for role '{cred['role']}'")
        return True

    def authenticate_all(self) -> dict:
        # The entry point used by the scanner to authenticate every configured role.
        # Iterates through credentials and dipatches to the correct auth-handler.

        results = {}

        for cred in self.config.credentials:
            role = cred.get("role", "unknown")
            auth_type = cred.get("auth_type", "form")
            logger.info(f"Authenticating role '{role}' via {auth_type}...")

            if auth_type == "form":
                results[role] = self._authenticate_form(cred)
            elif auth_type == "bearer":
                results[role] = self._authenticate_bearer(cred)
            elif auth_type == "basic":
                results[role] = self._authenticate_basic(cred)
            elif auth_type == "api_key":
                results[role] = self._authenticate_api_key(cred)
            else:
                logger.warning(
                    f"Unknown auth_type '{auth_type}' for role '{role}' - skipping"
                )
                results[role] = False

        return results

    def get_session_kwargs(self, role: str) -> dict:
        # The core abstraction used across the scanner.
        """It returns the correct request `kwargs` (cookies or headers) for a given role,
        allowing other modules to remain completely auth-agnostic."""

        # Returns empty kwargs immediately for unauthenticated requests, without logging a warning.
        if role is None:
            return {}

        session = self.sessions.get(role)

        if not session:
            logger.warning(
                f"No session found for role '{role}' - returning empty kwargs"
            )
            return {}

        auth_type = session.get("auth_type")

        if auth_type == "form":
            # Only `session_key` is returned so that `HTTPClient` routes requests through the live
            # `fresh_session` object directly. Passing a `cookies=` snapshot alongside `session_key`
            # would override the live cookie jar with a stale pre-redirect snapshot, causing DVWA to
            # treat every crawler request as unauthenticated.
            return {"session_key": role}
        elif auth_type in ("bearer", "basic", "api_key"):
            return {"headers": session["auth_header"], "session_key": role}

        return {}

    def get_cookies(self, role: str) -> dict:
        # Helper to directly retrieve stored cookies for a role.
        session = self.sessions.get(role, {})
        return session.get("cookies", {})

    def get_all_roles(self) -> list:
        # Returns all the roles that have been successfuly authenticated.
        return list(self.sessions.keys())

    def get_unauthenticated_kwargs(self) -> dict:
        # Used when testing endpoints without authentication.
        return {}