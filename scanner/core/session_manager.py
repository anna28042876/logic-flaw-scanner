"""
`session_manager.py`

Responsible for handling all authentication logic for the scanner.
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
    """Central manager that authenticates all the configured roles, and stores their session states. WOrks closely qwith `HTTPClient`, which actually
    sends requests using these sessions."""

    def __init__(self, config, http_client):
        """Stores `config`, and `http_client`, and initialises `self.sessions` as an empty dict, ready to be populated by `authenticate_all`."""

        self.config = config
        self.http_client = http_client

        """ Stores the authenticated session data per role:
        {
            "admin": {cookies, headers, auth_type, ...},
            "user_a": {...}
        } """
        self.sessions = {}

        # Session cache attempt.
        # self.session_cache = {}       Only stored raw `request.Session` objects,

    def _authenticate_form(self, cred: dict) -> bool:
        """Performs a form-based login for `cred`. Creates a fresh `requests.Session` per role, `GETs` the login page to extract CSRF toekns, andn hidden fields,
        POSTs the full payload with redirects followed, then stores the authenticated session. Also executes any `post_auth_steps` defined in `login_config`,
        for the admin role."""

        login_cfg = self.config.login_config

        # Creates a fresh isolated session for this role - dont merge IDOR breaks entirely.
        fresh_session = requests.Session()

        # print(f"authenticating {cred['role']}")

        # Apply proxy settings if the scanner is routing traffic through one (e.g., Burp).
        if self.config.proxy is not None:
            fresh_session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }

        # Constructs the full login URL safely by using the login URL directly if it is already absolute, otheerwise prepending the base target URL.
        raw_login_url = login_cfg["login_url"]
        if raw_login_url.startswith("http://") or raw_login_url.startswith("https://"):     # Issue to log - absolute URLs getting double prefixes prepended.
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
            
            soup = BeautifulSoup(get_resp.text, "lxml")  # LIable to break

            # logger.debug("login page fetched")

        except Exception as e:
            logger.warning(f"Could not GET login page for CSRF extraction: {e}")
            soup = None

        # Base payload with `username/password` mapped to the configured field names.
        payload = {
            login_cfg["username_field"]: cred["username"],
            login_cfg["password_field"]: cred["password"],
        }

        # payload structure
        # payload = {"username": cred["username"], "password": cred["password"]}

        # COllects all the named login form fields, including hidden CSRF tokens, and submit buttons, without overwriting the credentials that are already set.
        if soup:
            login_form = soup.find("form")
            if login_form:
                for field in login_form.find_all("input"):
                    name = field.get("name")
                    if not name:
                        continue
                    # Credentials are already set and must not be overwritten by form defaults.
                    if name in (
                        login_cfg["username_field"],
                        login_cfg["password_field"],
                    ):
                        continue
                    field_type = field.get("type", "text").lower()
                    value = field.get("value", "")
                    # Include submit buttons (always) and any field carrying a non-empty default value.
                    if field_type == "submit" or value:
                        payload[name] = value
                        logger.debug(
                            f"Form field '{name}' (type={field_type}) added to payload for {cred['role']}"
                        )

                        # print(payload)

            # Also supports frameworks that expose `CSRF` via the meta tags.
            meta_csrf = soup.find("meta", {"name": "csrf-token"})
            if meta_csrf and meta_csrf.get("content"):
                payload["_csrf"] = meta_csrf["content"]
                logger.debug(f"CSRF token found in meta tag for {cred['role']}")

        # FOllows redirects during login, so that DVWA fully establishes the authenticated PHP session, and does not invalidate the session cookie, after the redirect chain.
        try:
            response = fresh_session.post(
                login_url,
                data=payload,
                verify=self.config.verify_ssl,
                timeout=15,
                allow_redirects=True,       # Keep enabled or PHP sessions dont persist.
            )

            # print(response.status_code)

        except Exception as e:
            logger.error(f"Form login POST failed for role '{cred['role']}': {e}")
            return False

        success_indicator = str(login_cfg.get("success_indicator", "200"))

        # With `allow_redirects=True`, checks `response.history`  for the expected intermediate status.
        got_expected_redirect = any(
            str(r.status_code) == success_indicator for r in response.history
        )

        # Confirms the final URL is not a login, or setup page, indicating auth failure.
        final_url_lower = response.url.lower()
        # Login pages returning 200 was masking failed auth previously.
        ended_at_auth_page = any(
            indicator in final_url_lower for indicator in ("login", "setup")
        )

        body_lower = response.text.lower()
        no_error = not any(
            kw in body_lower for kw in ("invalid", "incorrect", "failed", "error")
        )

        # Primary success path, and fallback for paths that return 200 directly.
        auth_succeeded = (got_expected_redirect and not ended_at_auth_page) or (
            no_error and not ended_at_auth_page
        )

        if auth_succeeded:
            # Stores the auithenticated session, after the redirect chain completes, so that the saved cookies reflect the final valid login stte.
            self.sessions[cred["role"]] = {
                "cookies": dict(fresh_session.cookies),
                "session_obj": fresh_session,       # Keep storing live session objects - dont change - cookies not enough.
                "auth_type": "form",
                "username": cred["username"],
            }

            # Registers this session with `HTTPClient` so that all future requests will reuse it.
            self.http_client.register_session(cred["role"], fresh_session)

            logger.info(
                f"Form auth succeeded for role '{cred['role']}' ({cred['username']})"
            )

            # Executes any post-authentication steps using the admin session, e.g. setting DVWA security level to Low.
            post_auth_steps = login_cfg.get("post_auth_steps", [])      # TODO: Possibly refractor post-auth into its own helper.
            if post_auth_steps and cred.get("role") == "admin":         # Only admin should run setup/security config requests.
                # Iterates each configured post-auth step and dispatches a POST request using the authenticated admin session.
                for step in post_auth_steps:
                    step_url = step.get("url", "")
                    step_method = step.get("method", "POST").upper()
                    step_data = step.get("data", {})

                    # logger.debug(f"running post auth step {step_url}")

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

        # print(response.text[:300])

        return False

    def _authenticate_bearer(self, cred: dict) -> bool:
        """Performs a JSON post to the login endpoint, to obtain a JWT bearer token. Tries the keys `token`, `access_token`, `jwt``, and
        `auth_token`, in the response body, as well as the nested `authentication` wrapper used by JS."""

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

            # print(response)

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

            # logger.debug(body)

        except Exception:
            logger.warning(
                f"Bearer login response was not valid JSON for role '{cred['role']}'"
            )
            return False

        # Tries multiple common token fields across frameworks.
        extracted_token = None
        # JWT Field names inconsistent between apps - look up to expand.
        for key in ("token", "access_token", "jwt", "auth_token"):
            if key in body:
                extracted_token = body[key]
                break
            # JS only
            if "authentication" in body and isinstance(body["authentication"], dict):
                if key in body["authentication"]:
                    extracted_token = body["authentication"][key]
                    break

        if not extracted_token:
            logger.warning(
                f"Could not extract bearer token for role '{cred['role']}' - keys found: {list(body.keys())}"
            )

            # print(body)

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
        """Performs HTTP Basic authentication, by base64-encoding the credentials, and then verifying them against the `/api/` endpoint."""

        encoded = base64.b64encode(
            f"{cred['username']}:{cred['password']}".encode()
        ).decode()

        auth_header = {"Authorization": f"Basic {encoded}"}

        # Verifies the credentials against a known endpoint.
        test_url = self.config.target_url.rstrip("/") + "/api/"
        response, _ = self.http_client.send_request(
            "GET", test_url, headers=auth_header
        )

        # old endpoint
        # test_url = self.config.target_url

        if response is None or response.status_code not in (200, 201, 204):
            logger.warning(f"Basic auth test request failed for role '{cred['role']}'")

            # print(response.status_code)

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
        """Stores API key authentication, by reading the key from  the `cred`, and buyilding the appropriate header. NO verification request is sent."""

        # Dont auth check - some APIs rate-limit key validation.
        api_key = cred.get("api_key")

        if not api_key:
            logger.warning(f"No api_key field found for role '{cred['role']}'")
            return False

        api_key_header = cred.get("api_key_header", "X-API-Key")

        # previous header default
        # api_key_header = "Authorization"

        self.sessions[cred["role"]] = {
            "cookies": {},
            "auth_header": {api_key_header: api_key},
            "auth_type": "api_key",
            "username": cred.get("username", ""),
        }
        logger.info(f"API key auth stored for role '{cred['role']}'")
        return True

    def authenticate_all(self) -> dict:
        """Iterates through all of the configured credentials, and dispatches each to the correct authentication handler, based on its `auth_type` field."""

        results = {}

        for cred in self.config.credentials:
            role = cred.get("role", "unknown")
            auth_type = cred.get("auth_type", "form")
            logger.info(f"Authenticating role '{role}' via {auth_type}...")

            # TODO replace with dispatch map later maybe

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
        """It returns the correct request `kwargs` (cookies or headers) for a given role,
        allowing other modules to remain completely auth-agnostic."""

        # Returns empty kwargs immediately for unauthenticated requests, without logging a warning - prevents glitchy logs.
        if role is None:
            return {}

        session = self.sessions.get(role)

        if not session:
            logger.warning(
                f"No session found for role '{role}' - returning empty kwargs"
            )

            # print(self.sessions)
            # Dont attach anything for guest requests.
            return {}

        auth_type = session.get("auth_type")

        if auth_type == "form":
            # Returns only `session_key`, so requests use the live authenticated session directly, rather than stale pre-redirect cookies, that would invalidate authentication.
            return {"session_key": role}
        elif auth_type in ("bearer", "basic", "api_key"):
            return {"headers": session["auth_header"], "session_key": role}

        return {}

    def get_cookies(self, role: str) -> dict:
        """Returns the stored cookies dict, for the given role."""

        session = self.sessions.get(role, {})
        return session.get("cookies", {})

    def get_all_roles(self) -> list:
        """Returns all the roles that have been successfuly authenticated."""

        # print(self.sessions.keys())

        return list(self.sessions.keys())

    def get_unauthenticated_kwargs(self) -> dict:
        """Returns an empty dict, to be used as session kwargs, for unauthenticated requests."""
        return {}