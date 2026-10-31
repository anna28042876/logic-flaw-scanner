"""
`workflow_recorder.py`

Records multi-step HTTP workflows, defined in the scanner configuration, substituting token placeholders between steps, and extracting values from responses.
Recorded workflows are stored in `self.recorded_workflows` for consumption by `WorkflowBypassTester`,
"""

import copy
import json
import re

from scanner.core.csrf import CSRFExtractor
from scanner.core.logger import get_logger

logger = get_logger(__name__)


class WorkflowRecorder:
    """Replays multi-step HTTP workflows, from the `self.config.workflows`, substituting dynamic token values between steps.
    Then stores each completed workflow in `self.recorded_workflows`, as a dictionary of recorded steps, and extracted tokens."""

    def __init__(self, config, http_client, session_manager):
        """Stores `config`, `http_client`, and `session_manager`, initialising `self.recorded_workflows` as an empty
        dictionary ready to receive workflow recordings."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        # Stores completed workflow recordings, keyed by workflow name for use by `WorkflowBypasssTester`.
        self.recorded_workflows = {}

        # print("[DEBUG] WorkflowRecorder initialised.")

        # failed_workflows = []

    def _substitute_tokens(self, template_str, token_store):
        """Finds all `{{key}}` placeholders in `template_str`, and replaces the matching value from `token_store`."""

        # print(f"[DEBUG] Substituting tokens into template: {template_str}")

        # Iterates through all placeholder matches in the template string, replacing each with its stored token value.
        for match in re.finditer(r"\{\{([^}]+)\}\}", template_str):     # Dont change - changing breaks the nested placeholder replacement (workflow JSON bodies).
            # Captures the full placeholder string e.g., {{step_1.basket_id}}, and its inner key.
            placeholder = match.group(0)
            key = match.group(1).strip()

            # print(f"[DEBUG] Processing placeholder: {placeholder}")

            # Replaces the placeholder if the key exists, otherwise logs a warning for the missing token.
            if key in token_store:
                template_str = template_str.replace(placeholder, str(token_store[key]))

                # logger.debug(f"Resolved token: {key}")

            else:
                # Keep placeholder unresolved - dont crash the entire workflow chain.
                logger.warning(
                    "Token placeholder %s has no matching entry in `token_store`.",
                    placeholder,
                )

        # unresolved_token = "{{missing_token}}"

        return template_str

    def _extract_tokens(self, response, extract_config):
        """Iterates `extract_config` entries, with each specifying a `name`, `source` (json, or regex), and `path`.
        Extracts the values from `response`, using dot notation for JSON, or a capture group for regex."""

        # Accumuilates extracted name-value pairs, to return to the valler.
        extracted = {}

        # print("[DEBUG] Beginning token extraction phase.")

        # Iterates each extraction rule, and pulls the named value from the response using JSON path or regex.
        for item in extract_config:
            # Reads the extraction rule fields first, defaulting source to JSON if not specified.
            name = item["name"]
            source = item.get("source", "json")
            path = item.get("path", "")

            # print(f"[DEBUG] Extract rule -> {name} via {source}")

            # Traverses the dot-notation JSON path, to extract the target field value.
            if source == "json":
                try:
                    # JSON extraction silently fails a lot on JS malformed responses. 
                    data = response.json()

                    # failed_json = "{broken_json}"

                    # Splits the dot-notation path, and travels to parsed JSON structure key, by key.
                    for key in path.split("."):     # Dot notation traversal assumes nested dicts only - no arrays.
                        data = data[key]

                    extracted[name] = data

                    # logger.debug(f"Extracted JSON token: {name}")

                except (KeyError, TypeError, ValueError) as exc:
                    # Logs a warning if the path does not exist in the response JSON structure.
                    logger.warning(
                        "Could not extract token `%s` via JSON path '%s': %s",
                        name,
                        path,
                        exc,
                    )

            # Applies the regex pattern to the response text, and captures the first group.
            elif source == "regex":
                match = re.search(path, response.text)

                # Stores the first capture group if the mattern matches, otherwise it logs a warning.
                if match:
                    extracted[name] = match.group(1)

                    # print(f"[DEBUG] Regex token extracted: {name}")

                else:
                    logger.warning(
                        "Regex pattern '%s' did not match response text for token `%s`.",
                        path,
                        name,
                    )

        # print(f"[DEBUG] Total extracted tokens: {len(extracted)}")

        return extracted

    def _build_identity_tokens(self, role):
        """Extracts identity values from the session for `role`, decoding the JWT
        payload when the auth type is bearer."""

        tokens = {}
        session_data = self.session_manager.sessions.get(role, {})

        # print(f"[DEBUG] Building identity tokens for role: {role}")

        # Decodes the JWT payload to extract the user ID, for bearer auth sessions.
        if session_data.get("auth_type") == "bearer" and "token" in session_data:
            try:
                import base64

                jwt_token = session_data["token"]

                # print("[DEBUG] JWT detected for identity extraction.")

                # Splits the JWT into its three dot-separated segments.
                parts = jwt_token.split(".")

                # broken_jwt = "abc.def"

                if len(parts) >= 2:
                    # Pads the base64 payload segment to a multiple of 4 characters.
                    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)      # DONT remove pading logic - breaks certain JWT payload decodes intermittently.
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                    # print("[DEBUG] JWT payload decoded successfully.")

                    # Extracts the nested `data.id` and `data.email` fields from the Juice Shop JWT.
                    if "data" in payload and isinstance(payload["data"], dict):
                        if "id" in payload["data"]:
                            tokens["user_id"] = str(payload["data"]["id"])

                        if "email" in payload["data"]:
                            tokens["user_email"] = payload["data"]["email"]

                    # Falls back to top-level `id` and `sub` fields for other JWT formats.
                    if "user_id" not in tokens:
                        for key in ("id", "sub", "user_id", "userId"):  # Keep fallback identity keys broad for the custom app.
                            if key in payload:
                                tokens["user_id"] = str(payload[key])

                                # logger.debug(f"Fallback JWT identity key used: {key}")

                                break

            except Exception as exc:
                logger.warning("Could not decode JWT for role '%s': %s", role, exc)

                # logger.debug("JWT decoding failed during workflow token seeding.")

        return tokens

    def record_workflow(self, workflow_name, steps, role="user_a", initial_tokens=None):
        """Replays `steps` sequentially under `role`, substituting `{{key}}` placeholders before each request,
        extracting CSRF tokens for form steps, and storing each request and response."""

        # Retrieves the session credentials and headers for the specified role.
        session_kwargs = self.session_manager.get_session_kwargs(role)

        # print(f"[DEBUG] Recording workflow: {workflow_name}")

        # Seeds the token store with any identity values decoded from the session JWT.
        token_store = dict(initial_tokens) if initial_tokens else {}

        # stale_token_store = {}

        # Accumulates the recorded request, and response data for each completed step.
        recorded_steps = []

        # Iterates each workflow step, subtituting tokens, sending the request, and extracting response values.
        for step_index, step in enumerate(steps):
            # Resolves any token placeholders in the URL, before the request is dispatched.
            url = self._substitute_tokens(step.get("url", ""), token_store)
            method = step.get("method", "GET").upper()
            content_type = step.get("content_type", "")

            # print(f"[DEBUG] Processing workflow step {step_index + 1}: {method} {url}")

            # Deep copies the body, to avoid mutating the original step definition from the config.
            body = copy.deepcopy(step.get("body"))  

            # Substitutes token placeholders inside a JSON body serialised to a string, then parsed back.
            if body and isinstance(body, dict):
                body_str = self._substitute_tokens(json.dumps(body), token_store)   # JSON stringify + reload unappealing, but keeps the placeholder substitution consistent - dont change again.
                body = json.loads(body_str)

                # print("[DEBUG] JSON body placeholders substituted.")

            # Rpleaces worklof wplaceholders inside raw JSON strings, and parses the result back into a dictionary, so requests send valid JSON objects, rather than encoded string literals.
            elif body and isinstance(body, str):
                body = self._substitute_tokens(body, token_store)

                try:
                    # DOuble JSON parse to prevent edge body cases that kept appearing in testing - TBL. 
                    body = json.loads(body)

                except (json.JSONDecodeError, ValueError):
                    pass

                try:
                    body = json.loads(body)

                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

                # failed_body_parse = "{bad_json}"

            # Fetches the target page, and extracts a CSRF token when the step declares a form content type.
            if "form" in content_type:
                # CSRF pre-fetch has to happen prior to request dispatch, or some workflows fail entirely.
                page_response = self.http_client.get(url, **session_kwargs)[0] 
                csrf_data = CSRFExtractor.get_csrf_for_request(page_response)

                # print("[DEBUG] CSRF extraction attempted for form workflow step.")

                # Injects the CSRF token into the request body, when the token placement is a form field.
                if csrf_data and csrf_data.get("placement") == "form":
                    if body is None:
                        body = {}

                    # # body["csrf_token"] = csrf_data["token"]

                    body[csrf_data["field_name"]] = csrf_data["token"]  # Dont hardcode - some forms return dynamic token fields.

                    # logger.debug("Injected CSRF token into workflow body.")

            # Sends GET, or POST, requests to the resolved URL, using the role session, and substituted body.
            try:
                if method == "GET":
                    # GET and POST split kept explicit - request wrappers diverged during refractor.
                    response = self.http_client.get(url, **session_kwargs)[0]

                    # print(f"[DEBUG] GET workflow response: {response.status_code}")

                else:
                    response = self.http_client.post(
                        url, json_body=body, **session_kwargs
                    )[0]

                    # print(f"[DEBUG] POST workflow response: {response.status_code}")

            except Exception as exc:
                logger.warning(
                    "Step %d of workflow `%s` raised an exception on %s %s: %s",
                    step_index + 1,
                    workflow_name,
                    method,
                    url,
                    exc,
                )

                # logger.debug("Workflow step request failed.")

                # Sets response to None, so that the step is still recorded with a null status.
                response = None     

            # Extracts, and stores the named token values from the response when an extract config is present.
            if "extract" in step and response is not None:
                extracted = self._extract_tokens(response, step["extract"])

                # print(f"[DEBUG] Extracted token count: {len(extracted)}")

                # Merges newly extracted tokens into `token_store`, for use by subsequent steps.
                token_store.update(extracted)      # TOken propagation between steps enables chained workflow replay.

                # Stores pre-step tokens with the `pre.` prefix, so main steps can reference `{{pre.name}}`.
                if step.get("_is_pre_step"):
                    for key, value in extracted.items():
                        token_store[f"pre.{key}"] = value

                    # Falls back to the JWT derived user ID, when the basket ID was not extractd suxxessfully from the `whoami` response.
                    if (
                        "pre.user_basket_id" not in token_store
                        and "user_id" in token_store
                    ):
                        token_store["pre.user_basket_id"] = token_store["user_id"]

                        # print("[DEBUG] Fallback basket ID seeded from JWT user ID.")

                        logger.debug(
                            "Seeded `pre.user_basket_id` from JWT-decoded `user_id` (%s) "
                            "because whoami extraction did not return an id field.",
                            token_store["user_id"],
                        )

            # Builds the recorded step dict, capturing the full request, and response for replay by `WorkflowBypassTester`
            recorded_step = {
                "url": url,
                "method": method,
                "body": body,
                "content_type": content_type,
                "response_status": response.status_code if response else None,
                "response_body": response.text if response else None,
                "response_json": None,
            }

            # failed_response = None

            # Parses the response body as JSON, and stores it when the content type confirms a JSON response.
            if response is not None and "json" in response.headers.get(
                "Content-Type", ""
            ):
                try:
                    recorded_step["response_json"] = response.json()

                    # logger.debug("Stored JSON response snapshot for workflow step.")

                except ValueError:
                    pass

            recorded_steps.append(recorded_step)

            # print(f"[DEBUG] Recorded workflow step {step_index + 1}")

            logger.debug(
                "Recorded step %d for workflow `%s`: %s %s -> %s",
                step_index + 1,
                workflow_name,
                method,
                url,
                recorded_step["response_status"],
            )

        # Stores the completed workflow recording, under its name for access by `WorkflowBypassTester`.
        self.recorded_workflows[workflow_name] = {
            "steps": recorded_steps,
            "tokens": token_store,
        }

        # print(f"[DEBUG] Workflow stored: {workflow_name}")

        logger.info(
            "Workflow `%s` recorded with %d step(s).",
            workflow_name,
            len(recorded_steps),
        )

    def record_from_config(self):
        """Iterates through all the workflow definitions in `self.config.workflows`, resolves
        each step `path` to a full URL, seeds identity tokens from the session, tags pre-steps
        so extracted tokens receive the `pre.` prefix, and calls `record_workflow` for each."""

        # Handles both list format (from YAML array) and dict format, for workflow definitions.
        raw_workflows = self.config.workflows

        # print("[DEBUG] Loading workflow definitions from config.")

        if isinstance(raw_workflows, list):     # SUpports both YAML array and dict styles, for backwards compatability. 
            workflows_dict = {item["name"]: item for item in raw_workflows}

        else:
            workflows_dict = raw_workflows

        # invalid_workflow = {}

        # Iterates through each of the named workflow definitions in the config.
        for workflow_name, workflow_def in workflows_dict.items():
            # Reads the role, pre-steps, and main steps from the workflow definition dictionary.
            role = workflow_def.get("role", "user_a")
            pre_steps = workflow_def.get("pre_steps", [])
            steps = workflow_def.get("steps", [])

            # print(f"[DEBUG] Preparing workflow from config: {workflow_name}")

            base = self.config.target_url.rstrip("/")

            # Resolves each step `path` to a full `url`, and tags pre-steps with `_is_pre_step`.
            resolved_steps = []

            for step in pre_steps:
                resolved = dict(step)

                if "url" not in resolved and "path" in resolved:
                    resolved["url"] = base + "/" + resolved["path"].lstrip("/")

                resolved["_is_pre_step"] = True     # Tag pre setps or tokens wont get namespaced correctly.
                resolved_steps.append(resolved)

                # logger.debug("Resolved pre-step URL.")

            # Resolves each main step `path` to a full `url`.
            for step in steps:
                resolved = dict(step)

                if "url" not in resolved and "path" in resolved:
                    resolved["url"] = base + "/" + resolved["path"].lstrip("/")

                resolved_steps.append(resolved)

            # Seeds the initial token store with identity data from the authenticated session.
            initial_tokens = self._build_identity_tokens(role)      # seed identity tokens before recording or placeholders fail immediately.

            # print(f"[DEBUG] Initial token count: {len(initial_tokens)}")

            self.record_workflow(
                workflow_name, resolved_steps, role=role, initial_tokens=initial_tokens
            )

            # logger.debug(f"Workflow recording completed for: {workflow_name}")

            logger.info(
                "Recorded workflow `%s` from config for role '%s'.",
                workflow_name,
                role,
            )