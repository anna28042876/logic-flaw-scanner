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

    def _substitute_tokens(self, template_str, token_store):
        """Finds all `{{key}}` placeholders in `template_str`, and replaces the matching value from `token_store`. Then logs
        a warning for any placehooder whose key is absent, returning the substituted string."""

        # Iterates through all placeholder matches in the template string, replacing each with its stored token value.
        for match in re.finditer(r"\{\{([^}]+)\}\}", template_str):
            # Captures the full placeholder string e.g., {{step_1.basket_id}}, and its inner key.
            placeholder = match.group(0)
            key = match.group(1).strip()
            # Replaces the placeholder if the key exists, otherwise logs a warning for the missing token.
            if key in token_store:
                template_str = template_str.replace(placeholder, str(token_store[key]))
            else:
                logger.warning(
                    "Token placeholder %s has no matching entry in `token_store`.",
                    placeholder,
                )
        return template_str

    def _extract_tokens(self, response, extract_config):
        """Iterates `extract_config` entries, with each specifying a `name`, `source` (json, or regex), and `path`.
        Extracts the values from `response`, using dot notation for JSON, or a capture group for regex, returning
        a dictionary of extracted name-value pairs."""

        # Accumuilates extracted name-value pairs, to return to the valler.
        extracted = {}
        # Iterates each extraction rule, and pulls the named value from the response using JSON path or regex.
        for item in extract_config:
            # Reads the extraction rule fields first, defaulting source to JSON if not specified.
            name = item["name"]
            source = item.get("source", "json")
            path = item.get("path", "")
            # Traverses the dot-notation JSON path, to extract the target field value.
            if source == "json":
                try:
                    data = response.json()
                    # Splits the dot-notation path, and travels to parsed JSON structure key, by key.
                    for key in path.split("."):
                        data = data[key]
                    extracted[name] = data
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
                else:
                    logger.warning(
                        "Regex pattern '%s' did not match response text for token `%s`.",
                        path,
                        name,
                    )
        return extracted

    def _build_identity_tokens(self, role):
        """Extracts identity values from the session for `role`, decoding the JWT
        payload when the auth type is bearer. Returns a dictionary of token names
        to values, seeding `user_id` and `user_email` for placeholder substitution."""

        tokens = {}
        session_data = self.session_manager.sessions.get(role, {})

        # Decodes the JWT payload to extract the user ID, for bearer auth sessions.
        if session_data.get("auth_type") == "bearer" and "token" in session_data:
            try:
                import base64
                jwt_token = session_data["token"]
                # Splits the JWT into its three dot-separated segments.
                parts = jwt_token.split(".")
                if len(parts) >= 2:
                    # Pads the base64 payload segment to a multiple of 4 characters.
                    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    # Extracts the nested `data.id` and `data.email` fields from the Juice Shop JWT.
                    if "data" in payload and isinstance(payload["data"], dict):
                        if "id" in payload["data"]:
                            tokens["user_id"] = str(payload["data"]["id"])
                        if "email" in payload["data"]:
                            tokens["user_email"] = payload["data"]["email"]
                    # Falls back to top-level `id` and `sub` fields for other JWT formats.
                    if "user_id" not in tokens:
                        for key in ("id", "sub", "user_id", "userId"):
                            if key in payload:
                                tokens["user_id"] = str(payload[key])
                                break
            except Exception as exc:
                logger.warning("Could not decode JWT for role '%s': %s", role, exc)

        return tokens

    def record_workflow(self, workflow_name, steps, role="user_a", initial_tokens=None):
        """Replays `steps` sequentially under `role`, substituting `{{key}}` placeholders before each request,
        extracting CSRF tokens for form steps, and storing each request and response. Then saves the completed
        recording to `self.recorded_workflows` under `workflow_name`."""

        # Retrieves the session credentials and headers for the specified role.
        session_kwargs = self.session_manager.get_session_kwargs(role)
        # Seeds the token store with any identity values decoded from the session JWT.
        token_store = dict(initial_tokens) if initial_tokens else {}
        # Accumulates the recorded request, and response data for each completed step.
        recorded_steps = []

        # Iterates each workflow step, subtituting tokens, sending the request, and extracting response values.
        for step_index, step in enumerate(steps):
            # Resolves any token placeholders in the URL, before the request is dispatched.
            url = self._substitute_tokens(step.get("url", ""), token_store)
            method = step.get("method", "GET").upper()
            content_type = step.get("content_type", "")
            # Deep copies the body, to avoid mutating the original step definition from the config.
            body = copy.deepcopy(step.get("body"))

            # Substitutes token placeholders inside a JSON body serialised to a string, then parsed back.
            if body and isinstance(body, dict):
                body_str = self._substitute_tokens(json.dumps(body), token_store)
                body = json.loads(body_str)
            # Substitutes token placeholders inside a raw string body directly.
            elif body and isinstance(body, str):
                body = self._substitute_tokens(body, token_store)

            # Fetches the target page, and extracts a CSRF token when the step declares a form content type.
            if "form" in content_type:
                page_response = self.http_client.get(url, **session_kwargs)[0]
                csrf_data = CSRFExtractor.get_csrf_for_request(page_response)
                # Injects the CSRF token into the request body, when the token placement is a form field.
                if csrf_data and csrf_data.get("placement") == "form":
                    if body is None:
                        body = {}
                    body[csrf_data["field_name"]] = csrf_data["token"]

            # Sends GET, or POST, requests to the resolved URL, using the role session, and substituted body.
            try:
                if method == "GET":
                    response = self.http_client.get(url, **session_kwargs)[0]
                else:
                    response = self.http_client.post(
                        url, json_body=body, **session_kwargs
                    )[0]
            except Exception as exc:
                logger.warning(
                    "Step %d of workflow `%s` raised an exception on %s %s: %s",
                    step_index + 1,
                    workflow_name,
                    method,
                    url,
                    exc,
                )
                # Sets response to None, so that the step is still recorded with a null status.
                response = None

            # Extracts, and stores the named token values from the response when an extract config is present.
            if "extract" in step and response is not None:
                extracted = self._extract_tokens(response, step["extract"])
                # Merges newly extracted tokens into `token_store`, for use by subsequent steps.
                token_store.update(extracted)
                # Stores pre-step tokens with the `pre.` prefix, so main steps can reference `{{pre.name}}`.
                if step.get("_is_pre_step"):
                    for key, value in extracted.items():
                        token_store[f"pre.{key}"] = value

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
            # Parses the response body as JSON, and stores it when the content type confirms a JSON response.
            if response is not None and "json" in response.headers.get(
                "Content-Type", ""
            ):
                try:
                    recorded_step["response_json"] = response.json()
                except ValueError:
                    pass

            recorded_steps.append(recorded_step)
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
        if isinstance(raw_workflows, list):
            workflows_dict = {item["name"]: item for item in raw_workflows}
        else:
            workflows_dict = raw_workflows

        # Iterates through each of the named workflow definitions in the config.
        for workflow_name, workflow_def in workflows_dict.items():
            # Reads the role, pre-steps, and main steps from the workflow definition dictionary.
            role = workflow_def.get("role", "user_a")
            pre_steps = workflow_def.get("pre_steps", [])
            steps = workflow_def.get("steps", [])

            base = self.config.target_url.rstrip("/")

            # Resolves each step `path` to a full `url`, and tags pre-steps with `_is_pre_step`.
            resolved_steps = []
            for step in pre_steps:
                resolved = dict(step)
                if "url" not in resolved and "path" in resolved:
                    resolved["url"] = base + "/" + resolved["path"].lstrip("/")
                resolved["_is_pre_step"] = True
                resolved_steps.append(resolved)

            # Resolves each main step `path` to a full `url`.
            for step in steps:
                resolved = dict(step)
                if "url" not in resolved and "path" in resolved:
                    resolved["url"] = base + "/" + resolved["path"].lstrip("/")
                resolved_steps.append(resolved)

            # Seeds the initial token store with identity data from the authenticated session.
            initial_tokens = self._build_identity_tokens(role)

            self.record_workflow(
                workflow_name, resolved_steps, role=role, initial_tokens=initial_tokens
            )
            logger.info(
                "Recorded workflow `%s` from config for role '%s'.",
                workflow_name,
                role,
            )