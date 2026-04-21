"""
`workflow_recorder.py`

Records multi-step HTTP workflows, defined in the scanner configuration, substituting token placeholders between steps, and extracting values from responses.
Recorded workflows are stored in `self.recorded_workflows` for consumption by `WorkflowBypassTester`,
"""
import copy
import json
import re

from scanner.core.http_client import HTTPClient
from scanner.core.session_manager import SessionManager
from scanner.core.csrf import CSRFExtractor
from scanner.core.logger import get_logger

logger = get_logger(__name__)


class WorkflowRecorder:
    """ Replays multi-step HTTP workflows, from the `self.config.workflows`, substituting dynamic token values between steps.
    Then stores each completed workflow in `self.recorded_workflows`, as a dictionary of recorded steps, and extracted tokens."""

    def __init__(self, config, http_client, session_manager):
        """ Stores `config`, `http_client`, and `session_manager`, initialising `self.recorded_workflows` as an empty 
        dictionary ready to receive workflow recordings."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        # Stores completed workflow recordings, keyed by workflow name for use by `WorkflowBypasssTester`.
        self.recorded_workflows = {}

    def _substitute_tokens(self, template_str, token_store):
        """ Finds all `{{key}}` placeholders in `template_str`, and replaces the matching value from `token_store`. Then logs
        a warning for any placehooder whose key is absent, returning the substituted string."""

        # Iterates through all placeholder matches in the template string, replacing each with its stored token value.
        for match in re.finditer(r'\{\{([^}]+)\}\}', template_str):
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
        """ Iterates `extract_config` entries, with each specifying a `name`, `source` (json, or regex), and `path`. 
        Extracts the values from `response`, using dot notation for JSON, or a capture group for regex, returning
        a dictionary of extracted name-value pairs."""

        # Accumuilates extracted name-value pairs, to return to the valler.
        extracted = {}
        # Iterates each extraction rule, and pulls the named value from the response using JSON path or regex.
        for item in extract_config:
            # Reads the extraction rule fields first, defaulting source to JSON if not specified.
            name = item['name']
            source = item.get('source', 'json')
            path = item.get('path', '')
            # Traverses the dot-notation JSON path, to extract the target field value.
            if source == 'json':
                try:
                    data = response.json()
                    # Splits the dot-notation path, and travels to parsed JSON structure key, by key.
                    for key in path.split('.'):
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
            elif source == 'regex':
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

    def record_workflow(self, workflow_name, steps, role='user_a'):
        """ Replays `steps` sequentially under `role`, substituting `{{key}}` placeholders before each request, 
        extracting CSRF tokens for form steps, and storing each request and response. Then saves the completed 
        recording to `self.recorded_workflows` under `workflow_name`."""

        # Retrieves the session credentials and headers for the specified role.
        session_kwargs = self.session_manager.get_session_kwargs(role)
        # HOlds the token values extracted from the responses, for substitution in later steps.
        token_store = {}
        # Accumulates the recorded request, and response data for each completed step.
        recorded_steps = []

        # Iterates each workflow step, subtituting tokens, sending the request, and extracting response values.
        for step_index, step in enumerate(steps):
            # Resolves any token placeholders in the URL, before the request is dispatched.
            url = self._substitute_tokens(step.get('url', ''), token_store)
            method = step.get('method', 'GET').upper()
            content_type = step.get('content_type', '')
            # Deep copies the body, to avoid mutating the original step definition from the config.
            body = copy.deepcopy(step.get('body'))

            # Substitutes token placeholders inside a JSON body serialised to a string, then parsed back.
            if body and isinstance(body, dict):
                body_str = self._substitute_tokens(json.dumps(body), token_store)
                body = json.loads(body_str)
            # Substitutes token placeholders inside a raw string body directly.
            elif body and isinstance(body, str):
                body = self._substitute_tokens(body, token_store)

            # Fetches the target page, and extracts a CSRF token when the step declares a form content type.
            if 'form' in content_type:
                page_response = self.http_client.get(url, **session_kwargs)
                csrf_data = CSRFExtractor.get_csrf_for_request(page_response)
                # Injects the CSRF token into the request body, when the token placement is a form field.
                if csrf_data and csrf_data.get('placement') == 'form':
                    if body is None:
                        body = {}
                    body[csrf_data['field_name']] = csrf_data['token']

            # Sends GET or POST to the resolved URL, using the role session, and substituted body.
            try:
                if method == 'GET':
                    response = self.http_client.get(url, **session_kwargs)
                else:
                    response = self.http_client.post(url, json=body, **session_kwargs)
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
            if 'extract' in step and response is not None:
                extracted = self._extract_tokens(response, step['extract'])
                # Merges newly extracted tokens into `token_store`, for use by subsequent steps.
                token_store.update(extracted)

            # Builds the recorded step dict, capturing the full request, and response for replay by `WorkflowBypassTester`
            recorded_step = {
                'url': url,
                'method': method,
                'body': body,
                'content_type': content_type,
                'response_status': response.status_code if response else None,
                'response_body': response.text if response else None,
                'response_json': None,
            }
            # Parses the response body as JSON, and stores it when the content type confirms a JSON response.
            if response is not None and 'json' in response.headers.get('Content-Type', ''):
                try:
                    recorded_step['response_json'] = response.json()
                except ValueError:
                    pass

            recorded_steps.append(recorded_step)
            logger.debug(
                "Recorded step %d for workflow `%s`: %s %s -> %s",
                step_index + 1,
                workflow_name,
                method,
                url,
                recorded_step['response_status'],
            )

        # Stores the completed workflow recording, under its name for access by `WorkflowBypassTester`.
        self.recorded_workflows[workflow_name] = {
            'steps': recorded_steps,
            'tokens': token_store,
        }
        logger.info(
            "Workflow `%s` recorded with %d step(s).",
            workflow_name,
            len(recorded_steps),
        )

    def record_from_config(self):
        """ Iterates through all the workflow definitions in `self.config.workflows`, combining any `pre_steps` with the main `steps` list,
        and calls `record_workflow` for each to populate `self.recorded_workflows`."""

        # Handles both list format (from YAML array) and dict format, for workflow definitions.
        raw_workflows = self.config.workflows
        if isinstance(raw_workflows, list):
            workflows_dict = {item["name"]: item for item in raw_workflows}
        else:
            workflows_dict = raw_workflows
        # Iterates through each of the named workflow definitions in the config, and records it with pre-steps prepended.
        for workflow_name, workflow_def in workflows_dict.items():
            # Reads the role, pre-steps, and main steps from the worfklow definition dictionary.
            role = workflow_def.get('role', 'user_a')
            pre_steps = workflow_def.get('pre_steps', [])
            steps = workflow_def.get('steps', [])
            # Prepends the pre-steps to the main steps, so that token extraction setup runs before the workflow proper.
            all_steps = pre_steps + steps
            self.record_workflow(workflow_name, all_steps, role=role)
            logger.info(
                "Recorded workflow `%s` from config for role '%s'.",
                workflow_name,
                role,
            )