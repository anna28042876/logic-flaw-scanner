"""
`workflow_bypass.py`

Tests recorded workflows from `WorkflowRecorder` for any logic flaws. Includes step-skipping, out-of-order execution,
cross-session replay, unauthenticated replay, and 2FA bypass. The 2FA method is implemented as a theoretical capability,
as neither Juice Shop, nor DVWA, provides a 2FA flow to evaluate against.
"""
# Possibly implement 2FA flow in custom app.

import copy
import itertools
import random

from scanner.core.logger import get_logger
from scanner.core.models import Vulnerability

logger = get_logger(__name__)


class WorkflowBypassTester:
    """Takes in workflows recorded by `WorkflowRecorder`, and tests each one for bypass vulnerabilities.
    All confirmed findings are stored as `Vulnerability` objects, in `self.findings`."""

    def __init__(
        self, config, http_client, session_manager, workflow_recorder, comparator
    ):
        """Stores `config`, `http_client`, `session_manager`, `workflow_recorder`, and `comparator`.
        Initialises `self.findings` as an empty list, ready to accumulate bypass findings."""

        self.config = config
        self.http_client = http_client
        self.session_manager = session_manager
        self.workflow_recorder = workflow_recorder
        self.comparator = comparator
        # COnsolidates all the confirmed bypass findings as `VUlnerability` objects.
        self.findings = []
        # Seeds the random number generator with the fixed seed from `config` for reproducibility.
        random.seed(config.random_seed)

    def _replay_step(self, step, session_kwargs=None):
        """Replays a single recorded step dictionary using `session_kwargs` when called from cross-session,
        or authenticated replay tests, or with no credentials when called from `test_replay_unauthenticated`.
        Returns the HTTP response, or None if the request raises an exception.

        Args:
            step (dict): A recorded step dict containing `url`, `method`, and optionally `body`, as stored by `WorkflowRecorder.record_workflow`.

            session_kwargs (dict, optional): Session credentials to attach to the request. Passs `None`, or omit for an unauthenticated replay.

        Returns:
            requests.Response or None: The HTTP response, or `None`, if the request raises an exception."""

        url = step["url"]
        method = step.get("method", "GET").upper()
        # Deep copies the body to avoid mutating any of the original recorded steps during replay.
        body = copy.deepcopy(step.get("body"))
        # Falls back  to an empty dictionary, when no session credentials are provided for unauthenticated replay.
        kwargs = session_kwargs or {}
        # Dispatches POST or GET requests, for the recorded step using the provided session credentials.
        try:
            if method == "GET":
                return self.http_client.get(url, **kwargs)[0]
            return self.http_client.post(url, json_body=body, **kwargs)[0]
        except Exception as exc:
            logger.warning("Replay of %s %s raised an exception: %s", method, url, exc)
            return None

    def _final_step_succeeded(self, response):
        """Returns 'True' if `response` indicates the final workflow step was completed successfully,
        meaning a 200 status is returned, and access is granted.

        Args:
            response (request.Response or NOne): THe response from replaying the final workflow step.

        Returns:
            bool: `True`, if the response has status 200, and `ResponseCOmparator` classifies it as access granted. `False`,
            if the response is `None`, or access was denied."""

        # Returns 'False' immediately when the response is None, due to a request exection.
        if response is None:
            return False
        return response.status_code == 200 and self.comparator.is_access_granted(
            response
        )

    def test_skip_steps(self, workflow_name):
        """Retrieves the named workflow from `WorkflowRecorder`, and runs two skip tests, including jumping from step
        one directly to the final step, then individually skipping each middle step. Flags a High `Vulnerability` for each
        successful bypass.

        Args"
            workflow_name (str): THe name of a recorded workflow, in `self.workflow_recorder.recorded_workflows`."""

        workflow = self.workflow_recorder.recorded_workflows.get(workflow_name)
        # Skips testing if the workflow name is not present in `self.recorded_workflows`.
        if not workflow:
            logger.warning(
                "Workflow `%s` not found in recorded workflows, skipping skip-step test.",
                workflow_name,
            )
            return

        steps = workflow["steps"]
        # Skips testing if the workflow contains fewer than three steps, as skip testing requires a first, at least one middle, and final step.
        if len(steps) < 3:
            logger.debug(
                "Workflow `%s` has fewer than 3 steps, no middle steps to skip.",
                workflow_name,
            )
            return

        # Isolates the first step, middle, and final steps so that test 1 can skip all middle steps, and test 2 can skip each individualy.
        first_step = steps[0]
        final_step = steps[-1]
        middle_steps = steps[1:-1]
        session_kwargs = self.session_manager.get_session_kwargs("user_a")

        # Test 1. Replays step one to establish a session state, then jumps directly to the final step to check whether the server enforces intermediate steps.
        self._replay_step(first_step, session_kwargs)
        response_skip_all = self._replay_step(final_step, session_kwargs)
        # Flags a High findings, if the final step succeeds after all middle steps were skipped.
        if self._final_step_succeeded(response_skip_all):
            vuln = Vulnerability(
                vuln_type="Workflow Bypass - Step Skip",
                severity="High",
                endpoint=final_step["url"],
                method=final_step.get("method", "GET").upper(),
                # Records the HTTP status code, and worfklow name as machine-readable evidence.
                evidence=(
                    f"Final step of workflow `{workflow_name}` succeeded with HTTP "
                    f"{response_skip_all.status_code} after skipping all middle steps."
                ),
                # Describes the missing server-side state enforcement.
                description=(
                    f"Workflow `{workflow_name}` allows the final action to be completed "
                    f"without executing intermediate validation steps, indicating missing "
                    f"server-side state enforcement."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "HIGH: Workflow skip-all bypass confirmed for `%s`.", workflow_name
            )

        # Test 2. Iterates each middle step individually, to identify which specific steps the server fails to enforce. Rather than just whether any can be skipped.
        for i, skipped_step in enumerate(middle_steps):
            # Builds the reduced sequence by excluding on the current middle step at index i.
            sequence = (
                [first_step]
                + [s for j, s in enumerate(middle_steps) if j != i]
                + [final_step]
            )
            # Replays each step in the reduced seqwuence, to check if the final step still succeeds.
            for step in sequence[:-1]:
                self._replay_step(step, session_kwargs)
            response_skip_one = self._replay_step(sequence[-1], session_kwargs)
            # FLags a high finding identifying which of the specific middle steps could be skipped.
            if self._final_step_succeeded(response_skip_one):
                skipped_url = skipped_step["url"]
                vuln = Vulnerability(
                    vuln_type="Workflow Bypass - Step Skip",
                    severity="High",
                    endpoint=final_step["url"],
                    method=final_step.get("method", "GET").upper(),
                    # Uses `step_index` + 2 because the middle steps begin at position 2 in the full workflow.
                    evidence=(
                        f"Final step of workflow `{workflow_name}` succeeded with HTTP "
                        f"{response_skip_one.status_code} when step {i + 2} "
                        f"({skipped_url}) was skipped."
                    ),
                    description=(
                        f"Step {i + 2} of workflow `{workflow_name}` ({skipped_url}) "
                        f"is not enforced server-side and can be omitted without "
                        f"preventing the final action from succeeding."
                    ),
                )
                self.findings.append(vuln)
                logger.warning(
                    "HIGH: Step skip bypass confirmed for `%s` at step %d (%s).",
                    workflow_name,
                    i + 2,
                    skipped_url,
                )

    def test_out_of_order(self, workflow_name):
        """Retrieves the named workflow, and generates step permutations. For workflows with 4, or fewer, steps, all permutations are tested.
        For 5, or more, steps, a targeted stretegy is used where the final step is moved earlier, the first step moved later, and the full reversal.
        It flags a `High` `VUlnerability` for any permutation where the final action succeeds.

        Args:
            workflow_name (str): THe name of a recordd workflow, in `self.workflow_recorder.recorded_workflows`."""

        workflow = self.workflow_recorder.recorded_workflows.get(workflow_name)
        # Skips testing if the workflow name is not present in `self.recorded_workflows`.
        if not workflow:
            logger.warning(
                "Workflow `%s` not found in recorded workflows, skipping out-of-order test.",
                workflow_name,
            )
            return

        steps = workflow["steps"]
        # Skips testing if the workflow containes fewer than three steps, as the ordering cannot be meaningfully varied.
        if len(steps) < 3:
            logger.debug(
                "Workflow `%s` has fewer than 3 steps, out-of-order testing skipped.",
                workflow_name,
            )
            return

        session_kwargs = self.session_manager.get_session_kwargs("user_a")
        # Builds a list of step indices to use as the foundation for generating permutations.
        indices = list(range(len(steps)))
        # Stores the canonical order, to exclude it from bypass testing, as it is the legitimate sequence.
        canonical = tuple(indices)

        # Builds all permutations for short workflows, or a targeted set for longer ones.
        if len(steps) <= 4:
            # Uses permutation for wrofklows with 4, or fewer, steps, up to 24 combinations.
            permutations_to_test = list(itertools.permutations(indices))
        else:
            # Seeds the random number generator with 42, for reproducibility across scan runs.
            random.seed(42)
            targeted = set()
            final = indices[-1]
            first = indices[0]
            # Generates permutations within the final step moved to each earlier position.
            for pos in range(len(indices) - 1):
                perm = indices[:]
                perm.remove(final)
                perm.insert(pos, final)
                targeted.add(tuple(perm))
            # Generates the permutations with the first step moved to each later position.
            for pos in range(1, len(indices)):
                perm = indices[:]
                perm.remove(first)
                perm.insert(pos, first)
                targeted.add(tuple(perm))
                # Adds the fully reversed sequence as an additional targeted bypass pattern.
            targeted.add(tuple(reversed(indices)))
            permutations_to_test = list(targeted)

        # Iterates each permutation, replays the reordered steps, and checks if the final action succeeds.
        for perm in permutations_to_test:
            # SKips the canonical order, as it is the legitimate sequence, and not a bypass attempt.
            if tuple(perm) == canonical:
                continue
            # Builds the reordered step list via mapping each permuted index back to the recorded steps.
            reordered_steps = [steps[i] for i in perm]
            # Replays all steps, except the last, to establish any required state, prior to final action.
            for step in reordered_steps[:-1]:
                self._replay_step(step, session_kwargs)
            response_final = self._replay_step(reordered_steps[-1], session_kwargs)
            # FLags a 'High' finding, if the final step succeeds under a reordered execution sequence.
            if self._final_step_succeeded(response_final):
                # Formats the step order as human-readable strings, using 1-based step numbers.
                order_str = " -> ".join(str(i + 1) for i in perm)
                vuln = Vulnerability(
                    vuln_type="Workflow Bypass - Out of Order Execution",
                    severity="High",
                    endpoint=reordered_steps[-1]["url"],
                    method=reordered_steps[-1].get("method", "GET").upper(),
                    evidence=(
                        f"Final step of workflow `{workflow_name}` succeeded with HTTP "
                        f"{response_final.status_code} under step order: {order_str}."
                    ),
                    description=(
                        f"Workflow `{workflow_name}` does not enforce step execution "
                        f"order server-side. The final action succeeded under a "
                        f"reordered sequence ({order_str}), indicating missing state "
                        f"machine enforcement."
                    ),
                )
                self.findings.append(vuln)
                logger.warning(
                    "HIGH: Out-of-order bypass confirmed for `%s` with order %s.",
                    workflow_name,
                    order_str,
                )

    def test_replay_cross_session(self, workflow_name):
        """Replays the final step of the named workflow, using `user_bs`'s session, instead of the original role.
        Flags a 'High' `Vulnerability`, if the final step succeeds under the alternate session.

        Args:
            workfow_name (str): The name of a recorded workflow, `self.workflow_recorder.recorded_workflows`."""

        workflow = self.workflow_recorder.recorded_workflows.get(workflow_name)
        # SKips testing if the workflow name is not present in `self.recorded_workflows`.
        if not workflow:
            logger.warning(
                "Workflow `%s` not found in recorded workflows, skipping cross-session replay.",
                workflow_name,
            )
            return

        steps = workflow["steps"]
        final_step = steps[-1]
        # Retrieves `user_b` session credentials to replay the final step under a different unauthenticated user.
        cross_kwargs = self.session_manager.get_session_kwargs("user_b")
        response = self._replay_step(final_step, cross_kwargs)
        # Flags a 'High' finding if the final step succeeds under a different user session.
        if self._final_step_succeeded(response):
            vuln = Vulnerability(
                vuln_type="Workflow Bypass - Cross-Session Replay",
                severity="High",
                endpoint=final_step["url"],
                method=final_step.get("method", "GET").upper(),
                evidence=(
                    f"Final step of workflow `{workflow_name}` succeeded with HTTP "
                    f"{response.status_code} when replayed under `user_b` session."
                ),
                description=(
                    f"The final action of workflow `{workflow_name}` can be executed "
                    f"by a different authenticated user without completing the prior "
                    f"steps, indicating the server does not bind workflow state to "
                    f"the originating session."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "HIGH: Cross-session replay confirmed for workflow `%s`.", workflow_name
            )

    def test_replay_unauthenticated(self, workflow_name):
        """Replays the final step of the named workflow, with no authentication credentials.
        Flags a 'Critical' `Vulnerability` if the final step succeeds without any session."""

        workflow = self.workflow_recorder.recorded_workflows.get(workflow_name)
        # Skips testing if the workflow name is not present in `self.recorded_workflows`.
        if not workflow:
            logger.warning(
                "Workflow `%s` not found in recorded workflows, skipping unauthenticated replay.",
                workflow_name,
            )
            return

        steps = workflow["steps"]
        final_step = steps[-1]
        # Passes no session kwargs, so that the request is sent with no authentication credentials.
        response = self._replay_step(final_step)
        # FLags a 'Critical' findings, if the final step succeeds with no authentication credentials.
        if self._final_step_succeeded(response):
            vuln = Vulnerability(
                vuln_type="Workflow Bypass - Unauthenticated Replay",
                severity="Critical",
                endpoint=final_step["url"],
                method=final_step.get("method", "GET").upper(),
                evidence=(
                    f"Final step of workflow `{workflow_name}` succeeded with HTTP "
                    f"{response.status_code} when replayed with no authentication."
                ),
                description=(
                    f"The final action of workflow `{workflow_name}` can be executed "
                    f"without any authentication, bypassing all session and workflow "
                    f"state requirements."
                ),
            )
            self.findings.append(vuln)
            logger.warning(
                "CRITICAL: Unauthenticated replay confirmed for workflow `%s`.",
                workflow_name,
            )

    ### Skeleton -- Custom app.
    def test_2fa_bypass(self):
        """Checks `self.config.workflows` for any workflow tagged as '2fa'. If found, executes the login step,
        skips the 2FA step, and attempts to access a protected resource. Neither Juice Shop, nor DVWA, implements
        2FA, so this method can't be evaluated against them, but has been theoretically implemented for the custom app."""

        # Handles both list format (from YAML array) and dict format, for workflow definitions.
        raw_workflows = self.config.workflows
        if isinstance(raw_workflows, list):
            workflows_dict = {item["name"]: item for item in raw_workflows}
        else:
            workflows_dict = raw_workflows

        # Iterates config workflows, and tests any tagged as 2fa, by skipping the 2FA verification step.
        for workflow_name, workflow_def in workflows_dict.items():
            # SKips any workflow that is not explicitly tagged as 2FA flow, in the config.
            if workflow_def.get("type") != "2fa":
                continue

            # Logs a notivce that the test is theoretical for the custom app only, and cannot produce real results against JS + DVWA.
            logger.info(
                "2FA bypass test found workflow `%s` tagged as 2fa. "
                "NOTE: this test is theoretical as neither Juice Shop nor DVWA "
                "provides a 2FA flow. The module is included to demonstrate "
                "scanner extensibility and would require a 2FA-enabled target "
                "to produce a real evaluation result.",
                workflow_name,
            )

            workflow = self.workflow_recorder.recorded_workflows.get(workflow_name)
            # Skips execution if the workflow does not contain at least three steps for login, 2FA, and resource access.
            if not workflow:
                logger.warning(
                    "2FA workflow `%s` has no recorded steps, skipping bypass attempt.",
                    workflow_name,
                )
                continue

            steps = workflow["steps"]
            # SKips extraction if the workflow does not contain at least three steps for login, 2FA, and resource access.
            if len(steps) < 3:
                logger.debug(
                    "2FA workflow `%s` has fewer than 3 steps, cannot test bypass.",
                    workflow_name,
                )
                continue

            session_kwargs = self.session_manager.get_session_kwargs("user_a")
            # Treats the first recorded step as the login step, and the last as the protected resource access.
            login_step = steps[0]
            protected_step = steps[-1]

            # Replays only the login step, intentionally omitting the 2FA verification step.
            self._replay_step(login_step, session_kwargs)
            response = self._replay_step(protected_step, session_kwargs)
            # FLags a 'Critical' finding, if the protected resource is accessible after skipping the 2FA step.
            if self._final_step_succeeded(response):
                vuln = Vulnerability(
                    vuln_type="Workflow Bypass - 2FA Skip",
                    severity="Critical",
                    endpoint=protected_step["url"],
                    method=protected_step.get("method", "GET").upper(),
                    evidence=(
                        f"Protected resource at {protected_step['url']} returned HTTP "
                        f"{response.status_code} after login with no 2FA step completed."
                    ),
                    description=(
                        f"Workflow `{workflow_name}` does not enforce the 2FA "
                        f"verification step server-side. A protected resource was "
                        f"accessed immediately after login, bypassing the second "
                        f"authentication factor entirely."
                    ),
                )
                self.findings.append(vuln)
                logger.warning(
                    "CRITICAL: 2FA bypass confirmed for workflow `%s`.", workflow_name
                )

    def test_all_workflows(self):
        """Iterates all worfklows in `self.workflow_recorded.recorded_workflows`, and runs `test_skip_steps`,
        `test_out_of_order`, `test_replay_cross_session`, and `test_replay_unauthenticated` for each. Also runs
        `test_2fa_bypass` once across all config workflows."""

        # Iterates each recorded worfklow, and runs all bypass test methods against it.
        for workflow_name in self.workflow_recorder.recorded_workflows:
            logger.info("Running all bypass tests for workflow `%s`.", workflow_name)
            self.test_skip_steps(workflow_name)
            self.test_out_of_order(workflow_name)
            self.test_replay_cross_session(workflow_name)
            self.test_replay_unauthenticated(workflow_name)
        # Runs the 2FA bypass test once, after all recorded workflows have been processed.
        self.test_2fa_bypass()

    def get_findings(self):
        """Returns `self.findings` accumuilated across all workflow bypass tests.

        Returns:
            list[Vulnerabiliity]: All `High` (step skip, out-of-order, cross session), and `Critical` (unauthenticated replay, 2FA skip) findings recorded during this module's test run."""
        return self.findings
