"""
`comparator.py`

Core comparison and analysis logic for HTTP responses within the scanner.

Responsible for identifying meaningful differences between responses generated
under different contexts (the differing user roles, for example) in order to
detect potential vulnerabilities such as the IDOR vulnerability and data leakages.

Provides structural comparison (status codes, body lengths, similarities), JSON-aware
analysis' (key comparisons, sensitive field extractions), Heuristics to determine whether
access was actually granted, detection of leaked sensitive data across different responses,
and human-readable difference reporting for debugging and reporting modules.

Key part of the scanner's analysis layer, sitting between the raw HTTP execution, and final
vulnerabilty reporting.
"""

import json
import difflib
import re

from scanner.core.logger import get_logger

# Logger spanning project-wide for security-relevant events e.g., detected leaks.
logger = get_logger(__name__)


class ResponseComparator:
    """Provides the static, and instance, methods for comparing HTTP responses. Its used by every test module
    that needs to determine whether two responses differ in a security-relevant way e.g., identical body lengths,
    shared senssitive fields, or the absence of denial phrases."""

    MIN_CONTENT_LENGTH = 200

    def __init__(self, min_content_length=None):
        """Allows runtime override of the minimum content length threshold, used by `is_access_granted`.

        Args:
            min_content_length (int, optional): The ovveride for `MIN_CONTENT_LENGTH`. Useful for when scanning APIs, or lightweight
             endpoint that return small, but valid payloads. If NOne, the class constant (200) is used."""

        if min_content_length is not None:
            self.MIN_CONTENT_LENGTH = min_content_length

    @staticmethod
    def compare_status(resp_a, resp_b):
        """Checks wether two responses share the same HTTP status code.

        Args:
            resp_a (requests.Response): The first response, typically the baseline authenticated response.
            resp_b (requests.Response): The second response, typically the test e.g., cross role, or unauthenticated, response.

        Returns:
            bool: True, if both responses return the same status code, otherwise False."""

        return resp_a.status_code == resp_b.status_code

    @staticmethod
    def compare_body_length(resp_a, resp_b, threshold=0.1):
        """Compares response body sizes, using a relative threshold to account for dynamic content e.g., timestamps,
        CSRF tokens, or per-request UUIDs.

        Args:
            resp_a (requests.Response): The first response to compare.
            resp_b (requests.Response): The second response to compare.
            threshold (float): The mazimum allowable relative size difference, as a fraction, (0.1 = 10%). Defaults to 0.1.

            Returns:
                bool: True if the relative size difference is within `threshold`. False if the bodies differ significantly. Also returns
                True if both bodies are empty, and False if only one is empty."""

        len_a = len(resp_a.content)
        len_b = len(resp_b.content)

        # If both are empty, treat as equivallent.
        if len_a == 0 and len_b == 0:
            return True

        # If only one is empty, then they are different.
        if len_a == 0 or len_b == 0:
            return False

        # Calculates the relative difference ratio.
        ratio = abs(len_a - len_b) / max(len_a, len_b)
        return ratio <= threshold

    @staticmethod
    def compare_json_keys(json_a, json_b):
        """Recursively extracts all JSON keys using dotted notation for nested keys from both objects, and returns a structural diff
        showing which keys are unique to each and which are shared.

        Args:
            json_a (dict or list): The first parsed JSON value to compare.
            json_b (dict or list): The second parsed JSON value to compare.

        Returns:
            dict: A dictionnary with three sets called 'keys_only_in_a',
            'keys_only_in_b', and 'shared_keys', each containing dotted
            key path strngs."""

        def extract_keys(obj, prefix=""):
            keys = set()

            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Build the dotted path for nested keys e.g., `user.email`.
                    full_key = f"{prefix}.{k}" if prefix else k

                    keys.add(full_key)
                    keys.update(extract_keys(v, full_key))

            elif isinstance(obj, list):
                # Lists are traversed but do not add their own key level.
                for item in obj:
                    keys.update(extract_keys(item, prefix))

            return keys

        keys_a = extract_keys(json_a)
        keys_b = extract_keys(json_b)

        # Return a structure difference of key presence.
        return {
            "keys_only_in_a": keys_a - keys_b,
            "keys_only_in_b": keys_b - keys_a,
            "shared_keys": keys_a & keys_b,
        }

    @staticmethod
    def compare_body_text(body_a, body_b):
        """Calculates the textual similarity rati, between two response bodies, using `difflib.SequenceMatcher`.

        Args:
            body_a (str): The body teext of the first responce.

            body_b (str): The body text of the second response.

        Returns:
            float: A ratio between 0.0 (completley different) and 1.0 (identicle)."""

        return difflib.SequenceMatcher(None, body_a, body_b).ratio()

    @staticmethod
    def extract_sensitive_fields(json_body, patterns=None):
        """Recursively walks through a parsed JSON structure, and returns all key-value pairs
        whose key matches any of the provided sensitive field name patterns.

        Args:
            json_body (dict or list): The parsed JSON value to inspect.

            patterns (list[str], optional): A list of case-insensitive regex patterns, to match against key names. Defaults to a 13-entry list covering
                common PII, and credential field names e.g., email, name, token, password, balance, card, etc..

        Returns:
            dict: A flat dictionary of {key: value} pairs, where the key matched at least one sensitive pattern. Empty dict if no matches foundd."""

        if patterns is None:
            patterns = [
                "email",
                "name",
                "phone",
                "address",
                "ssn",
                "password",
                "token",
                "secret",
                "balance",
                "account",
                "card",
                "dob",
                "salary",
            ]

        found = {}

        def walk(obj):
            # Recursively traverses JSON to locate matching keys.
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Case-insensitive regex match against known sensitive patterns.
                    if any(
                        re.search(pattern, k, re.IGNORECASE) for pattern in patterns
                    ):
                        found[k] = v
                    walk(v)

            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(json_body)
        return found

    def is_data_leak(self, resp_a_body, resp_b_body, role_a_identifier=None):
        """Attempts to detect data leakages between two responses by checking whether a known identifier from role A appears in role B's response,
        and by comparing sensitive fields that were extracted from both parsed JSON bodys.

        Args:
            resp_a_body (requests.Response or str): The baseline role A's response object, or body text.

            resp_b_body (requests.Response or str): The test role B's response object, or body text.

            role_a_identifier (str, optional): A known unique string for role A, e.g. their email adress, whose presence in role B's response
            constituytes a confirmed leak.

        Returns:
            tuple: A two-element tuple of (bool, str). The bool is True if a leak is detected, otherwise its False. The `str` descibes the reason for the,
            determination."""

        if hasattr(resp_a_body, "text"):
            resp_a_body = resp_a_body.text
        if hasattr(resp_b_body, "text"):
            resp_b_body = resp_b_body.text

        # Tries to parse both bodies as JSON to allow for a structured comparison.
        try:
            json_a = json.loads(resp_a_body)
        except (json.JSONDecodeError, TypeError):
            json_a = None

        try:
            json_b = json.loads(resp_b_body)
        except (json.JSONDecodeError, TypeError):
            json_b = None

        """Fast-path detection where if a known identifier from Role A appears in Role B's response
        this is a strong identifier of a leak."""

        if role_a_identifier and role_a_identifier in resp_b_body:
            reason = f"Role A identifier '{role_a_identifier}' found in role B response body."
            logger.warning(reason)
            return True, reason

        # If both responses are valid JSON, compare sensitive fields.
        if json_a and json_b:
            fields_a = self.extract_sensitive_fields(json_a)
            fields_b = self.extract_sensitive_fields(json_b)

            # Identifies fields that exist in both responses with identical values.
            leaked = {
                k: v for k, v in fields_a.items() if k in fields_b and fields_b[k] == v
            }

            if leaked:
                reason = (
                    f"Sensitive fields present in both responses: {list(leaked.keys())}"
                )
                logger.warning(reason)
                return True, reason

        # No evidence of leaks found.
        return False, "No data leak found."

    def is_access_granted(self, response):
        """Determines whether a response represents genuine access to a protected resource, rather than an error page that happens
        to return HTTP 200.

        Args:
            response (requests.Response): The response to evaluate.

        Returns:
            bool: True, only if the response has status 200, does not contain common denial phrases, and has a body length of at least
            `MIN_CONTENT_LENGTH` bytes. False in all other cases.
        """

        denial_strings = [
            "access denied",
            "forbidden",
            "unauthorised",
            "unauthorized",
            "not allowed",
            "login required",
            "please log in",
        ]

        # Only HTTP 200 responses are considered potentially valid.
        if response.status_code != 200:
            return False

        body_lower = response.text.lower()

        # Checks for common denial phrases in the response bodies.
        if any(phrase in body_lower for phrase in denial_strings):
            return False

        # Ensures that the response has enough content to be meaningful.
        if len(response.content) < self.MIN_CONTENT_LENGTH:
            return False

        return True

    def generate_diff_report(self, resp_a, resp_b):
        """Generates a human-raedable comparison report, between two responses, including status match, body length comparison, similarity
        ratio, and a unified diff of the first 2000 chasracters of each body.

        Args:
            resp_a (requests.Response): The baseline response e.g., authenticated.
            resp_b (requests.Response): The test response e.g., cross-role or unauthenticated.

        Returns:
            str: A formatted multiline string, showing the conmparison results, and a unified diff, suitable for inclusion in vulnerability evidence ."""

        # Limits body size to avoid excessive outputs in reports.
        body_a = resp_a.text[:2000]
        body_b = resp_b.text[:2000]

        status_match = self.compare_status(resp_a, resp_b)
        length_match = self.compare_body_length(resp_a, resp_b)
        similarity = self.compare_body_text(body_a, body_b)

        # Generates a unified difference to show the exact line-level differences.
        diff_lines = list(
            difflib.unified_diff(
                body_a.splitlines(),
                body_b.splitlines(),
                lineterm="",
                fromfile="response_a",
                tofile="response_b",
            )
        )
        diff_text = "\n".join(diff_lines) if diff_lines else "No differences found."

        # The final formatted report string.
        report = (
            f"=== Response Comparator Report ===\n"
            f"Status match:      {status_match} "
            f"(A={resp_a.status_code}, B={resp_b.status_code})\n"
            f"Body length match: {length_match} "
            f"(A={len(resp_a.content)} bytes, B={len(resp_b.content)} bytes)\n"
            f"Similarity ratio:  {similarity:.4f}\n"
            f"\n--- Unified Diff (first 2000 chars each) ---\n"
            f"{diff_text}\n"
        )

        return report
