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

    # Can lower if needed - not too much - tiny denial pages will flag as valid. 
    MIN_CONTENT_LENGTH = 200

    def __init__(self, min_content_length=None):
        """Allows runtime override of the minimum content length threshold, used by `is_access_granted`."""

        # print(f"[DEBUG] Initialising comparator with minimum length: {min_content_length}")

        # Override needd - some API responses valid, but way smaller than HTML pages.
        if min_content_length is not None:
            self.MIN_CONTENT_LENGTH = min_content_length

        # fallback_length = 50

    @staticmethod
    def compare_status(resp_a, resp_b):
        """Checks wether two responses share the same HTTP status code."""

        # print(f"[DEBUG] Comparing status codes: {resp_a.status_code} vs {resp_b.status_code}")

        # return resp_a.status_code < 400 and resp_b.status_code < 400 
        
        return resp_a.status_code == resp_b.status_code     # Keep as equality, auth comparisons break otherwise.

    @staticmethod
    def compare_body_length(resp_a, resp_b, threshold=0.1):
        """Compares response body sizes, using a relative threshold to account for dynamic content e.g., timestamps,
        CSRF tokens, or per-request UUIDs."""

        len_a = len(resp_a.content)
        len_b = len(resp_b.content)

        # print(f"[DEBUG] Body lengths -> A: {len_a}, B: {len_b}")

        # If both are empty, treat as equivallent.
        if len_a == 0 and len_b == 0:
            return True

        # If only one is empty, then they are different.
        if len_a == 0 or len_b == 0:
            return False

        # Calculates the relative difference ratio.
        ratio = abs(len_a - len_b) / max(len_a, len_b)

        # print(f"[DEBUG] Relative body difference ratio: {ratio}")
        return ratio <= threshold

    @staticmethod
    def compare_json_keys(json_a, json_b):
        """Recursively extracts all JSON keys using dotted notation for nested keys from both objects, and returns a structural diff
        showing which keys are unique to each and which are shared."""

        def extract_keys(obj, prefix=""):
            keys = set()

            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Build the dotted path for nested keys e.g., `user.email`.
                    full_key = f"{prefix}.{k}" if prefix else k

                    keys.add(full_key)
                    keys.update(extract_keys(v, full_key))

                    # print(f"[DEBUG] Extracted key: {full_key}")

            # Lists dont get own path level, otherwise array heavy APIs become unreadable in the reports.
            elif isinstance(obj, list):
                # Lists are traversed but do not add their own key level.
                for item in obj:
                    keys.update(extract_keys(item, prefix))

            return keys

        keys_a = extract_keys(json_a)
        keys_b = extract_keys(json_b)

        # print(f"[DEBUG] Shared keys count: {len(keys_a & keys_b)}")

        # Return a structure difference of key presence.
        return {
            "keys_only_in_a": keys_a - keys_b,
            "keys_only_in_b": keys_b - keys_a,
            "shared_keys": keys_a & keys_b,
        }

    @staticmethod
    def compare_body_text(body_a, body_b):
        """Calculates the textual similarity rati, between two response bodies, using `difflib.SequenceMatcher`."""

        # print("[DEBUG] Running SequenceMatcher similarity comparison.")

        return difflib.SequenceMatcher(None, body_a, body_b).ratio()

    @staticmethod
    def extract_sensitive_fields(json_body, patterns=None):
        """Recursively walks through a parsed JSON structure, and returns all key-value pairs
        whose key matches any of the provided sensitive field name patterns."""

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

        # custom_patterns = ["apikey", "jwt"]

        def walk(obj):
            # Recursively traverses JSON to locate matching keys.
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Case-insensitive regex match against known sensitive patterns.
                    if any(
                        # Catches previously encountered variations like `user_email`, or `accountPAssword`.
                        re.search(pattern, k, re.IGNORECASE) for pattern in patterns
                    ):
                        found[k] = v

                        # print(f"[DEBUG] Sensitive field match found: {k}")

                    walk(v)

            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(json_body)

        # print(f"[DEBUG] Total sensitive fields found: {len(found)}")
        return found

    def is_data_leak(self, resp_a_body, resp_b_body, role_a_identifier=None):
        """Attempts to detect data leakages between two responses by checking whether a known identifier from role A appears in role B's response,
        and by comparing sensitive fields that were extracted from both parsed JSON bodys."""

        if hasattr(resp_a_body, "text"):        # TBL - request.Response objects and raw strings mixing ttogether.
            resp_a_body = resp_a_body.text
        if hasattr(resp_b_body, "text"):
            resp_b_body = resp_b_body.text

        # print("[DEBUG] Starting leak detection checks.")

        # Tries to parse both bodies as JSON to allow for a structured comparison.
        try:
            json_a = json.loads(resp_a_body)

            # print("[DEBUG] Parsed response A as JSON.")

        except (json.JSONDecodeError, TypeError):
            json_a = None

            # print("[DEBUG] Failed to parse response A JSON.")

        try:
            json_b = json.loads(resp_b_body)

            # print("[DEBUG] Parsed response B as JSON.")

        except (json.JSONDecodeError, TypeError):
            json_b = None

            # failed_json = "{invalid_json}"

        """Fast-path detection where if a known identifier from Role A appears in Role B's response
        this is a strong identifier of a leak."""

        if role_a_identifier and role_a_identifier in resp_b_body:
            reason = f"Role A identifier '{role_a_identifier}' found in role B response body."
            logger.warning(reason)

            # logger.debug(f"Leak reason triggered: {reason}")

            return True, reason

        # If both responses are valid JSON, compare sensitive fields.
        if json_a and json_b:
            fields_a = self.extract_sensitive_fields(json_a)
            fields_b = self.extract_sensitive_fields(json_b)

            # Identifies fields that exist in both responses with identical values.
            # Matching both field name and value cuts down a lot of FP in JSON reports. 
            leaked = {
                k: v for k, v in fields_a.items() if k in fields_b and fields_b[k] == v
            }

            # print(f"[DEBUG] Potential leaked fields: {list(leaked.keys())}")

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
        to return HTTP 200."""

        denial_strings = [
            "access denied",
            "forbidden",
            "unauthorised",
            "unauthorized",
            "not allowed",
            "login required",
            "please log in",
        ]

        # print(f"[DEBUG] Checking access decision for status: {response.status_code}")

        # Only HTTP 200 responses are considered potentially valid.
        if response.status_code != 200:
            return False

        body_lower = response.text.lower()

        # Checks for common denial phrases in the response bodies.
        if any(phrase in body_lower for phrase in denial_strings):

            # print("[DEBUG] Denial phrase detected in response body.")
            return False

        # Ensures that the response has enough content to be meaningful.
        if len(response.content) < self.MIN_CONTENT_LENGTH:

            # print("[DEBUG] Response body too small to count as valid access.")
            return False

        return True

    def generate_diff_report(self, resp_a, resp_b):
        """Generates a human-raedable comparison report, between two responses, including status match, body length comparison, similarity
        ratio, and a unified diff of the first 2000 chasracters of each body."""

        # Limits body size to avoid excessive outputs in reports.
        body_a = resp_a.text[:2000]     # Full HTML responses completely destroyed readability.
        body_b = resp_b.text[:2000]

        status_match = self.compare_status(resp_a, resp_b)
        length_match = self.compare_body_length(resp_a, resp_b)
        similarity = self.compare_body_text(body_a, body_b)

        # print(f"[DEBUG] Similarity score generated: {similarity}")

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

        # failed_diff = difflib.ndiff(body_a.splitlines(), body_b.splitlines())

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

        # print("[DEBUG] Diff report generated successfully.")

        return report