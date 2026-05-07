"""
`match_findings.py`
Compares the scanner's JSON report output, and the filtered ZAP JSON export, against the manually verified GT (GT) files, for JS + DVWA.
PRoduces per-tool true positive, false negative, and false positive counts as a JSON file to `evaluation/raw_counts.json`, and prints a summary
to the console. These raw counts feed directly into the metric calculations.
"""
import argparse
import json
import os
import re
import sys

from scanner.core.logger import get_logger

logger = get_logger(__name__)

""" Maps each `scanner_module` value used in the GT JSON files, to the `vuln_type` keyword substrings emittted
by the corresponding scanner module. A finding matches teh GT entry, when its `vuln_type` contains any keyword from 
this mapping."""

MODULE_VULN_TYPE_MAP = {
    # `horizontal_auth.py` produces IDOR, and BOLA, findings for both read, and write cross-role substitutiton.
    "horizontal_auth": [
        "IDOR/BOLA",
        "Horizontal Privilege Escalation", 
    ],
    # `vertical_auth.py` produces escalation findings, when a non-admin session reaches an admin-only endpoint.
    "vertical_auth": [ 
        "Vertical Privilege Escalation",
        "Unauthenticated Access to Admin Endpoint",
    ],
    # `session_termination.py` produces findings, when a JWT, or session cookie, remains valid post logout.
    "session_termination": [ 
        "Session Not Invalidated on Logout", 
        "Expired JWT Accepted", 
        "JWT Without Expiry",
    ],
    # `session_fixation.py`produces a finding when the same JWT is re-issued on lre-login, or when PHPSESSID is not rotated.
    "session_fixation": [
        "JWT Token Reuse",
        "Session Fixation",
    ],
    # `rate_limit_detector.py` produces a  ffinding for every endpoint, that returns no 429 responses across all three tiers.
    "rate_limit_detector": [ 
        "Missing Rate Limiting",
    ],
    # `rate_limit_bypass.py` produces one finding per bypass technique, that suceeds against a tested endpoint.
    "rate_limit_bypass": [ 
        "Rate Limit Bypass",
    ],
    # `workflow_bypass.py` produces findings for step-skio, out of order, cross-session, and unauthenticated replay bypasses.
    "workflow_bypass": [
        "Workflow Bypass",
    ],
    # `unauth_access.py` Produces findings for unauthenticated endpoint access, and wordlist-driven forced browsing hits.
    "unauth_access": [ 
        "Authentication Bypass",
        "Forced Browsing",
    ],
    # `CSRFExtractor` in `csrf.py` is a utility class that doesn't produce findings. 
    # Entries with `scanner_module` "csrf" will always produce a false negative.
    "csrf": [],
}

# Maps ZAP alert names, and keywords to the GT `categorry` values, used in the GT JSON files.
# Entries are substring matched, case insensitively, against the ZAP alert `name` field.
ZAP_CATEGORY_MAP = {
    # Access control keywords cover ZAP alerts for path traversal, directory browsing, and IDOR-adjacent findings.
    "broken_access_control": [
        "access control",
        "path traversal",
        "idor",
        "broken access",
        "directory browsing",
    ],
    # Authentication keywords cover session fixation, CSRF, and weak credential alerts from ZAP.
    "broken_authentication": [
        "authentication",
        "csrf",
        "anti-csrf",
        "session fixation",
        "session token",
        "weak password",
        "password",
    ],
    # Security misconfig keywords cover ZAP alerts for missing rate limiting, and server information leakage. 
    "security_misconfiguration": [
        "rate limit",
        "brute force",
        "missing",
        "absence of",
        "server leaks",
    ],
    # Workflow keywords are unlikely to appear in ZAP results, as ZAP has no business logic awareness.
    "workflow_manipulation": [
        "business logic",
        "workflow",
    ],
}

# Modules where endpoint matching is skipped entirely during ground truth matching.
# `session_termination.py` logs findings at the base target URL rather than the specific logout
# endpoint, because session validity is tested target-wide, not per-route.
# `session_fixation.py` on DVWA logs at the login endpoint, not at the specific vulnerability
# module path defined in the ground truth (e.g. `/vulnerabilities/weak_id/`).
ENDPOINT_SKIP_MODULES = {"session_termination", "session_fixation"}


def _normalise_endpoint(endpoint_str, base_url=""):
    """ Strips `base_url` prefixes, and trailing slashes, from `endpoint_str` andd replaces numeric path segments, and `{id}`
    placeholders with a wildcard token, for fuzzy matching. Returns a normalised path string for comparison."""

    # Removes the base URL prefix, so that absolute URLs are reduced to their path components. 
    if base_url and endpoint_str.startswith(base_url):
        endpoint_str = endpoint_str[len(base_url):]
    
    # Strips trailing slashes, and converts the path to lowercase for case-insensitive matching.
    endpoint_str = endpoint_str.rstrip("/").lower()

    # Replaces numeric segments, and curly brace placeholders, with a wildcard token.
    # Ensures that `/rest/basket/1`, and `/rest/basket/{id}` are treated as equivalent.
    endpoint_str = re.sub(r"/\d+", "/{id}", endpoint_str)
    endpoint_str = re.sub(r"\{[^}]+\}", "{id}", endpoint_str)

    return endpoint_str


def _endpoints_match(gt_endpoint, finding_endpoint, base_url=""):
    """Returns 'True' when the normalised `gt_endpoint`, matches the normalised `finding_endpoint`.
    Uses `_normalise_endpoint` to strip base URLs, numeric segments, and placeholder tokens
    prior to comparing."""

    norm_gt = _normalise_endpoint(gt_endpoint, base_url="")
    norm_finding = _normalise_endpoint(finding_endpoint, base_url=base_url)

    # Checks for an exact match post normalisation.
    if norm_gt == norm_finding:
        return True

    #Checks whether the normalised finding endpoint ends with the normalised GT path, to handle cases where the scanner records the full absolute URL.
    if norm_finding.endswith(norm_gt):
        return True

    # Checks whether the GT endpoint is a prefix of the finding endpoint, to handle parameterised paths where the scanner records additional query strings. 
    if norm_finding.startswith(norm_gt.rstrip("{id}").rstrip("/")):
        return True

    return False


def _vuln_type_matches_module(vuln_type_str, scanner_module):
    """Returns 'True' when `vuln_type_str` contains at least one keyword associated with
    `scanner_module`, in `MODULE_VULN_TYPE_MAP`. Returns 'False' for unknown modules, and
    the `csrf` module, which emits no findings."""

    # Retrieves the keyword list for the given module, returns empty list for unknowns.
    keywords = MODULE_VULN_TYPE_MAP.get(scanner_module, [])

    # Empty keyword list means the module never produces findings, so the entry is always unmatched.
    if not keywords:
        return False

    # Checks whether any keyword appears as a substring in the `vuln_type` string.
    for keyword in keywords:
        if keyword.lower() in vuln_type_str.lower():
            return True

    return False


def _match_scanner_to_ground_truth(gt_entries, scanner_findings, base_url=""):
    """Iterates through the GT entries, and scanner findings to produce true positive, false negative,
    and false positive classifications. Returns a dictionary with the keys `true_positives`,
    `false_negatives`, `false_positives`, and `matched_gt_ids`."""

    #Tracks the GT IDs that were successfully matched to a scanner finding.
    matched_gt_ids = set()
    # Tracks the finding list indices that were used by a GT match, to identify false positives later.
    matched_finding_indices = set()

    # Iterates through the GT entries, and searches scanner findings for a matching endpoint and vuln type.
    for gt_entry in gt_entries:
        gt_id = gt_entry.get("id", "unknown")
        gt_endpoint = gt_entry.get("endpoint", "")
        gt_module = gt_entry.get("scanner_module", "")

        # Skips entries marked out of scope.
        if not gt_entry.get("in_scope", True):
            continue

        # Searches through all the scanner findings for one that matches both the endpoint, and the expected module type.
        for idx, finding in enumerate(scanner_findings):
            finding_endpoint = finding.get("endpoint", "")
            finding_vuln_type = finding.get("vuln_type", "")

            # Skips the endpoint check for session_termination and session_fixation modules.
            # `session_termination.py` logs at the base target URL rather than the specific logout endpoint.
            # `session_fixation.py` on DVWA logs at the login page, not the ground truth vulnerability module path.
            if gt_module in ENDPOINT_SKIP_MODULES:
                endpoint_ok = True
            else:
                endpoint_ok = _endpoints_match(gt_endpoint, finding_endpoint, base_url=base_url)

            module_ok = _vuln_type_matches_module(finding_vuln_type, gt_module)

            # Records a match, and stops searching further findings for this GT entry.
            if endpoint_ok and module_ok:
                matched_gt_ids.add(gt_id)
                matched_finding_indices.add(idx)
                break

        # Secondary pass for `rate_limit_detector` GT entries: accepts a `rate_limit_bypass` finding
        # at the same endpoint as a true positive. This handles the case where `rate_limit_detector.py`
        # correctly confirmed that rate limiting exists on the endpoint and did not emit a missing rate
        # limit finding, but `rate_limit_bypass.py` then confirmed the limit is circumventable. The bypass
        # finding is a stronger positive result and still confirms the endpoint was correctly identified as
        # a rate limiting target. Applied only when the primary pass produced no match for this GT entry.
        if gt_id not in matched_gt_ids and gt_module == "rate_limit_detector":
            for idx, finding in enumerate(scanner_findings):
                if idx in matched_finding_indices:
                    continue
                finding_endpoint = finding.get("endpoint", "")
                finding_vuln_type = finding.get("vuln_type", "")
                endpoint_ok = _endpoints_match(gt_endpoint, finding_endpoint, base_url=base_url)
                bypass_ok = _vuln_type_matches_module(finding_vuln_type, "rate_limit_bypass")
                if endpoint_ok and bypass_ok:
                    matched_gt_ids.add(gt_id)
                    matched_finding_indices.add(idx)
                    break

        # Tertiary pass for `rate_limit_bypass` GT entries: claims ALL bypass findings at the same
        # endpoint (not just the first), since multiple bypass techniques on one endpoint are all
        # equally valid confirmations and should not generate separate false positives.
        if gt_module == "rate_limit_bypass" and gt_id in matched_gt_ids:
            for idx, finding in enumerate(scanner_findings):
                if idx in matched_finding_indices:
                    continue
                finding_endpoint = finding.get("endpoint", "")
                finding_vuln_type = finding.get("vuln_type", "")
                endpoint_ok = _endpoints_match(gt_endpoint, finding_endpoint, base_url=base_url)
                module_ok = _vuln_type_matches_module(finding_vuln_type, "rate_limit_bypass")
                if endpoint_ok and module_ok:
                    matched_finding_indices.add(idx)

    true_positives = []
    false_negatives = []

    # Classifies each in-scope GT entry as a true positive or a false negative
    for gt_entry in gt_entries:
        if not gt_entry.get("in_scope", True):
            continue
        if gt_entry.get("id") in matched_gt_ids:
            true_positives.append(gt_entry.get("id"))
        else:
            # Records unmatched GT entries as false negatives, meaning the scanner missed them. 
            false_negatives.append(gt_entry.get("id"))

    false_positives = []

    # Issue 7: Deduplicate FPs by (normalised endpoint, vuln_type) so that the same logical
    # finding emitted twice — e.g. by both `vertical_auth` (Vertical Privilege Escalation)
    # and `unauth_access` (Authentication Bypass) on the same admin URL, or by query-string
    # variants of the same DVWA page — is only counted once toward the false positive total.
    seen_fp_keys = set()

    # Builds a key set from findings that were successfully matched to a GT entry, so that
    # duplicate findings with the same endpoint and vuln_type do not count as false positives.
    matched_finding_keys = set()
    for idx in matched_finding_indices:
        f = scanner_findings[idx]
        ep_m = _normalise_endpoint(f.get("endpoint", ""), base_url=base_url)
        # Normalises Rate Limit Bypass variants so that all bypass techniques at the same endpoint
        # share a single key, preventing each bypass technique from generating its own FP entry.
        vt_m = f.get("vuln_type", "")
        if "Rate Limit Bypass" in vt_m:
            vt_m = "Rate Limit Bypass"
        matched_finding_keys.add((ep_m, vt_m))

    # Builds a set of finding indices that match out-of-scope (in_scope:false) GT entries.
    # These are confirmed detections that are intentionally excluded from the evaluation scope
    # (e.g. DVWA at Low security genuinely serves every page without authentication), so they
    # should not inflate the false positive count.
    out_of_scope_matched = set()
    for gt_entry in gt_entries:
        if gt_entry.get("in_scope", True):
            continue
        gt_endpoint_oos = gt_entry.get("endpoint", "")
        gt_module_oos = gt_entry.get("scanner_module", "")
        for idx, finding in enumerate(scanner_findings):
            if idx in matched_finding_indices or idx in out_of_scope_matched:
                continue
            finding_endpoint = finding.get("endpoint", "")
            finding_vuln_type = finding.get("vuln_type", "")
            if gt_module_oos in ENDPOINT_SKIP_MODULES:
                ep_ok = True
            else:
                ep_ok = _endpoints_match(gt_endpoint_oos, finding_endpoint, base_url=base_url)
            mod_ok = _vuln_type_matches_module(finding_vuln_type, gt_module_oos)
            if ep_ok and mod_ok:
                out_of_scope_matched.add(idx)

    # Classifies each scanner finding not matched to any GT entry as a false positive.
    for idx, finding in enumerate(scanner_findings):
        if idx not in matched_finding_indices:
            # Skips the Scanner Error findings generated by module crash boundaries in `main.py`.
            if finding.get("vuln_type") == "Scanner Error":
                continue

            # Skips findings that match an out-of-scope GT entry.
            if idx in out_of_scope_matched:
                continue

            # Builds a deduplication key from the normalised endpoint and the vuln_type string.
            ep_norm = _normalise_endpoint(finding.get("endpoint", ""), base_url=base_url)
            vtype = finding.get("vuln_type", "")
            # Normalises Rate Limit Bypass variants so all bypass techniques at the same endpoint
            # share one key, collapsing three bypass FPs per endpoint to at most one.
            if "Rate Limit Bypass" in vtype:
                vtype = "Rate Limit Bypass"
            fp_key = (ep_norm, vtype)

            # Skips findings whose key was already consumed by a matched (TP) finding, preventing
            # duplicate findings of the same type at the same endpoint from counting as FPs.
            if fp_key in matched_finding_keys:
                continue

            if fp_key in seen_fp_keys:
                continue
            seen_fp_keys.add(fp_key)

            # Appends a summary of the unmatched finding for reporting, and manual review.
            false_positives.append({
                "vuln_type": finding.get("vuln_type", "unknown"),
                "endpoint": finding.get("endpoint", "unknown"),
                "method": finding.get("method", "unknown"),
            })

    return {
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "tp_count": len(true_positives),
        "fn_count": len(false_negatives),
        "fp_count": len(false_positives),
    }


def _get_zap_category(alert_name):
    """Returns the ground truth `category` string that best matches the ZAP `alert_name`, or
    'None' if no mapping is found in `ZAP_CATEGORY_MAP`."""

    alert_lower = alert_name.lower()

    # Iterates through every category and its associated keywords, returning on the first match.
    for category, keywords in ZAP_CATEGORY_MAP.items():
        for keyword in keywords:
            if keyword in alert_lower:
                return category

    # Returns 'None' when no category keyword matches, marking the alert as outside of the comparison scope.
    return None


def _match_zap_to_ground_truth(gt_entries, zap_path, base_url=""):
    """Parses the ZAP filtered export at `zap_path`, and matches its alerts against the ground truth
    entries. Returns the same TP/FN/FP structure as `_match_scanner_to_ground_truth`, or an error
    dictionary if the file cannot be parsed."""

    # Error result immediately, if the ZAP export file does not exist.
    if not os.path.isfile(zap_path):
        logger.warning("ZAP results file not found at %s.", zap_path)
        return {"error": f"ZAP results file not found: {zap_path}"}

    with open(zap_path, "r", encoding="utf-8") as zap_file:
        try:
            zap_data = json.load(zap_file)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse ZAP JSON at %s: %s", zap_path, exc)
            return {"error": f"Invalid JSON in ZAP file: {exc}"}

    # Flattens the ZAP site, and alerts the structure into a normalised list of alert dictionaries.
    # ZAP exports nest alerts under a site array, with each alert containing an instances sub-array.
    zap_alerts = []

    # Iterates through the xZAP sites, and their alert lists, normalising each alert to a flat dictionary.
    for site in zap_data.get("site", []):
        for alert in site.get("alerts", []):
            alert_name = alert.get("name", alert.get("alert", ""))
            # Iterates thgrough the instances to extract individual affected URIs and methods
            for instance in alert.get("instances", [{}]):
                zap_alerts.append({
                    "name": alert_name,
                    "uri": instance.get("uri", ""),
                    "method": instance.get("method", "GET"),
                    "riskcode": alert.get("riskcode", "0"),
                    #Maps the alert name to a ground truth category for cross-tool comparison.
                    "category": _get_zap_category(alert_name),
                })

    matched_gt_ids = set()
    matched_alert_indices = set()

    # Iterates thourhg the ground truth entries, and searches the ZAP alerts for matching endpoint + category.
    for gt_entry in gt_entries:
        gt_id = gt_entry.get("id", "unknown")
        gt_endpoint = gt_entry.get("endpoint", "")
        gt_category = gt_entry.get("category", "")

        if not gt_entry.get("in_scope", True):
            continue

        for idx, alert in enumerate(zap_alerts):
            endpoint_ok = _endpoints_match(gt_endpoint, alert.get("uri", ""), base_url=base_url)
            # Compares the mapped ZAP category against the ground truth category string directly.
            category_ok = alert.get("category") == gt_category

            if endpoint_ok and category_ok:
                matched_gt_ids.add(gt_id)
                matched_alert_indices.add(idx)
                break

    true_positives = []
    false_negatives = []

    # Classifies each in-scope ground truth entry as a true positive, or a false negative.
    for gt_entry in gt_entries:
        if not gt_entry.get("in_scope", True):
            continue
        if gt_entry.get("id") in matched_gt_ids:
            true_positives.append(gt_entry.get("id"))
        else:
            false_negatives.append(gt_entry.get("id"))

    false_positives = []

    # Classifies each ZAP alert not matched to any ground truth entry as a false positive.
    for idx, alert in enumerate(zap_alerts):
        if idx not in matched_alert_indices:
            false_positives.append({
                "name": alert.get("name", "unknown"),
                "uri": alert.get("uri", "unknown"),
                "method": alert.get("method", "unknown"),
            })

    return {
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "tp_count": len(true_positives),
        "fn_count": len(false_negatives),
        "fp_count": len(false_positives),
    }


def _load_scanner_report(report_path):
    """Loads a scanner JSON report from `report_path`, and returns the findings list + metadata
    dictionary as a two-element tuple. Exits with an error message if the file cannot be parsed."""

    with open(report_path, "r", encoding="utf-8") as report_file:
        try:
            data = json.load(report_file)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse scanner report at %s: %s", report_path, exc)
            sys.exit(1)

    # Returns the findings, and metadata, as separate values so that callers can access timing, and request counts.
    return data.get("findings", []), data.get("metadata", {})


def _load_ground_truth(gt_path):
    """Loads a ground truth JSON file from `gt_path`, and returns the entries list + metadata
    dictionary as a two-element tuple. Exits with an error message if the file cannot be parsed."""

    with open(gt_path, "r", encoding="utf-8") as gt_file:
        try:
            data = json.load(gt_file)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse ground truth file at %s: %s", gt_path, exc)
            sys.exit(1)

    # Returns entries, and metadata separately, so that callers can read the base URL from the metadata block.
    return data.get("entries", []), data.get("metadata", {})


def _print_results_table(tool_name, results, gt_entries):
    """Prints a console summary for `tool_name` showing TP, FN, and FP counts,
    the IDs of true positive ground truth entries, false negative ground truth entries,
    and a list of false positive findings."""

    print(f"\n{'=' * 60}")
    print(f"  {tool_name}")
    print(f"{'=' * 60}")
    print(f"  True Positives  (TP): {results.get('tp_count', 0)}")
    print(f"  False Negatives (FN): {results.get('fn_count', 0)}")
    print(f"  False Positives (FP): {results.get('fp_count', 0)}")
    print(f"{'=' * 60}")

    # Prints the IDs of the ground truth entries confirmed as true positives.
    if results.get("true_positives"):
        print("  Detected (TP):")
        for gt_id in results["true_positives"]:
            print(f"    + {gt_id}")

    # Prints the IDs of the ground truth entries not matched by any finding.
    if results.get("false_negatives"):
        print("  Missed (FN):")
        for gt_id in results["false_negatives"]:
            print(f"    - {gt_id}")

    # Prints a summary of each false positive finding, capped at 10 keeping outputs readable.
    if results.get("false_positives"):
        print(f"  False Positives ({results.get('fp_count', 0)}):")
        for fp in results["false_positives"][:10]:
            print(f"    ! {fp.get('vuln_type', fp.get('name', 'unknown'))} @ {fp.get('endpoint', fp.get('uri', 'unknown'))}")
        if results.get("fp_count", 0) > 10:
            print(f"    ... and {results.get('fp_count', 0) - 10} more (see raw_counts.json)")

    print()
    print()


def main():
    """Parses the CLI arguments, runs the ground truth matching for the scanner and ZAP, and writes
    the raw TP/FN/FP counts to `evaluation/raw_counts.json`."""

    # Constructs the CLI argument parser, for all required, and optional file path arguments.
    parser = argparse.ArgumentParser(
        description="Matches scanner and ZAP findings against ground truth JSON files to produce raw TP/FN/FP counts."
    )
    parser.add_argument(
        "--gt-juiceshop",
        required=True,
        help="Path to ground_truth_juiceshop.json.",
    )
    parser.add_argument(
        "--gt-dvwa",
        required=True,
        help="Path to ground_truth_dvwa.json.",
    )
    parser.add_argument(
        "--scanner-report-js",
        required=True,
        help="Path to the scanner JSON report produced against Juice Shop.",
    )
    parser.add_argument(
        "--scanner-report-dvwa",
        required=True,
        help="Path to the scanner JSON report produced against DVWA.",
    )
    parser.add_argument(
        "--zap-report",
        default=None,
        help="Path to the filtered ZAP JSON export (evaluation/zap_filtered_results.json).",
    )
    parser.add_argument(
        "--output",
        default="evaluation/raw_counts.json",
        help="Path to write the raw TP/FN/FP counts JSON output (default: evaluation/raw_counts.json).",
    )

    args = parser.parse_args()

    # Loads both the ground truth files, and both scanner report files prior to any matching beginning.
    gt_js_entries, gt_js_meta = _load_ground_truth(args.gt_juiceshop)
    gt_dvwa_entries, gt_dvwa_meta = _load_ground_truth(args.gt_dvwa)
    js_findings, js_meta = _load_scanner_report(args.scanner_report_js)
    dvwa_findings, dvwa_meta = _load_scanner_report(args.scanner_report_dvwa)

    # Reads the base URLs from the ground truth metadata, so that endpoint normalisation strips the correct prefix.
    js_base_url = gt_js_meta.get("base_url", "http://localhost:3000")
    dvwa_base_url = gt_dvwa_meta.get("base_url", "http://localhost:8080")

    # Runs the scanner matching pass for Juice Shop and DVWA separately.
    scanner_js_results = _match_scanner_to_ground_truth(gt_js_entries, js_findings, base_url=js_base_url)
    scanner_dvwa_results = _match_scanner_to_ground_truth(gt_dvwa_entries, dvwa_findings, base_url=dvwa_base_url)

    # Combines Juice Shop and DVWA scanner counts into a single combined result, for overall metrics.
    # Duration, and request count, are summed across both targets to reflect total scanner effort.
    scanner_combined = {
        "true_positives": scanner_js_results["true_positives"] + scanner_dvwa_results["true_positives"],
        "false_negatives": scanner_js_results["false_negatives"] + scanner_dvwa_results["false_negatives"],
        "false_positives": scanner_js_results["false_positives"] + scanner_dvwa_results["false_positives"],
        "tp_count": scanner_js_results["tp_count"] + scanner_dvwa_results["tp_count"],
        "fn_count": scanner_js_results["fn_count"] + scanner_dvwa_results["fn_count"],
        "fp_count": scanner_js_results["fp_count"] + scanner_dvwa_results["fp_count"],
        "duration_seconds": js_meta.get("duration_seconds", 0) + dvwa_meta.get("duration_seconds", 0),
        "total_requests": js_meta.get("total_requests", 0) + dvwa_meta.get("total_requests", 0),
    }

    # Runs the ZAP matching pass if a ZAP export path was provided.
    zap_results = None
    if args.zap_report:
        # Runs ZAP matching against Juice Shop only, as ZAP was already run against Juice Shop.
        zap_results = _match_zap_to_ground_truth(gt_js_entries, args.zap_report, base_url=js_base_url)

    # Prints console summaries for the scanner, and ZAP results.
    _print_results_table("Scanner vs Juice Shop Ground Truth", scanner_js_results, gt_js_entries)
    _print_results_table("Scanner vs DVWA Ground Truth", scanner_dvwa_results, gt_dvwa_entries)
    _print_results_table("Scanner Combined (Both Targets)", scanner_combined, gt_js_entries + gt_dvwa_entries)

    #Prints the ZAP summary, but only when a valid ZAP report was parsed without errors.
    if zap_results and "error" not in zap_results:
        _print_results_table("ZAP vs Juice Shop Ground Truth", zap_results, gt_js_entries)

    # Assembles the output dictionary, for saving to `evaluation/raw_counts.json`.
    output_data = {
        "scanner": {
            "juiceshop": scanner_js_results,
            "dvwa": scanner_dvwa_results,
            "combined": scanner_combined,
        }
    }

    # Appends the ZAP results to the output dictionary, if ZAP matching was performed
    if zap_results:
        output_data["zap"] = {"juiceshop": zap_results}

    # Creates the evaluation output directory if it does not already exist.
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as out_file:
        # Writes with two-space indentation, so that the file is readable during manual review.
        json.dump(output_data, out_file, indent=2)

    logger.info("Raw counts written to %s.", args.output)
    print(f"Raw counts saved to: {args.output}")
    print("These counts are used directly by Phase 11.3 metric calculations.")


if __name__ == "__main__":
    main()