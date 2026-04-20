"""
`main.py`

The top-level orchestrator for the full logic flaw scanner. Loads `ScanConfig`, constructs all the module 
instances, and runs the full scan pipeline in ordered sequence. Exposes a CLI via `argparse`. Each module step runs inside
its own error boundary, so that a single module crash does not discard any findings that were accumulated via earlier modules.
"""

import argparse
import datetime
import os
import sys
import traceback

from scanner.core.config import ScanConfig
from scanner.core.logger import setup_logger, get_logger
from scanner.core.http_client import HTTPClient
from scanner.core.session_manager import SessionManager
from scanner.core.scope import ScopeEnforcer
from scanner.core.comparator import ResponseComparator
from scanner.core.evidence import EvidenceCollector
from scanner.core.models import ScanResult, Vulnerability
from scanner.modules.crawler import Crawler
from scanner.modules.spa_crawler import SPACrawler
from scanner.modules.param_enumerator import ParameterEnumerator
from scanner.modules.unauth_access import UnauthAccessChecker
from scanner.modules.session_termination import SessionTerminationValidator
from scanner.modules.session_fixation import SessionFixationTester
from scanner.modules.horizontal_auth import HorizontalAuthTester
from scanner.modules.vertical_auth import VerticalAuthTester
from scanner.modules.workflow_recorder import WorkflowRecorder
from scanner.modules.workflow_bypass import WorkflowBypassTester
from scanner.modules.rate_limit_detector import RateLimitDetector
from scanner.modules.rate_limit_bypass import RateLimitBypassTester
from scanner.reports.html_report import HTMLReportGenerator
from scanner.reports.json_report import JSONReportGenerator

# Retrieves a named logger for the module, so that all orchestrator messages are prefixed with `main`.
logger = get_logger(__name__)

# Scanner version string.
SCANNER_VERSION = "1.0.0"


class Scanner:
    """ Loads config, constructs all module instances, and runs the full pipeline. Findings from all the modules
    are aggregated into a single `ScanResult`, and written to HTML, and JSON reports."""

    def __init__(self, config_path, output_dir="reports/", modules="all", verbose=False):
        """ Loads, and validates `ScanConfig`, configures the logger, and instantiates all the shared core components. 
        Parses the `modules` string into a set for `_should_run`, to query throughout the scan pipeline."""
        
        # Loads the YAML config file, via `ScanConfig`, and immediately validates required fields.
        self.config = ScanConfig(config_path)
        self.config.validate()

        # Sets DEBUG Logging when verbose is requested, otherwise it restricts console output to INFO.
        log_level = "DEBUG" if verbose else "INFO"
        setup_logger(log_level)

        # Creates the shared `HTTPClient` with the loaded config file, so that all modules use the same session pool.
        self.http_client = HTTPClient(self.config)
        # Creates `SessionManager`, which will later call `authenticate_all()` to populate per-role sessions.
        self.session_manager = SessionManager(self.config, self.http_client)
        # Creates `ScopeEnforcer`, to gate every URL against the configured target domain, and exclusion lists.
        self.scope_enforcer = ScopeEnforcer(self.config)
        # Creates a shared `ResponseComparator` instance, passed to all modules that perform cross-role diffing.
        self.comparator = ResponseComparator()
        # Creates the `EvidenceCollector`, that accumulates sanitised request/response pairs for the report output.
        self.evidence_collector = EvidenceCollector()

        # Stores the output directory path for use, when generating reports at the end of `run()`.
        self.output_dir = output_dir

        # Stores either the sentinel string "all", or a set of lowercase module name tokens, parsed from the CLI argument.
        if modules.strip().lower() == "all":
            self.modules = "all"
        else:
            self.modules = {m.strip().lower() for m in modules.split(",")}

    def _print_banner(self):
        """ Prints an ASCII banner showing the scanner name, version, target URL, number of configured credential sets, 
        and the UTC scan start timestamp."""

        # COunts the number of credential sets to display how many roles the scanner will authenticate. 
        credential_count = len(self.config.credentials) if self.config.credentials else 0
        # Formats the current UTC time as a readable string.
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Builds the full banner string, using f-string formatting with left-padded fields.
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║          Logic Flaw Scanner  v{SCANNER_VERSION}                          ║
║          Semi-Automated Web Vulnerability Discovery          ║
╠══════════════════════════════════════════════════════════════╣
║  Target   : {self.config.target_url:<49}║
║  Roles    : {credential_count:<49}║
║  Started  : {timestamp:<49}║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def _should_run(self, module_name):
        """ Returns 'True' when the module named `module_name` is included in the scan run, either because `self.modules` is set 
        to the sentinel value 'all', or because `module_name` is present in the parsed module set."""

        # Returns 'True' immediately, when all modules are selected, avoiding a set membership check.
        if self.modules == "all":
            return True
        # Checks whether the specific token, e.g., 'idor', or 'ratelimit', appears in the parsed set.
        return module_name in self.modules

    def run(self):
        """ Runs the full scan pipeline, executing authentication, crawling, parameter enumeration, authorisation testing, workflow
        bypass, and rate limiting modules in sequence. Each step is enclosed in an error boundary, so that a crash in one module 
        does not automatically discard the findings from all prior modules."""

        self._print_banner()

        # Records the UTC scan start time, before any modules run, so that the duration can be calculated at the end.
        scan_start = datetime.datetime.utcnow()
        # Initialises the master findings list that all modules append their `Vulnerability` objects into.
        all_findings = []
        # Tracks which module tokens were actually executed, written into `ScanResult.modules_run`.
        modules_run = []
        
        ## Authentication
        # Authenticates all configured roles before any module runs. Aborts if there are no sessions established.
        logger.info("Step: Authentication.")
        try:
            # Calls `authenticate_all()`, which dispatches to the correct auth handler per role, based on config auth type.
            auth_results = self.session_manager.authenticate_all()
            logger.info("Authentication results: %s", auth_results)

            # Treats an empty results dictionary as a fatal error, because all the subsequent modules require at least one session. 
            if not auth_results:
                logger.error("Authentication produced no sessions. Aborting scan.")
                sys.exit(1)
        except Exception:
            # Treats any unhandled exception during authentication as fatal, because all the modules depend on it.
            logger.error(
                "Authentication step raised an unhandled exception. Aborting scan.\n%s",
                traceback.format_exc(),
            )
            sys.exit(1)

        ## Scope setup
        # Fetches and parses `robots.txt`, to populate the scope enforcer's disallowed paths list.
        logger.info("Step: Scope setup.")

        # Only fetches `robots.txt`, if the YAML configuration has `robots_txt: true` under the scope block.
        if self.config.scope.get("robots_txt", False):
            try:
                # Populates `ScopeEnforcer.disallowed_paths`, so that all crawl, and probe, requests respect robots directives.
                self.scope_enforcer.fetch_robots_txt()
            except Exception:
                # Logs the failure but does not abort, since robots.txt is advisory, and not strictly required for scanning.
                logger.error(
                    "Scope setup raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )

        ## Static crawl.
        # Initialises endpoint, and form lists here, so that downstream modules always have defined containers - even if crawling is skipped.
        endpoints = []
        forms = []

        if self._should_run("crawl"):
            logger.info("Step: Static crawling.")
            modules_run.append("crawl")
            try:
                # Constructs `Crawler` with all four shared dependencies, so it can perform multi-role BFS crawling.
                crawler = Crawler(
                    self.config,
                    self.http_client,
                    self.session_manager,
                    self.scope_enforcer,
                )

                # Runs an unauthenticated pass first, then one breadth first pass per configured role, to populate `discovered_by_roles`.
                crawler.crawl_all_sessions()
                # Retrieves the deduplicated endpoint list, produced across all crawl passes.
                endpoints = crawler.get_endpoints()
                # Retrieves the form list for use by session, and CSRF modules later in the pipeline.
                forms = crawler.get_forms()

                logger.info(
                    "Static crawler discovered %d endpoints and %d forms.",
                    len(endpoints),
                    len(forms),
                )
            except Exception as exc:
                logger.error(
                    "Module `crawler.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                
                # Records a scanner error finding, so that the crash is visible in the final report, rather than getting unnoticeably lost.
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module crawler crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## SPA Crawl
        # Runs the Playwright SPA crawler against Juice Shop's Angular frontend, and merges any new endpoints.
        # Gated on both the 'crawl' module token, and the `handle_spa` flag in `crawl_config`, defaulting to 'True'.
        if self._should_run("crawl") and self.config.crawl_config.get("handle_spa", True):
            logger.info("Step: SPA crawling.")
            try:
                # Constructs `SPACrawler`, which uses Playwright Chromium to intercept XHR, and Fetch API calls.
                spa_crawler = SPACrawler(
                    self.config,
                    self.session_manager,
                    self.scope_enforcer,
                )
                # Launches the headless browser, and navigates Juice Shop's Angular routes, to capture any API calls.
                spa_crawler.crawl_with_browser()
                # Converts captured XHR, and Fetch requests into `Endpoint` objects.
                spa_endpoints = spa_crawler.get_api_endpoints()
                # Builds a lookup set of already known (method, url) pairs, to avoid duplicate entries.
                existing_keys = {(e.method, e.url) for e in endpoints}

                # Iterates SPA-discovered endpoints, and appends only those that are not already there in the static crawl results.
                for ep in spa_endpoints:
                    if (ep.method, ep.url) not in existing_keys:
                        endpoints.append(ep)
                        existing_keys.add((ep.method, ep.url))

                logger.info(
                    "SPA crawler added %d new endpoints. Total endpoints: %d.",
                    len(spa_endpoints),
                    len(endpoints),
                )
            except Exception as exc:
                logger.error(
                    "Module `spa_crawler.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module spa_crawler crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Parameter Enumeration.
        # Initialises both of the outputs here, so that `idor` module steps always receive the defined values, even if `params` is skipped.
        endpoint_params = {}
        parameters_found = 0

        if self._should_run("params"):
            logger.info("Step: Parameter enumeration.")
            modules_run.append("params")
            try:
                # Constructs `ParameterEnumerator`, which extracts URL query params, form fields, and JSON body keys.
                param_enumerator = ParameterEnumerator(
                    self.config,
                    self.http_client,
                    self.session_manager,
                )
                # Runs enumeration across the full endpoint list, including wordlist fuzzing for hidden parameters.
                param_enumerator.enumerate_all(endpoints)
                # Retrieves the (method, url) keyed parameter dictionary, for passing to `HorizontalAuthTester`.
                endpoint_params = param_enumerator.get_params()
                # Sums the parameter count across all endpoints for the `ScanResult` metrics field.
                parameters_found = sum(len(v) for v in endpoint_params.values())
                
                logger.info(
                    "Parameter enumeration found %d parameters across %d endpoints.",
                    parameters_found,
                    len(endpoint_params),
                )
            except Exception as exc:
                logger.error(
                    "Module `param_enumerator.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module param_enumerator crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Unauthenticated Access.
        # Tests every discovered endpoint for unauthenticated access, and performs wordlist-driven, forced browsing.
        if self._should_run("unauth"):
            logger.info("Step: Unauthenticated access and forced browsing.")
            modules_run.append("unauth")
            try:
                # Constructs `UnauthAccessChecker`, which compares bare-session responses against authenticated baselines.
                unauth_checker = UnauthAccessChecker(
                    self.config,
                    self.http_client,
                    self.session_manager,
                    self.comparator,
                )

                # Tests each crawled endpoint individually, for authentication bypass using `ResponseComparator`.
                unauth_checker.test_all(endpoints)
                # Checks `wordlists/common_paths.txt` entries, against the target to discover unlisted, unprotected resources.
                unauth_checker.test_forced_browsing()
                # Appends all High, and Medium findings from both test types, into the master list.
                all_findings.extend(unauth_checker.get_findings())

                logger.info(
                    "Unauthenticated access module produced %d finding(s).",
                    len(unauth_checker.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `unauth_access.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module unauth_access crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Session Testing.
        # Groups the session termination, and session fixation, under the same 'session' token, to keep CLI flags simple.
        if self._should_run("session"):

            # Tests for logout invalidation for all the configured roles, and the JWT expiry fallback for Juice Shop.
            logger.info("Step: Session termination testing.")
            modules_run.append("session")
            try:
                # Builds `SessionTerminationValidator`, which deep-copies pre-logout credentials, prior to testing.
                session_termination_validator = SessionTerminationValidator(
                    self.config,
                    self.http_client,
                    self.session_manager,
                )

                # Iterates through all the configured roles, and tests whether the server invalidates sessions on logout.
                session_termination_validator.test_all_roles()
                # Appends 'Medium' findings for non-invalidated sessions, and JWT specific findings, where applicable.
                all_findings.extend(session_termination_validator.get_findings())

                logger.info(
                    "Session termination module produced %d finding(s).",
                    len(session_termination_validator.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `session_termination.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module session_termination crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

            # Tests session fixation for DVWA using PHPSESSID, and token reuse for Juice Shop.
            logger.info("Step: Session fixation testing.")
            try:
                # Constructs `SessionFixationTester`, which compares session identifiers before, and after login.
                session_fixation_tester = SessionFixationTester(
                    self.config,
                    self.http_client,
                    self.session_manager,
                )
                # Runs both the PHPSESSID fixation check, for DVWA, and the JWT token reuse check for Juice Shop.
                session_fixation_tester.test_fixation()
                # Appends 'High' findings for confirmed fixation, and 'Medium' findings for token reuse.
                all_findings.extend(session_fixation_tester.get_findings())
                logger.info(
                    "Session fixation module produced %d finding(s).",
                    len(session_fixation_tester.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `session_fixation.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module session_fixation crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Horizontal Authorisation/IDOR
        # Tests IDOR read/write, and enumeration across all user-specific endpoints, using cross-role ID substitution.
        if self._should_run("idor"):
            logger.info("Step: Horizontal authorisation and IDOR testing.")
            modules_run.append("idor")
            try:
                # Constructs `HorizontalAuthTester`, with `ResponseComparator`, for body-level cross-role diffing.
                horizontal_auth_tester = HorizontalAuthTester(
                    self.config,
                    self.http_client,
                    self.session_manager,
                    self.comparator,
                )
                # Passes `endpoint_params` so that the tester can identify which endpoints have ID-type parameters.
                horizontal_auth_tester.test_all_idor(endpoints, endpoint_params)
                # Appends 'Critical' findings for confirmed IDOR read/write, and sequential ID enumeration.
                all_findings.extend(horizontal_auth_tester.get_findings())

                logger.info(
                    "Horizontal auth module produced %d finding(s).",
                    len(horizontal_auth_tester.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `horizontal_auth.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module horizontal_auth crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Vertical Authorisation.
        # Tests vertical privilege escalation, by replaying admin-pattern endpoints under `user_a`, and unauthenticated sessions.
        if self._should_run("vertical"):
            logger.info("Step: Vertical authorisation testing.")
            modules_run.append("vertical")
            try:
                # Constructs `VerticalAuthTester` which identifies admin endpoints, via URL pattern matching, and crawl metadata.
                vertical_auth_tester = VerticalAuthTester(
                    self.config,
                    self.http_client,
                    self.session_manager,
                    self.comparator,
                )
                # Iterates through all endpoints, filters to admin-pattern URLs, and replays each under `user_a`, and no-auth sessions.
                vertical_auth_tester.test_all_vertical(endpoints)
                # Appends 'Critical' findings for confirmed vertical escalation, and 'High' findings for unauthenticated admin access.
                all_findings.extend(vertical_auth_tester.get_findings())

                logger.info(
                    "Vertical auth module produced %d finding(s).",
                    len(vertical_auth_tester.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `vertical_auth.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module vertical_auth crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Workflow Bypass.
        # Records configured workflows, then tests each for step-skip, out of order, cross-session, and unauthenticated replay bypass.
        if self._should_run("workflow"):
            logger.info("Step: Workflow recording and bypass testing.")
            modules_run.append("workflow")
            try:
                # Constructs `WorkflowRecorder`, which reads in the workflow definitions from the YAML config, and replays each step.
                workflow_recorder = WorkflowRecorder(
                    self.config,
                    self.http_client,
                    self.session_manager,
                )

                # Replays all the workflows defined in `config.workflows`, substituting `{{token}}` placeholders between steps.
                workflow_recorder.record_from_config()

                # Constructs `WorkflowBypassTester`, and passes the populated `workflow_recorder` so that it has recorded step data.
                workflow_bypass_tester = WorkflowBypassTester(
                    self.config,
                    self.http_client,
                    self.session_manager,
                    workflow_recorder,
                    self.comparator,
                )
                # Runs all four bypass test types against every recorded workflow, plus the theoretical 2FA bypass - intended for the custom application.
                workflow_bypass_tester.test_all_workflows()
                # Appends 'High' findings for confirmed bypasses, and 'Critical' findings for unauthenticated replay success.
                all_findings.extend(workflow_bypass_tester.get_findings())

                logger.info(
                    "Workflow bypass module produced %d finding(s).",
                    len(workflow_bypass_tester.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `workflow_bypass.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module workflow_bypass crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Rate Limit Detection and Bypass.
        # Checks authentication endpoints for rate limiting, then runs six bypass techniques against tested endpoints.
        if self._should_run("ratelimit"):
            logger.info("Step: Rate limit detection.")
            modules_run.append("ratelimit")
            # Initialises `detection_results` here, so that the bypass tester always receives a defined dictionary, even if detection crashes.
            detection_results = {}
            try:
                # Constructs `RateLimitDetector`, which uses `janedoe@fake.local` as the test credential - avoids account lockout.
                rate_limit_detector = RateLimitDetector(
                    self.config,
                    self.http_client,
                )
                # Identifies critical auth endpoints from the crawl results, and runs tiered rate-limiting tests against each.
                rate_limit_detector.detect_all(endpoints)
                # Retrieves the per-endpoint detection results dictionary for passing directly to `RateLimitBypassTester`.
                detection_results = rate_limit_detector.detection_results
                # Appends 'Medium' findings for endpoints, where no rate limiting was detected at any tier.
                all_findings.extend(rate_limit_detector.get_findings())

                logger.info(
                    "Rate limit detection module produced %d finding(s) across %d endpoint(s).",
                    len(rate_limit_detector.get_findings()),
                    len(detection_results),
                )
            except Exception as exc:
                logger.error(
                    "Module `rate_limit_detector.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module rate_limit_detector crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

            # Runs XFF rotation, IP header variants, user agent rotation, URL case variation, method switching, and parameter pollution bypass techniques.
            logger.info("Step: Rate limit bypass testing.")
            try:
                # Constructs `RateLimitBypassTester` with the detection results so it can target the same endpoints.
                rate_limit_bypass_tester = RateLimitBypassTester(
                    self.config,
                    self.http_client,
                    detection_results,
                )
                # Runs all six bypass techniques against every endpoint in `detection_results`, regardless of rate-limited status.
                rate_limit_bypass_tester.test_all_endpoints(detection_results)
                # Appends 'High' findings for each bypass technique that succeeds in circumventing the detected limit.
                all_findings.extend(rate_limit_bypass_tester.get_findings())
                logger.info(
                    "Rate limit bypass module produced %d finding(s).",
                    len(rate_limit_bypass_tester.get_findings()),
                )
            except Exception as exc:
                logger.error(
                    "Module `rate_limit_bypass.py` raised an unhandled exception.\n%s",
                    traceback.format_exc(),
                )
                all_findings.append(
                    Vulnerability(
                        vuln_type="Scanner Error",
                        severity="Info",
                        description=f"Module rate_limit_bypass crashed: {str(exc)}",
                        endpoint="N/A",
                        method="N/A",
                        evidence={},
                    )
                )

        ## Builds ScanResult
        # Records the scan end time, after all modules have completed, or individually failed.
        scan_end = datetime.datetime.utcnow()

        # Calculates total elapsed seconds as a float, for the `ScanResult.scan_duration_seconds` field.
        duration = (scan_end - scan_start).total_seconds()

        # Constructs the `ScanResult` dataclass from all accumulated metrics, passed directly to both report generators.
        scan_result = ScanResult(
            target_url=self.config.target_url,
            scan_start=scan_start.isoformat(),
            scan_end=scan_end.isoformat(),
            scan_duration_seconds=duration,
            endpoints_discovered=len(endpoints),
            parameters_found=parameters_found,
            vulnerabilities=all_findings,
            total_requests=self.http_client.get_request_count(),
            modules_run=modules_run,
        )

        ## Report Generation.
        # Defensive programming - creates the output directory if it does not already exist before writing the reports.
        os.makedirs(self.output_dir, exist_ok=True)

        # Builds a timestamp string from the scan start time, to make each report filename unique per run.
        timestamp_str = scan_start.strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(self.output_dir, f"report_{timestamp_str}.html")
        json_path = os.path.join(self.output_dir, f"report_{timestamp_str}.json")

        # Generates both the HTML, and JSON reports, from the completed `ScanResult`, and `EvidenceCollector`.
        try:
            # Passes `evidence_collector` so that the HTML template can render collapsible request, and response panels.
            HTMLReportGenerator(scan_result, self.evidence_collector).generate(html_path)
            logger.info("HTML report written to %s.", html_path)
        except Exception:
            logger.error("HTML report generation failed.\n%s", traceback.format_exc())

        try:
            # Passes `evidence_collector`, so that the JSON report embeds the full sanitised evidence store.
            JSONReportGenerator(scan_result, self.evidence_collector).generate(json_path)
            logger.info("JSON report written to %s.", json_path)
        except Exception:
            logger.error("JSON report generation failed.\n%s", traceback.format_exc())

        ## Console Summary
        # Defines the severity display order from most critical, to least, matching `docs/severity_rubric.md`.
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        # Initialises a count dictionary, to keep track of how many findings fall into each respective severity tier.
        severity_counts = {}

        # Counts the findings per severity level, for the console summary table.
        for vuln in all_findings:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        print("\n" + "=" * 64)
        print("  SCAN COMPLETE")
        print("=" * 64)
        print(f"  Target          : {self.config.target_url}")
        print(f"  Duration        : {duration:.1f}s")
        print(f"  Endpoints found : {len(endpoints)}")
        print(f"  Requests sent   : {self.http_client.get_request_count()}")
        print(f"  Total findings  : {len(all_findings)}")
        print("-" * 64)

        # Iterates over each severity tier, in priority order, and prints the findings count for that tier.
        for sev in severity_order:
            count = severity_counts.get(sev, 0)
            # Skips tiers with zero findings to keep the summary table clean.
            if count > 0:
                print(f"  {sev:<12} : {count}")
        print("=" * 64)
        print(f"  Reports saved to: {self.output_dir}")
        print("=" * 64 + "\n")

        return scan_result


def main():
    """ Parses CLI arguments, builds a `Scanner` instance, and calls `scanner.run()`. 
    Handles `KeyboardInterrupt` with a clean exit message."""

    # Constructs the argument parser with a plain-text description shown in `--help` output.
    parser = argparse.ArgumentParser(
        description="Logic Flaw Scanner: semi-automated web vulnerability discovery tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Requires a path to the target YAML config, so the scanner knows which target, and credentials to use.
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the YAML configuration file for the target scan.",
    )
    # Accepts an optional output directory, defualting to 'reports/' in the working directory.
    parser.add_argument(
        "--output-dir",
        default="reports/",
        help="Directory to write HTML and JSON report files (default: reports/).",
    )
    # Accepts a comma-separated module list, so that individual test categories can be run in isolation.
    parser.add_argument(
        "--modules",
        default="all",
        help=(
            "Comma-separated list of modules to run. "
            "Options: crawl, params, unauth, session, idor, vertical, workflow, ratelimit. "
            "Defaults to 'all'."
        ),
    )
    # Switches the log level from INFO, to DEBUG, highlighting all `logger.debug` calls.
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG-level logging to the console and log file.",
    )
    # Overrides the proxy field from the YAML config at runtime, which is useful for routing traffic through Burp Suite.
    parser.add_argument(
        "--proxy",
        default=None,
        help="Override the config proxy setting (for example, http://127.0.0.1:8080 for Burp Suite).",
    )
    # Disables SSL certificate verifiaction at runtime, intended for lab environments using self-signed certificates.
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Override the config to disable SSL certificate verification.",
    )

    args = parser.parse_args()

    # Builds the `Scanner` instance, which triggers configuration loading, validation, and component building.
    scanner = Scanner(
        config_path=args.config,
        output_dir=args.output_dir,
        modules=args.modules,
        verbose=args.verbose,
    )

    # Overrides the proxy setting loaded from the YAML config file, if the CLI flag was provided.
    if args.proxy:
        # Mutates `_data` directly to propagate the override into all components that read `config.proxy`.
        scanner.config._data["proxy"] = args.proxy
        logger.info("Proxy overridden via CLI: %s.", args.proxy)

    # Disables SSL verification when the CLI flag is set, overriding the YAML configuration file value.
    if args.no_ssl_verify:
        # Mutates `_data` directly, so that `HTTPClient` picks up the override when building the session.
        scanner.config._data["verify_ssl"] = False
        logger.info("SSL verification disabled via CLI flag.")

    # Runs the full scan pipeline, and catches `KeyboardInterrupt`, so 'CTRL+C' exits without a traceback.
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C). Exiting cleanly.")
        sys.exit(0)

# Ensures that `main()` is only called when the file is directly executed, and not just imported as a module.
if __name__ == "__main__":
    main()