"""
`html_report.py`

Generates a self-contained HTML report for a completed scanner run. Loads the Jinja2 template
for `scanner/templates/report.html`, calculates severity counts from `ScanResult.vulnerabilities`,
renders the template with scan context, and writes the output to a caller-specified file path.
"""

import os
import types
import datetime as _dt
import jinja2

from scanner.core.logger import get_logger

# print("loading html report generator")

# Gets a named logger for this module using the shared `get_logger` helper.
logger = get_logger(__name__)


class HTMLReportGenerator:
    """Renders `ScanResult` data and evidence into a self-contained HTML report using Jinja2."""

    # Version string injected into the report footer.
    SCANNER_VERSION = "1.0.0"

    # Ordered severity levels used in the report charts.
    SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

    def __init__(self, scan_result, evidence_store):
        """Stores the scan result and evidence store for report rendering."""

        # logger.debug("initialising html report generator")

        # `scan_result` holds discovered endpoints, vulnerabilities, and timing metadata.
        self.scan_result = scan_result

        # `evidence_store` contains evidence entries keyed by evidence ID.
        self.evidence_store = evidence_store

    def _compute_severity_counts(self):
        """Counts findings grouped by severity level."""

        # counts = {}

        # Initialises all severity levels to zero so empty levels still appear in charts.
        counts = {level: 0 for level in self.SEVERITY_LEVELS}       # Formatting not great - fix.

        # Increments counts for each vulnerability severity.
        for vuln in self.scan_result.vulnerabilities:

            # print(vuln.severity)

            # Normalises casing before matching against severity keys.
            # Failed on lowercase severities from older modules.
            severity = vuln.severity.capitalize()

            if severity in counts:
                counts[severity] += 1

        return counts

    def generate(self, output_path):
        """Renders the HTML template and writes the final report to disk."""

        # logger.info("starting html report generation")

        # Resolves the absolute path to `scanner/templates/`.
        templates_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "templates",
        )

        # templates_dir = "./templates"

        # Normalises the path before passing it into `FileSystemLoader`.
        templates_dir = os.path.normpath(templates_dir)

        # `autoescape` is enabled to avoid rendering raw HTML from findings/evidence.
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(templates_dir),
            autoescape=jinja2.select_autoescape(["html"]),
        )

        # print(templates_dir)

        # Loads the report template from `scanner/templates/`.
        template = env.get_template("report.html")

        # Builds the severity summary counts used by the charts.
        severity_counts = self._compute_severity_counts()

        # Parses ISO timestamps back into datetime objects for `.strftime()` support.
        parsed_start = _dt.datetime.fromisoformat(self.scan_result.scan_start)
        parsed_end = _dt.datetime.fromisoformat(self.scan_result.scan_end)

        # Wraps the dataclass in a namespace so timestamps can be swapped safely.
        scan_result_view = types.SimpleNamespace(**self.scan_result.to_dict())

        scan_result_view.scan_start = parsed_start
        scan_result_view.scan_end = parsed_end

        # print(scan_result_view)

        # Builds the full render context passed into the template.
        context = {
            "scan_result": scan_result_view,
            "severity_counts": severity_counts,
            "evidence_store": self.evidence_store,
            "scanner_version": self.SCANNER_VERSION,
        }

        # old context structure
        # context = {"scan_result": self.scan_result}

        # Renders the template into a final HTML string.
        rendered = template.render(**context)   # keep render separate - debugging inline not great.

        # Resolves the output path before writing.
        output_path = os.path.abspath(output_path)      # Bug to log - relative paths broke when running from  /evaluation.

        # Creates missing parent directories automatically.
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Writes the rendered HTML report using UTF-8 encoding.
        with open(output_path, "w", encoding="utf-8") as report_file:

            # logger.debug("writing html output")

            report_file.write(rendered)

        logger.info("HTML report written to %s", output_path)