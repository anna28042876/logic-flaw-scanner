"""
`html_report.py`
Generates a self-contained HTML reporet for a completed scanner run. LOads the Jinja2 template 
for `scanner/templates/report.html`, calculates the severity counts from `ScanResult.vulnerabilities`,
renders the termplate with all scan context, and then writes the output to a caller-specified file path
"""

import os
import types
import datetime as _dt
import jinja2

from scanner.core.logger import get_logger

# Gets a named logger for this module, using the shared `get_logger` helper, from `logger.py`.
logger = get_logger(__name__)


class HTMLReportGenerator:
    """ Renders `ScanResult` data, and `EvidenceCollector` evidence into a sel-contained HTML report, via the 
    Jinja2 template `report.html`. It accepts a `scan_result`, and an `evidence_store` dictionary, on construction."""

    # Version string injected into the report footer, via the `scanner_version` template variable.
    SCANNER_VERSION = "1.0.0"

    # Ordered severity levels, used to build the bar chart in `report.html`.
    SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

    def __init__(self, scan_result, evidence_store):
        """ Stores the `ScanResult` instance, and the `evidence_Store` dictionary, produced by `EvidenceCollector`. 
        Both are passed directly into the Jinja2 render scope, by `generate`."""

        # `scan_result` holds all the discovered endpoints, vulnerabilities, and scan metadata.
        self.scan_result = scan_result
        # `evidence_store` is a dictionary, keyed by evidence ID, mapping to the dictionaries built by `EvidenceCOllector`.
        self.evidence_store = evidence_store

    def _compute_severity_counts(self):
        """ COunts `VUlnerability` objects in `scan_result.vulnerabilities`, which are grouped by severity string. 
        Then returns a dictionary keyed by each level  in `SEVERITY_LEVELS`, with integer counts, defaulting to zero."""
        
        # Initalises all five severity levels to zero, so that missing levels still appear in the bar chart.
        counts = {level: 0 for level in self.SEVERITY_LEVELS}

        # Increments the count for each severity level, found in the vulnerabilities list.
        for vuln in self.scan_result.vulnerabilities:
            # Capitalises the severity string to match the `SEVERITY_LEVELS` keys, regardless of source casing.
            severity = vuln.severity.capitalize()
            if severity in counts:
                counts[severity] += 1
        return counts

    def generate(self, output_path):
        """ Renders `report.html`, with `scan_result`, `severity_counts`, `evidence_store`, and `scanner_version`, then 
        writes the result to `output_path`. Creates the parent directories, if they do not exist, and logs the absolute output
        path upon success."""

        # Resolves the absolute path to `scanner/templates/`, regardless of the working directory.
        templates_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "templates",
        )

        # Normalises the path to remove any `..` segments, prior to passing it to `FileSystemLoader`.
        templates_dir = os.path.normpath(templates_dir)

        # `autoescape` is enabled for HTML, to prevent JInja2 from rendering any raw user-controlled strings.
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(templates_dir),
            autoescape=jinja2.select_autoescape(["html"]),
        )

        # Loads `report.html` from `scanner/templates/`, via the configured `FileSystemLoader`.
        template = env.get_template("report.html")
        # Builds the severity count dictionary, used to populate the bar chart section of `report.html`.
        severity_counts = self._compute_severity_counts()

        # Parses the ISO string timestamps back into datetime objects, so thatr the template can call `.strftime()`.
        parsed_start = _dt.datetime.fromisoformat(self.scan_result.scan_start)
        parsed_end = _dt.datetime.fromisoformat(self.scan_result.scan_end)

        # Wraps `scan_result` in a simple namespace, so that the template receives the datetime objects without mutating any oif the dataclass.
        scan_result_view = types.SimpleNamespace(**self.scan_result.to_dict())
        scan_result_view.scan_start = parsed_start
        scan_result_view.scan_end = parsed_end

        # Assembles the full Jinja2 render context, passed into `report.html`, at template render time.
        context = {
            "scan_result": scan_result_view,
            "severity_counts": severity_counts,
            "evidence_store": self.evidence_store,
            "scanner_version": self.SCANNER_VERSION,
        }

        # Renders the template to a string, with all context variables substituted.
        rendered = template.render(**context)

        # Resolves `output_path` to an absolute path, prior to creating the dictionaries, or writing the file.
        output_path = os.path.abspath(output_path)
        # Creates any missing parent directories, prior to writing the report file.
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Writes the rendered HTML string to the output file using UTF-8 encoding.
        with open(output_path, "w", encoding="utf-8") as report_file:
            report_file.write(rendered)

        logger.info("HTML report written to %s", output_path)