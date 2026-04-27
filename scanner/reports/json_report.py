"""
`json_report.py`

Generates a machine readable JSON report for a completed scanner run. Serialises `ScanResult` metadata, all
`Vulnerability` findings, and the full `EvidenceCollector` evidence store into a structured dictionary, then writes it
to a caller-specified file path, using `json.dump`, with `default=str`, to handle the datetime, and other non-serialisable
types safely.
"""

import os
import json

from scanner.core.logger import get_logger

# Obtains a named logger for this module, using the shared `get_logger` helper, from `logger.py`.
logger = get_logger(__name__)


class JSONReportGenerator:
    """Serialises `ScanResult` data, and `EvidenceCollector` evidence, into a structured JSON report file. Accepts a `scan_result`,
    and an `evidence_store` dictionary on construction. Produces one output file, per `generate` call."""

    # Version string recorded in the report metadata block, for traceability.
    SCANNER_VERSION = "1.0.0"

    def __init__(self, scan_result, evidence_store):
        """Stores the `ScanResult` instance, and the `evidence_store` dictionary, produced by `EvidenceCollector`. Both are serialised
        into the output JSON, by `generate`."""

        # `scan_result` holds all the discovered endpoints, vulnerabilities, and scan-timing metadata.
        self.scan_result = scan_result
        # `evidence_store` is a dictionary keyed by evidence ID, mapping to dictionaries built by `EvidenceCollector`.
        self.evidence_store = evidence_store

    def _build_metadata(self):
        """Builds the top-level metadata block, for the JSON report. Includes the target URL, scan start, and end times, duration,
        request count, endpoint count, parameter count, and scanner version."""

        return {
            "scanner_version": self.SCANNER_VERSION,
            # `scan_id` is the SHA256-derived, 16-character identifier, assigned by `EvidenceCollector`.
            "scan_id": self.scan_result.scan_id,
            "target_url": self.scan_result.target_url,
            # `scan_start`, and `scan_end` are datetime objects serialiseed to strings, via `default=str`, in `generate`.
            "scan_start": self.scan_result.scan_start,
            "scan_end": self.scan_result.scan_end,
            "duration_seconds": self.scan_result.scan_duration_seconds,
            # Endpoint, and parameter counts, reflect totals discovered across all the crawler, and enumerator passes.
            "total_endpoints": self.scan_result.endpoints_discovered,
            "total_parameters": self.scan_result.parameters_found,
            # `total_requests` is the cumulative HTTP request count, that is tracked via `HTTPClient`.
            "total_requests": self.scan_result.total_requests,
            # `total_findings` is derived at the report time, rather than stored on `ScanResult` directly.
            "total_findings": len(self.scan_result.vulnerabilities),
        }

    def _build_findings(self):
        """Converts every `Vulnerability` in `scan_result.vulnerabilities`, into a plain dictionary using `to_dict`. It returns a list
        of these dictionaries, ordered by the original finding sequence."""

        # Initialises an empty list that will hold one dictionary per `Vulnerability`, in insertion order.
        findings = []

        # Converts each `Vulnerability` into a serialisable dictionary, and then appends it to the findings list.
        for vuln in self.scan_result.vulnerabilities:
            # `to_dict` is defined on the `Vulnerability` dataclass, in `models.py`, using `asdict`.
            findings.append(vuln.to_dict())

        return findings

    def _build_evidence(self):
        """Converts the `evidence_store` into a JSON-serialisable form. Returns a dictionary keyed by evidence ID, with each
        value being the corresponding evidence dictionary, from `EvidenceCollector`."""

        # Initialises an empty dictionary, that will mirror the structure of `evidence_store`.
        evidence = {}

        # Iterates the evidence list returned by `get_all_evidence`, keying each entry by its id field.
        for evidence_record in self.evidence_store.get_all_evidence():
            evidence[evidence_record.get("id", "unknown")] = evidence_record

        return evidence

    def generate(self, output_path):
        """Builds the full report dictionary from `metadata`, `findings`, and `evidence` blocks, then writes it to `output_path` as indented JSON.
        Uses `default=str` to safely serialise datetime objects. Creates parent directories if they are absent, and logs the absolute output path
        upon success."""

        # Composes the three top-level blocks into the final report dictionary.
        report_data = {
            "metadata": self._build_metadata(),
            "findings": self._build_findings(),
            # `evidence` is keyed by the 16-character, SHA256-derived ID, adssigned in `EvidenceCollector`.
            "evidence": self._build_evidence(),
        }

        # Resolves `output_path` to an absolute path, prior to creating any directories, or writing the file.
        output_path = os.path.abspath(output_path)
        # Creates any of the missing parent directories, before writing the report file.
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Writes the report dictionary to the output file, with two-space indentation, and a `default=str` fallback.
        with open(output_path, "w", encoding="utf-8") as report_file:
            # `default=str` ensures that datetime objects, UUIDs, and any other non-serialisable types are cast to strings.
            json.dump(report_data, report_file, indent=2, default=str)

        logger.info("JSON report written to %s", output_path)