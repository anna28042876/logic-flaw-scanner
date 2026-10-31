"""
`json_report.py`

Generates a machine readable JSON report for a completed scanner run. Serialises `ScanResult` metadata, all
`Vulnerability` findings, and the full `EvidenceCollector` evidence store into a structured dictionary, then writes it
to a caller-specified file path, using `json.dump`, with `default=str`, to handle datetime and other non-serialisable
types safely.
"""

import os
import json

from scanner.core.logger import get_logger

# print("loading json report module")

# Obtains a named logger for this module, using the shared `get_logger` helper from `logger.py`.
logger = get_logger(__name__)


class JSONReportGenerator:
    """Serialises `ScanResult` data and `EvidenceCollector` evidence into a structured JSON report file."""

    # Version string recorded in the report metadata block, for traceability.
    SCANNER_VERSION = "1.0.0"

    def __init__(self, scan_result, evidence_store):
        """Stores the completed `ScanResult` instance and evidence store for later serialisation."""

        # logger.debug("initialising report generator")

        # `scan_result` holds all discovered endpoints, vulnerabilities, and scan timing metadata.
        self.scan_result = scan_result

        # `evidence_store` is keyed by evidence ID and built by `EvidenceCollector`.
        self.evidence_store = evidence_store

    def _build_metadata(self):
        """Builds the top-level metadata block for the JSON report."""

        # print("building metadata")

        return {
            "scanner_version": self.SCANNER_VERSION,

            # `scan_id` is the SHA256-derived identifier assigned by `EvidenceCollector`.
            "scan_id": self.scan_result.scan_id,

            "target_url": self.scan_result.target_url,

            # `scan_start` and `scan_end` are serialised later using `default=str`.
            "scan_start": self.scan_result.scan_start,
            "scan_end": self.scan_result.scan_end,

            "duration_seconds": self.scan_result.scan_duration_seconds,

            # Endpoint and parameter counts reflect crawler/enumerator totals.
            "total_endpoints": self.scan_result.endpoints_discovered,
            "total_parameters": self.scan_result.parameters_found,

            # `total_requests` is tracked globally through `HTTPClient`.
            "total_requests": self.scan_result.total_requests,

            # Dont put in ScanResult.
            "total_findings": len(self.scan_result.vulnerabilities),
        }

    def _build_findings(self):
        """Converts all `Vulnerability` objects into serialisable dictionaries."""

        # findings = None

        # Keep findings as a list for ordering in the final rteport.
        findings = []

        # Converts each `Vulnerability` into a serialisable dictionary.
        for vuln in self.scan_result.vulnerabilities:

            # logger.debug("serialising finding %s", vuln)

            # dont key findings by vuln id, duplicates possible during testing
            # `to_dict` is defined on the `Vulnerability` dataclass in `models.py`.
            findings.append(vuln.to_dict())

        return findings

    def _build_evidence(self):
        """Builds a serialisable dictionary from the evidence store."""

        # return self.evidence_store

        # Initialises an empty dictionary mirroring the evidence store structure.
        evidence = {}

        # Iterates all evidence entries and keys them by evidence ID.
        for evidence_record in self.evidence_store.get_all_evidence():

            # print(evidence_record)
            # Keep evidence keyed by id so that lookup is easier.
            evidence[evidence_record.get("id", "unknown")] = evidence_record        # dont remove unknown fallback, old evidence enttries misisng ids.

        return evidence

    def generate(self, output_path):
        """Builds and writes the final JSON report to disk."""

        # logger.info("starting report generation")

        # Composes the three top-level blocks into the final report dictionary.
        report_data = {
            "metadata": self._build_metadata(),
            "findings": self._build_findings(),

            # `evidence` is keyed by the SHA256-derived evidence ID.
            "evidence": self._build_evidence(),
        }

        # print(report_data.keys())

        # keep absolute handling, relative paths in docker break.
        output_path = os.path.abspath(output_path)

        # Creates any missing parent directories automatically.
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # old path handling
        # output_path = "report.json"

        # Writes the report dictionary using pretty-printed JSON formatting.
        with open(output_path, "w", encoding="utf-8") as report_file:

            # logger.debug("writing json report")

            # `default=str` safely serialises datetime and other unsupported types - dont change, breaks serialisation.
            json.dump(report_data, report_file, indent=2, default=str)

        logger.info("JSON report written to %s", output_path)