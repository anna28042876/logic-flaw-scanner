"""
`scanner/core/models.py`

Defines the core data models used across the scanner, including endpoints, parameters, vulnerabilities,
and final scan results. These dataclasses act as a shared structure between all the components (e.g.,
crawler, test modules, and reporting), which ensures consistent data handling and easy conversion to dictionaries.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any


@dataclass
class Endpoint:
    """Represents a single unique route discovered during scanning. COmbines the URL, and HTTP method to distinguish
    between e.g., `GET /users`, and `POST /users`. THis is the primary unit passed into the testing modules."""

    url: str
    method: str = "GET"

    # Parameter names discovered for this endpoint.
    parameters: List[str] = field(default_factory=list)
    # Indicateswhgether the endpoint was found behind authentication.
    requires_auth: bool = False
    # Tracks which component is discovered (`crawler`, `SPA crawler`, etc.,)
    discovered_by: str = "crawl"
    # Helps modules decide how to process responses (HTML vs JSON).
    content_type: str = "text/html"
    # Tracks which roles discovered this endpoint during crawling.
    discovered_by_roles: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """Converts this dataclass instance into a plain dictionary thats suitable for JSON serialisation, and report
        output.

        Returns:
            dict: All the fields of this `Endpoint` as a nested dictionary that is produced by `dataclasses.asdict`."""
        return asdict(self)


@dataclass
class Parameter:
    """Represents a single paramater that is associated with an endpoint. Its used heavily during fuzzing, and IDOR testing
    to determine the attack surface."""

    name: str
    # Where the parameter appears: `url`, `body`, `header`, or `cookie`.
    location: str
    # Inferred type: `string`, `integer`, `boolean`, or `unknown`.
    param_type: str
    # Example value that is observed during crawling.
    sample_value: Optional[str] = None
    # Flags likely object identifiers (key targets for IDOR testing).
    is_id_field: bool = False

    def to_dict(self) -> dict:
        """Converts this dataclass instance into a plain dictionary that is suitable for JSON serialisation, and report
        output.

        Returns:
            dict: All the fields of this `Parameter` as a nested dictionary, produced by `dataclasses.asdict`.
        """
        return asdict(self)


@dataclass
class Vulnerability:
    """Represents a confirmed, or potential vulnerability, discovered by a test module. This is the main output unit that
    will get included in reports."""

    vuln_type: str

    # Standardised severity rating (`Critical`, `High`, `Medium`, `Low`, `Info`)
    severity: str
    endpoint: str
    method: str
    description: str
    # Evidence contains structured proof (e.g., request/response pairs, diffs, extracted data).
    evidence: Dict[str, Any] = field(default_factory=dict)
    # FUll request trace for reproduceability and debugging.
    request_log: List[Dict] = field(default_factory=list)
    # Optional remediattion guidance and classification.
    remediation: str = ""
    cvss_category: str = ""

    def to_dict(self) -> dict:
        """COnverts this dataclass instance into a plain dictionaryt that is suitable for JSON serialisation, and
        report output.

        Returns:
            dict: All the fields of this `Vulnerability`, as a nested dictionary produced by `dataclasses.asdict`."""

        return asdict(self)

    def to_summary(self) -> str:
        """Returns a single-line, human-readable, summary of this vulnerability, that is used in console outputs and
        report indexes.

        Returns:
            str: A fdormatted string in the form '[Severity] vuln_type at METHOD endpoint'."""
        return f"[{self.severity}] {self.vuln_type} at {self.method} {self.endpoint}"


@dataclass
class ScanResult:
    """Top-level containerthat represents the complete outcome of a scan run. Its build by the main scanner workflow,
    and passed directly to the reporting modules."""

    target_url: str
    scan_start: str
    scan_end: str
    scan_duration_seconds: float

    # Aggregated discovery metrics.
    endpoints_discovered: int
    parameters_found: int

    # All vulnerabilities identified during the scan.
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # Total HTTP requests made during the scan.
    total_requests: int = 0
    # Which modules were executed.
    modules_run: List[str] = field(default_factory=list)
    # SHA256-derived 16-character identifier assigned at report generation time.
    scan_id: str = ""

    def to_dict(self) -> dict:
        """Converts the entire scan results into a serialisable structure for JSON export, and HTML report gen.

        Returns:
            dict: All the fields of this `ScanResult`, as a nested dictionary produced by `dataclasses.asdict`, including
            the full `vulnerabilities` list."""

        return asdict(self)
