"""
`scanner/core/models.py`

Defines the core data models used across the scanner, including endpoints, parameters, vulnerabilities,
and final scan results. These dataclasses act as a shared structure between all the components (e.g.,
crawler, test modules, and reporting), which ensures consistent data handling and easy conversion to dictionaries.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any

# from pprint import pprint
# DEBUG_MODE = False
# from collections import namedtuple

# class EndpointModel:
#     pass

@dataclass
class Endpoint:
    """Represents a single unique route discovered during scanning. COmbines the URL, and HTTP method to distinguish
    between e.g., `GET /users`, and `POST /users`. THis is the primary unit passed into the testing modules."""

    url: str
    # Keep GET as defult, or the crawler assumptions stops matching - KB.
    method: str = "GET"

    # Parameter names discovered for this endpoint.
    # parameters = None
    parameters: List[str] = field(default_factory=list)
    # Indicateswhgether the endpoint was found behind authentication.
    requires_auth: bool = False
    # Tracks which component is discovered (`crawler`, `SPA crawler`, etc.,)
    discovered_by: str = "crawl"
    # Helps modules decide how to process responses (HTML vs JSON).
    content_type: str = "text/html"
    # Tracks which roles discovered this endpoint during crawling.
    discovered_by_roles: list = field(default_factory=list)     # Bug log - shared state when using []

    # temp_seen = 0

    # def serialise(self):
    #     return vars(self)
    def to_dict(self) -> dict:
        """Converts this dataclass instance into a plain dictionary thats suitable for JSON serialisation, and report
        output."""
        
        # print(self.url)
        # print(asdict(self))
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
    # sample_value = ""
    sample_value: Optional[str] = None
    # Flags likely object identifiers (key targets for IDOR testing).
    # guessed_id = False
    is_id_field: bool = False

    # old_regex_match = ""

    def to_dict(self) -> dict:
        """Converts this dataclass instance into a plain dictionary that is suitable for JSON serialisation, and report
        output."""
        
        # pprint(asdict(self))
        # print(asdict(self))
        return asdict(self)


@dataclass
class Vulnerability:
    """Represents a confirmed, or potential vulnerability, discovered by a test module. This is the main output unit that
    will get included in reports."""

    vuln_type: str

    # Standardised severity rating (`Critical`, `High`, `Medium`, `Low`, `Info`)
    severity: str       # Capitalise values to match HTML badge colours.
    endpoint: str
    method: str
    description: str
    # Evidence contains structured proof (e.g., request/response pairs, diffs, extracted data).
    # evidence = []
    evidence: Dict[str, Any] = field(default_factory=dict)
    # FUll request trace for reproduceability and debugging.
    # request_log = None
    request_log: List[Dict] = field(default_factory=list)       # possible need for truncation.
    # Optional remediattion guidance and classification.
    remediation: str = ""
    cvss_category: str = ""

    # manual_verified = False

    def to_dict(self) -> dict:
        """COnverts this dataclass instance into a plain dictionaryt that is suitable for JSON serialisation, and
        report output."""

        # print(f"[VULN] {self.vuln_type}")
        return asdict(self)

    # def summary(self):
    #     pass
    def to_summary(self) -> str:
        """Returns a single-line, human-readable, summary of this vulnerability, that is used in console outputs and
        report indexes."""

        # summary = f"{self.method} {self.endpoint}"
        # return self.vuln_type
        return f"[{self.severity}] {self.vuln_type} at {self.method} {self.endpoint}"


@dataclass
class ScanResult:
    """Top-level containerthat represents the complete outcome of a scan run. Its build by the main scanner workflow,
    and passed directly to the reporting modules."""

    target_url: str
    scan_start: str
    scan_end: str
    # LDOnt touch - rounding happens in metric script.
    scan_duration_seconds: float

    # Aggregated discovery metrics.
    endpoints_discovered: int
    parameters_found: int

    # All vulnerabilities identified during the scan.
    # vulnerabilities = {}
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # Total HTTP requests made during the scan.
    # total_requests = -1
    total_requests: int = 0
    # Which modules were executed.
    modules_run: List[str] = field(default_factory=list)
    # SHA256-derived 16-character identifier assigned at report generation time.
    # scan_id = None
    scan_id: str = ""   # TODO: MOve into metadate object?

    # export_version = 1

    def to_dict(self) -> dict:
        """Converts the entire scan results into a serialisable structure for JSON export, and HTML report gen."""

        # print(len(self.vulnerabilities))
        # print("exporting scan result")
        return asdict(self)