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
    # Represents a single unique route discovered during scanning.
    # COmbines the URL + HTTP method to distinguish between e.g., `GET /users`, and `POST /users`.
    # This is the primary unit passed into testing modules. 

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
        # Converts the dataclass into a serialisable dictionary for reporting/output.
        return asdict(self)


@dataclass
class Parameter:
    # Represents a single parameter associated with an endpoint. 
    # Used heavily during fuzzing and IDOR testing to determine attack surface.

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
        # Converts the dataclass into a serialisable dictionary.
        return asdict(self)


@dataclass
class Vulnerability:
    # Represents a confirmed or potential vulnerability that is discovered by a test module.
    # This is the main output unit that gets aggregated into reports. 
    
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

    # Optional remediation guidance and classification.
    remediation: str = ""
    cvss_category: str = ""

    def to_dict(self) -> dict:
        # Converts the dataclass into a serialisable dictionary for reports.
        return asdict(self)

    def to_summary(self) -> str:
        # One-line summary used in console outputs and report indexes. 
        return f"[{self.severity}] {self.vuln_type} at {self.method} {self.endpoint}"


@dataclass
class ScanResult:
    # Top-level container that reperesents the outcome of an entire scan.
    # Built by the scan controller and passed directly to the reporting modules.
    target_url: str
    scan_start: str
    scan_end: str
    scan_duration_seconds: float

    # Aggregated discovery metrics.
    endpoints_discovered: int
    parameters_found: int

    # All vulnerabilities identified during the scan.
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    ## Operational metadata.
    # Total HTTP requests made during the scan. 
    total_requests: int = 0

    # Which modules were executed.
    modules_run: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        # Converts the entire scan result into a serialisable structure.
        # Used for JSON export and HTML report generation.
        return asdict(self)