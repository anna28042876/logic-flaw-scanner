### Semi-Automated Logic Flaw Scanner:

Python-based semi-automated web vulnerability scanner, targeting logic and authorisation flaws:
    • IDOR/BOLA,
    • Broken Access Control,
    • Authentication and Session Management Weaknesses,
    • Rate-Limiting Failures,
    • Workflow Bypasses.


## Description:
This scanner embeds human pentester reasoning for logic-based web flaws into a reproducible, semi-automated Python tool.
Unlike general-purpose scanners e.g., ZAP, it performs authenticated multi-role testing, stateful workflow replay, and 
rate-limit threshold testing. It was evaluated against OWASP JS v17.1.1, and DVWA v1.9, achieving a combined recall of 
0.6364, and precision of 1.0000 across 22 ground truth entires, compared to 0.0000 recall for both ZAP and Burp Community
against the same targets. 

## Features:

• Multi-role authenticated crawling, via `crawler.py`, and `spa_crawler.py`.
• Parameter enumeration via `param_enumerator.py`, and bundled wordlists. 
• Unauthenticated access detection, via `unauth_access.py`.
• Session invalidation testing, via `session_termination.py`.
• Session fixation detection (JWT reuse, and PHPSESSID rotation), via `session_fixation.py`.
• Horizontal IDOR/BOLA detection via `horizontal_auth.py`, with three-tier ID discovery. 
• Vertical privilege escalation detection, via `vertical_auth.py`.
• Stateful workflow recording, and step-skip bypass, via `workflow_recorder.py`, and `workflow_bypass.py`.
• Rate limit absence detection, via `rate_limit_detector.py`, with three-tier escalation.
• Rate limit bypass, via header rotation in `rate_limit_bypass.py`.
• HTML and JSON report generation, via `html_report.py` and `json_report.py`.
• Per-moduile error boundaries, so that a single module crash does not discard any earlier findings.
• Scope enforcement on every request, via `scope.py`.
• Output sanitisation throughout the report pipeline.

## Architecture:
# COmponent Diagram:

    ```mermaid
    flowchart TD
        subgraph CLI["CLI Layer"]
            A["main.py — argparse"]
        end

        subgraph ORCH["Orchestrator"]
            B["Scanner class"]
        end

        subgraph CORE["Core Layer"]
            C1["config.py"]
            C2["http_client.py"]
            C3["session_manager.py"]
            C4["scope.py"]
            C5["comparator.py"]
            C6["evidence.py"]
        end

        subgraph MOD["Module Layer"]
            M1["crawler.py"]
            M2["spa_crawler.py"]
            M3["param_enumerator.py"]
            M4["unauth_access.py"]
            M5["session_termination.py"]
            M6["session_fixation.py"]
            M7["horizontal_auth.py"]
            M8["vertical_auth.py"]
            M9["workflow_recorder.py"]
            M10["workflow_bypass.py"]
            M11["rate_limit_detector.py"]
            M12["rate_limit_bypass.py"]
        end

        subgraph REP["Report Layer"]
            R1["html_report.py"]
            R2["json_report.py"]
        end

        CLI -->|"config path, flags"| ORCH
        ORCH -->|"loads and validates"| C1
        ORCH -->|"constructs shared instances"| C2
        ORCH -->|"constructs shared instances"| C3
        ORCH -->|"constructs shared instances"| C4
        ORCH -->|"constructs shared instances"| C5
        ORCH -->|"constructs shared instances"| C6
        C1 --> MOD
        C2 --> MOD
        C3 --> MOD
        C4 --> MOD
        C5 --> MOD
        C6 --> MOD
        MOD -->|"ScanResult findings"| REP
    ```

# Scan Execution Sequence:

    ```mermaid
    sequenceDiagram
        participant CLI as CLI
        participant Scanner as Scanner
        participant Core as Core Layer
        participant Mod as Module Layer
        participant Rep as Report Layer

        CLI->>Scanner: Scanner(config_path, output_dir, modules)
        Scanner->>Core: ScanConfig.load() and validate()
        Scanner->>Core: SessionManager.authenticate_all()
        Scanner->>Mod: Crawler.run()
        Scanner->>Mod: SPACrawler.run()
        Scanner->>Mod: ParameterEnumerator.run()
        Scanner->>Mod: UnauthAccessChecker.run()
        Scanner->>Mod: SessionTerminationValidator.run()
        Scanner->>Mod: SessionFixationTester.run()
        Scanner->>Mod: HorizontalAuthTester.run()
        Scanner->>Mod: VerticalAuthTester.run()
        Scanner->>Mod: WorkflowRecorder.run()
        Scanner->>Mod: WorkflowBypassTester.run()
        Scanner->>Mod: RateLimitDetector.run()
        Scanner->>Mod: RateLimitBypassTester.run()
        Scanner->>Rep: HTMLReportGenerator.generate()
        Scanner->>Rep: JSONReportGenerator.generate()
        Rep-->>CLI: reports/ directory
    ```
Standalone `.mermaid` source files are stored in `docs/architecture.mermaid`, and `docs/scan_sequence.mermaid`. 
PNG exports are at `docs/architecture.png`, and `docs/scan_sequence.png`.

## Requirements:

|-----------------------------------------------------------------------|
| Requirement    | Version                                              |
|-----------------------------------------------------------------------|
| Python         | 3.13 or later                                        |
| Docker         | 24.0 or later                                        |
| Docker Compose | 2.x                                                  |
| OS             | Kali Linux 2024.x (tested) or any Debian-based Linux |
| Node.js        | 18 or later (for Mermaid PNG export only)            |
|-----------------------------------------------------------------------|

Python dependencies are pinned in `requirements.txt`. Key packages:

|-------------------------------------------------------------|
| Package        | Version           | Purpose                |
|-------------------------------------------------------------|
| requests       | 2.32.5            | HTTP client            |
| beautifulsoup4 | 4.14.3            | HTML crawling          |
| playwright     | 1.58.0            | SPA crawling           |
| PyYAML         | 6.0.3             | Config loading         |
| Jinja2         | 3.1.6             | HTML report templating |
| scipy          |                   | McNemar's test         |
| pytest         | 9.0.2             | Unit testing           |
| ruff           | 0.15.7            | Linting and formatting |
|-------------------------------------------------------------|

## Installation:

```bash
# Clone, or extract thee project into the working directory.
cd ~/logic-flaw-scanner

# Create, and activate a Python virtual environment (venv).
python3 -m venv venv
source venv/bin/activate

# Install all the pinned Python dependencies.
pip install -r requirements.txt

# Start Juice Shop, and DVWA in Docker.
docker-compose up -d

# Confirm both targets are reachable before scanning.
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080
```

Both curl commands should return `200`. DVWA requires the setup page to be
completed on first run: visit `http://localhost:8080/setup.php` and click
*Create / Reset Database* before scanning.

## Configuration:

Scan targets are defined in the YAML files under `configs/`. There are two pre-built configs provided: `configs/juiceshop.yaml,`,
 and `configs/dvwa.yaml`.

*The minimum required structure is:*

```yaml
target:
  base_url: "http://localhost:3000"
  excluded_paths:
    - "^/rest/user/logout"

verify_ssl: false
proxy: null
throttle_delay: 0.05

scope:
  include_subdomains: false
  allowed_paths:
    - "/api/"
    - "/rest/"

login:
  login_url: "http://localhost:3000/rest/user/login"
  login_method: POST
  username_field: "email"
  password_field: "password"
  success_indicator: "token"

credentials:
  - username: "admin@juice-sh.op"
    password: "CHANGE_ME_ADMIN"
    role: "admin"
    auth_type: "bearer"
  - username: "user_a@test.com"
    password: "CHANGE_ME_USER_A"
    role: "user_a"
    auth_type: "bearer"
  - username: "user_b@test.com"
    password: "CHANGE_ME_USER_B"
    role: "user_b"
    auth_type: "bearer"

rate_limit:
  requests_per_second: 10
  total_requests: 100
  critical_endpoints:
    - url: "/rest/user/login"
      method: POST
  bypass_headers:
    - "X-Forwarded-For"
  rate_limit_tiers:
    - { rps: 10, count: 100 }
    - { rps: 25, count: 150 }
    - { rps: 50, count: 200 }

reporting:
  output_dir: "reports/"
  format: "both"

random_seed: 42
```
These credential roles are required for the full testing: `admin` (vertical escalation), `user_a`, 
and `user_b` (horizontal IDOR). Removing, or omitting, any roles disables its corresponding module.

## Usage:

# Full Scan Against JuiceShop:

```bash
python -m scanner.main --config configs/juiceshop.yaml
```

# FUll Scan Against DVWA:

```bash
python -m scanner.main --config configs/dvwa.yaml 
```

# Write Reports To Custom Output DIrectory:

```bash
python -m scanner.main --config configs/juiceshop.yaml --output-dir results/
```

# RUn Only The Rate Limiting and Session Modules:

```bash
python -m scanner.main --config configs/juiceshop.yaml --modules ratelimit,session
```

# Enable Debug Logging:

```bash
python -m scanner.main --config configs/juiceshop.yaml --verbose
```

# Route Traffic Through Burp Suite Proxy:

```bash
python -m scanner.main --config configs/juiceshop.yaml --proxy http://127.0.0.1:8080 --no-ssl-verify
```

# Available MOdule Names For `--modules`:

|----------------------------------------------------------------|
| Token       | Modules run                                      |
|----------------------------------------------------------------|
| `crawl`     | `crawler.py`, `spa_crawler.py`                   |
| `params`    | `param_enumerator.py`                            |
| `unauth`    | `unauth_access.py`                               |
| `session`   | `session_termination.py`, `session_fixation.py`  |
| `idor`      | `horizontal_auth.py`                             |
| `vertical`  | `vertical_auth.py`                               |
| `workflow`  | `workflow_recorder.py`, `workflow_bypass.py`     |
| `ratelimit` | `rate_limit_detector.py`, `rate_limit_bypass.py` |
| `all`       | All of the above (default)                       |
|----------------------------------------------------------------|

## Output:

Reports are written to `reports/` on default, named by timestamp:
    `report_YYYYMMDD_HHMMSS.html`, and `report_YYYYMMDD_HHMMSS.json`.

# HTML Report:

A self-contained single-file HTMNL report, rendered via `html_report.py`, using Jinja2 templating. It contains a findings
summary table, per-finding detail cards with sanitised request, and response evidence, severity breakdown, and scan metadata.
They're intended for human review, and for the appendix.

# JSON Report:

A strcutured, machine-readable, report produced by `json_report.py`. Contains the full findings list with `vuln_type`, `endpoint`, 
`method`, `severity`, `evidence` fields, and `metadata` block with `duration_seconds`, `total_requests`, and `scanner_Version`. Its 
used as an input to `evaluation/match_findings.py` for the metric calulcation.

## Testing:

The tests use pytesst against the core engine coponents. All 60 tests pass on Python 3.13.

```bash
cd ~/logic-flaw-scanner
source venv/bin/activate
pytest tests/ -v
```

|----------------------------------------------------------------------------------------------------------|
| Test file                   | Coverage                                                                   |
|----------------------------------------------------------------------------------------------------------|
| `tests/test_comparator.py`  | `ResponseComparator` status, body length, data leak, access grant logic    |
| `tests/test_config.py`      | `ScanConfig` loading, validation, and field defaults                       |
| `tests/test_csrf.py`        | `CSRFExtractor` token extraction from HTML forms                           |
| `tests/test_http_client.py` | `HTTPClient` request construction and throttle behaviour                   |
| `tests/test_models.py`      | `Vulnerability` and `ScanResult` data model construction and serialisation |
| `tests/test_scope.py`       | `ScopeEnforcer` domain, path, and exclusion list enforcement               |
|----------------------------------------------------------------------------------------------------------|

Linting, and formattng, are enforced via ruff:

```bash
ruff check scanner/
ruff format --check scanner/
```

## Ethical Use STatement:

This tool is designed exclusively for the use against locally hosted, intentionally vulnerable applications (OWASP Juice SHop, and DVWA), within
a controlled lab environment. 

Scanning against any system without explicit, written authorisation from the systm owner is illegal under the Computer Misuse Act 1990 (UK) and equivalent
legislation in other jurisdictions. The developer accepts no responsibility for misuse of this tool.

This project was conducted under formal EthOS ethics approval. All scanning was performed against
Docker-isolated targets on a host-only network with no external connectivity. All test credentials, personally identifiable information used during testing,
and scan artefacts are confined to the local VM and are not transmitted outside the lab environment.