# Semi-Automated Logic Flaw Scanner

A Python-based semi-automated web vulnerability scanner, targeting logic, and
authorisation flaws: IDOR/BOLA, Broken Access Control, authentication and
session management weaknesses, rate-limiting failures, and workflow bypasses.


## Attribution

All work in `scanner/` is attributed soley to the developer, and the developer only. 
Third-party libraries are used under open-source licences and are
listed in `requirements.txt`. No code has been copied from external sources
without citation.

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
docker-compose up -d
python -m scanner.main --config configs/juiceshop.yaml
```

## Structure

- `scanner/core/` — config, HTTP client, session manager, comparator, models.
- `scanner/modules/` — crawler, auth testers, workflow recorder, rate limit modules.
- `scanner/reports/` — HTML, and JSON report generators.
- `configs/` — YAML scan configs for Juice Shop and DVWA.
- `docs/` — environment notes, severity rubric, architecture diagrams.
- `tests/` — pytest unit tests.
- `wordlists/` — parameter, and path wordlists.

## Ethical Use

This tool is designed exclusively for use against locally hosted, intentionally
vulnerable applications (OWASP Juice Shop, DVWA, and a bespoke vulnerable app). 
Scanning any system without explicit, written authorisation is illegal under the 
Computer Misuse Act 1990.
