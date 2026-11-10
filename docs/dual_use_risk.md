# Dual-Use Risk Register

## Tool: Semi-Automated Logic Flaw Scanner

### Risk
This tool automates HTTP request replay, session token manipulation, and
endpoint probing. The same capabilities that detect vulnerabilities in
authorised targets, could be misused against systems without permission,
which would constitute an offence under the Computer Misuse Act 1990.

### Mitigations Implemented
- scope.py enforces a domain allowlist; requests outside the configured
  target base URL are blocked before dispatch.
- scan_config.yaml requires explicit target declaration; no default target.
- All testing conducted inside an isolated Kali Linux VM with no external
  network interfaces active during scans.
- Docker targets (Juice Shop, DVWA) contain no real personal data.
- credentials.txt excluded from version control via .gitignore.
- Lab account passwords in configs/ and launch.py are placeholders.
- Source is published openly; the README Ethical Use Statement and
  docs/responsible_disclosure.md restrict use to authorised targets only.
