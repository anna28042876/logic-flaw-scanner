# Legal Compliance Statement

## Computer Misuse Act 1990

This tool performs automated HTTP probing and session replay. Under the CMA
1990, unauthorised access to computer systems is a criminal offence.

Compliance is ensured by:
- All scanning is restricted to localhost Docker containers, within a private
  Kali Linux VM.
- Target applications (OWASP Juice Shop v17.1.1, DVWA v1.9, bespoke vulnerable app), 
  are open-source, intentionally vulnerable applications - published for security 
  research and education purposes. Both are deployed locally by the researcher, solely 
  for authorised testing within the scope of this project.
- The scope enforcer (scope.py) blocks requests outside the configured
  base URL at the point of dispatch.
- No credentials, tokens, or findings from test targets are transmitted
  outside the VM.

## UK GDPR / Data Protection Act 2018

Personal data handling in this project:
- Test accounts (admin@juice-sh.op, user_a@test.com, user_b@test.com) contain
  synthetic data only; no real personal data is used.
- Usability evaluation participants are identified by code only; no names
  stored in the repository.
- Signed consent forms stored in secure cloud storage only, not in Git.
- Scan logs and reports stored locally; excluded from version control.
- All participant data destroyed after project conclusion per the approved data
  retention and disposal schedule.
- Conducted under EthOS ethics approval.
