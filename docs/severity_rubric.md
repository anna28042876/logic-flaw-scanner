### Severity Rubric
------------------------------------------------------------------------------------------------------------------
This document defines the severity mapping used by the logic flaw scanner, when assigning severity levels to the 
`Vulnerability` objects. The rubric is aligned with OWASP risk categories.

Findings are counted per endpoint, not per vulnerability class. If the scanner flags three sperate IDOR endpoints, 
each one is recorded as a distinct finding. A second summary table in the report further aggregates the findings by
vulnerability class. 

------------------------------------------------------------------------------------------------------------------

## Severity Levels
--------------------------------------
# Critical
- IDOR/BOLA, with a confirmed data leak across user accounts (cross-role read/write, confirmed via 
  `ResponseComparator`).
- Vertical privilege escalation to an admin role, confirmed via a non-denial response from an admin-only endpoint.
- 2FA bypass where a protected resource is reached, after skipping the verification step.

--------------------------------------
# High
- Authentication Bypass: Unauthenticated access to a protected endpoint, confirmed by `UnauthAccessChecker`.
- Session Fixation: PHPSESSID not rotated on login in DVWA, or JWT token reused across two JS logins.
- Rate Limit Bypass on an Authenticated Endpoint: Any bypass technique succeeds in exceeding the detected threshold.
- Workflow Bypass: Step skip, out of order execution, or cross session replay, enabling the final action to succeed.
--------------------------------------
# Medium
- Missing Rate Limiting: No 429 responses, and no anomalous response time growth detected across full test sequence.
- Session Not Invalidated on Logout: Old credentials being accepted after a logout request.
- JWT Without Expiry: Decoded payload contains no `exp` claim.
- Forced Browsing: An unprotected resource returns a 200 response, via the wordlist path test.
--------------------------------------
# Low
- Informational findings such as JWT token reuse across sessions, where no protected action is completed.
- Verbose error messages, or stack traces returned in response bodies. 
--------------------------------------
# Info
- Scanner Errors: A module raised an unhandled exception. The findings record the module name + exception message.
- Skipped Tests: A module was excluded, via the `--modules` CLI flag.
- Informational notes that do not represent a confirmed vulnerability. 

------------------------------------------------------------------------------------------------------------------
## References

- OWASP Foundation. (2025). *OWASP Top 10*. https://owasp.org/www-project-top-ten/