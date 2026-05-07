### Evaluation Analysis.

This document scovers the comparative analysis for Phase 11 of the scanner evaluation. It identifies the vulnerability categories 
detected byby the scanner that ZAP and Burp Community missed, the categories those tools surfaced that the scanner does not cover, 
the false positive landscape, and limitations of the scanner that require human judement, or fall outside of the outlined scope.

All figures in this document are drawn from `evaluation/raw_counts.json`, `evaluation/stats_summary.csv`, and `evaluation/scan_timings.json`,
produced during phase 11.2 and 11.3.

## Summary of Results.

--------------------------------------------------------------------------------------
| Tool                    | Target      | TP  | FN | FP  | Recall Precision | F1     |
--------------------------------------------------------------------------------------
| Scanner                 | Juice Shop  | 10  | 7  |  0  | 0.5882 1.0000    | 0.7404 |
| Scanner                 | DVWA        | 4   | 1  |  0  | 0.8000 1.0000    | 0.8889 |
| Scanner                 | Combined    | 14  | 8  |  0  | 0.6364 1.0000    | 0.7778 |
| ZAP 2.17.0              | Juice Shop  | 0   | 17 |  0  | 0.0000 0.0000    | 0.0000 |
| Burp Community 2026.2.3 | Juice Shop  | 0   | 17 |  0  | 0.0000 0.0000    | 0.0000 |
--------------------------------------------------------------------------------------
McNemar's test (Yates corrected, scanner vs ZAP on JS):
    b=10, c=0, chi-squared=8.1000, p=0.0044.
The difference is statistically significant at allpha 0.05. The small discordant pair count (b+c=10, below 25) means that this result should 
be reported alongisde the effect size, rather than treated as conclusive in isolation.

## Categories the Scanner Detected That Burp Missed.

The scanner detectged true positives across four ground truth categories. ZAP and Burp Community detected zero true positives across all seventeed 
Juice SHop ground truth entries. 

# Vertical Privilige Escalation (broken_access_control).

`vertical_auth.py` confirmed that four admin-only JS endpoints returned non-denail responses, under a normal user session:
    `/api/Users` (JS-003).
    `/api/Complaints` (JS-004).
    `/rest/admin/application-configuration` (JS-014).
    `/rest/saveLoginIp` (JS-015),

and these were all confirmed accessible under the low-privilege `user_a` session. Recall for this module across both targets was 100 percent of the 
in-scope vertical escalation entries (6/6).

Neither ZAP, nor Burp Community, can perform authenticated cross-role comparison. Both tools operate with a single session context, and have no
mechanism to replay a request under a second role to determine whether access is improperly granted.

# Session Management FLaws (broken_authentication).

`session_termination.py` confirmed that the JS JWT remained valid after logout requests to `/rest/user/logout`(JS-007). `session_fixation.py`
confirmed that JS reissues the same DJWT value across two seperate logins at `/rest/user.login` (JS-008), and that DVWA does not rotate the `PHPSSID`  
cookie on login at `/vulnerabilities/weak_id/` (DV-004). These require maintinging pre-login, and post-login credential states across a controlled 
test sequence, which passive scanning tools cannot replicate.

# Missing Rate Limiting (security_misconfiguration)

`rate_limit_detector.py` confirmed the absence of 429 responses, or anomalous timing growth across repeated requests to:
    `/rest/user/reset-password` (JS-009), 
    `/rest/user/login` (JS-010), 
    `/rest/user/authentication-details/` (JS-016),
on JS, and `/login.php` (DV-001) on DVWA. `rate_limit_bypass.py` additionally confirmed that thge IP header rotation bypassed the rate limit on 
`rest/user/reset-password` (JS-017).

ZAP's active scan ruleset does not include brute-force threshold testing against authentication endpoints. Burp Community's passive scan noted 
authentication requests, but issued no rate limit findings.

## Categories ZAP and Burp Found That the Scanner DOesn't Cover.

ZAP's spider, and active scan, surfaced sixteen alerts against JS. None of these matched the ground truth entries, which was expected. The ground truth 
was made to cover only the four vulnerability categories within the scanner's defined scope. 

The ZAP alerts fell into three groups outside the scanner's scope:
    *Security Header Misconfiguration:*
        CSP failure to define directive with no fallback, COntent Security Policy header not set, missing anti-clickjacking header, and X-COntent-Type-Options
        header missing. These are passive informational findings produced by the HTTP response header inspection. The scanner does not perform any 
        header analysis by design.
    *Information Disclosure:*
        Application error disclosure, private IP disclosure, timestamp disclosure, cross-domain JavaScript source file inclusion, and cross-domain 
        misconfiguration. These require no authentication, and are detectable by any crawling tool. The scanner's scope is authenticated logic flaws, not 
        information leakage.
    *Library and Infrastructure Findings:*
        Vulnerable JS library, modern web application identifier, retrieved from cache, and session management response identified. These are characteristic 
        findings from ZAP's technology fingerprinting rules. They carry no confirmed exploitability evidence. 
    
    Burp Community's passive-only scan produced a comparable set of informational findings through its HTTP history analysis. But the community edition does
    not export issues, so findings were not formally counted.

    The scanner does not detect SQL injection, cross-site scripting, server-side request forgery, command injection, or any injection-class vulnerbaility. THis
    is a deliberate scope constraint, not a design gap. Those categories are already well-served, and documented, by general purpose tools. This scanner includes
    human pentester reasoning, specifically for logic flaws that require multi-role session management, and stateful workflow control. 

## False Positives, and How They Could Be Reduced.

The scanner produced zero false positives across both targets (combined FP=0, precision 1.0000). This is due to three design decisions in the core engine:
    *`ResponseComparator.is_access_granted`* requires both a non-denail HTTP status, and a minimum content length threshold before classifying a findings,
    preventing empty 200 responses being counted as access grants. 
    *`ResponseComparator.is_data_leak`* cross-reference the authenticateis_d user's known identifiers against the repsonse body, then checks for sensitive field keys,
    requiring both signals before raising a data leak findings.
    *`RateLimitDetector`* uses a fixed test email address (janedoe@fake.local) throughout its test sequence, to avoid generating JWT tokens, or locking real accounts,
    which could otherwise produce confounding signals in subsequent comparator calls.

Despite the zero FP result across the two targetrs, confitions that could produce false positives in broader deployments include the following:
    Shared application state between test accounts could cause a legitimate resource to ppear accessible to a second user, if the application intentionally shares
    it e.g., publically visible feedback, or shared product reviews. This would be misclassified as an IDOR finding by `horizontal_auth.py`. 
    *Mitigation:*
        COnfigure `known_resource_ids` in the target YAML, with resources that are private by design, and manually exclude endpoints where the sharing is intentional.
        
Rate Limit Bypass techniques could produce a false positive, if a bypass technique coincides with a temporary backend rate limit tier that returns 200 OK for a 
different reason. 
    *Mitigation:*
        Cross-reference bypass findings with the raw request logs in the timestamped log file, prrior to reporting.
        
Workflow bypass tests sed out-of-order replays. If the application has no state enforcement, and allows the final step to succeed unconditionally for all users,
the scanner will flag it. In that case, the finding may represent a genuiine design choice rather than a bug. 
    *Mitigation:*
        Require manual review of all workflow bypass findings before treating them as confirmed vulnerabilities - again *semi*-automated.

## Limitations and Human Judgement Requirements

# What Requires Human Judgement:

*IDOR Confirmation:*
    `horizontal_auth.p` detects cross-user resource access using `ResponseCOmparator.is_data_lkeak`. The comparator checks whether the target user's identifier
    apears in the second user's response. However, some endpoints return shared resources by design. A human reviewer must inspect the flagged endpoint to confirm 
    whether the returned data is private to the target user, or legitimtely public. 
*Vertical Escalation Scope:*
    `vertical_auth.py` flags any endpoint that doesn't return a denail response, to a non-admin session. Some admin endpoints return 200 OK, with empty or 
    non-sensitive payloads. Whether the exposure consitutes an exploitable finding, requires manual assessment of the response body content.
*Workflow Bypass Impact:*
    `workflow_bypass.py` detects that a final workflow step was reachable, without completing preceding steps. Whether the bypass produces a harmful outcome, e.g.,
    placing an order without payment, requires manual confirmation that the application completed the business action, not just that it returned a non-error response.

## What The Scanner Can Not Detect:

*CSRF VUlnerabilities:*
    `CSRFExtractor` in `csrf.py` is a untility class, used to extract tokens for other modules. It does not test whether CSRF protections are absent, or bypassable.
    DV-002 (`/vulnerabilities/csrf/`) was a confirmed false negative for this reason. Adding a dedicated CSRF detection module is a possible extention.
*Horizontal IDOR Where Resource IDs Are Not Discoverable:*
    `horizontal_auth.py` discovers resource IDs through three tiers:
        `/rest/user/whoami` ednpoint,
        JSON array cross-referencing, 
        `known_resource_id` config field.
    All four JS horizontal IDOR entries (JS-001, JS-002, JS-005, JS-006), were false negatives because the basket IDs, feedback IDs, and review IDs for the opposing
    user were not present in any of those three sources. Endpoints where resource IDs must be obtained through a seperate enumeration pass, or where IDs are non-sequential 
    UUIDs unknown to the scanner, will be missed. 
*Workflow Bypass On Unconfigured Workflows:*
    `workflow_bypass.py` only tests workflows defined in the target YAML config. JS-012, and JS-013, covering the JS basket manipulation and checkout bypass, were 
    both false negatives. The basket and checkout workflow was defined in `configs/juiceshop.yaml`, but the bypass test did not produce a detectable response difference 
    at the comparison threshold. Workflows that use indempotent endpoints, or that require precise request body states, are likely to evade detecction. 
*Rate Limiting On NOn-Authentication Endpoints:*
    `rate_limit_detector.py` targets critical authentication endpoints identified by URL pattern matching. JS-011 (`/api/Users`, the user registration endpoint) was a 
    false negative, because the endpoint was not classified as a criticl authentication target by the pattern matcher. Any rate-limited resource that does not match
    authentication endpoint pattern will not be tested.
*Injection-CLass Vulnerabilities:*
    SQL injection, cross-site scripting, server-side request forgery, command injection, and XML external entity injection are outside of the scope by design. These 
    are well-covered by ZAPs active scan ruleset, and Burp Professional. The scanner is not intended to duplicate that coverage. 
*Second-Order and Asynchronous VUlnerabilities:*
    Any vulnerability where the effect is not visible in the immediate HTTP response, can not be detected. E.g., stored XSS payloads that execute in a different users
    session, or logic flaws that appear only after a background job processes a queued action.
*Race Condition:*
    The scanner sends requests sequentially with a configurabe throttle delay. VUlnerabilities that require near-simultaneous requests cannot be triggered/detected.

## Scan Duration:

The scanner required 4916 seconds on JS, and 2887 seconds on DVWA, against 2940 seconds for ZAPS spider and active scan, and 180 seconds for Burp Community's passive pass.
The scanner's longer runtime reflects the volume of authenticated, multi-role, and multi-step requests required for logic flaw testing (58,760 requests on JS, vs 421 for ZAP).
This is an inherent trade-off of the approach, not a performance deficiency.

### References:
- OWASP Foundation. (2025). *OWASP Top 10*. https://owasp.org/www-project-top-ten/
- McNemar, Q. (1947). Note on the sampling error of the difference between correlated
  proportions or percentages. *Psychometrika*, 12(2), 153-157.
- PortSwigger. (2025). *Burp Suite Community Edition*. https://portswigger.net/burp/communitydownload
- OWASP Foundation. (2025). *OWASP ZAP*. https://www.zaproxy.org/

