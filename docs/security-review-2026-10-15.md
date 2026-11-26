# Security review — 15 October 2026

Scope: console, collector parsing/resource use, vault verification, Linux
installer and Windows deployment scripts. Tests use loopback and temporary
records. Production checks cover configuration, access controls, TLS/HTTP
responses and normal service operation; no disruptive fleet-wide traffic test.

## Confirmed issues addressed

| Finding | Risk | Correction |
|---|---|---|
| Plain HTTP login fallback when TLS files disappear | High: credential/session exposure during a TLS configuration failure | Missing TLS stops the web service; plaintext authentication/protected reads are refused; cookies always require Secure |
| Password response survives audit failure | High: reveals without the required audit entry | Audit must be written and flushed before a password response; failure returns 503 without a secret |
| Revocation while a reveal body is uploaded | High: a formerly authorized session can finish a reveal | Recheck session/account immediately before lookup, under the account-management lock |
| Untrusted fields can forge audit lines | Medium: misleading audit history | Validate machine/ID, escape and bound audit values, rotate logs |
| Cross-origin login accepted | Medium: login CSRF | Check browser Origin/Sec-Fetch-Site; keep session CSRF mandatory for sensitive API mutations |
| Unbounded workers/caches/unknown heartbeat IDs | Medium: resource exhaustion | Cap connections (32 total, 16 per IP, 35-second absolute deadline), sessions (512), Basic cache (64), failure-IP entries (4096) and unknown UDP IDs (256, five-minute retention); registered peers continue updating |
| Unbounded SMB pre-auth response/deadline | Medium: collector memory/time exhaustion | 64 KiB response limit and transaction deadline; heartbeat parsing stays unchanged |
| Multiple computer accounts claim one RustDesk ID | Medium: wrong machine/user/password association | Reject ambiguous IDs instead of choosing the newest claim; preserve mandatory owner/domain checks |
| Vault content/reads insufficiently bounded | Medium: malformed, oversized or replaced files | Strict schema and filename/host agreement, bounded regular-file/no-follow reads, change detection across owner queries, explicit SMB encryption for ACL queries |
| Selecting a password prevents automatic remask | Medium: on-screen disclosure exceeds reveal window | Expiry directly masks the cell despite text selection; clear on page hiding and discard stale reveal responses |
| Malformed Windows record errors can contain passwords | Medium: deployment log disclosure | Generic parse errors, owner verification before reuse, bounded and validated lookup records |

Additional hardening: script-hash CSP, HSTS, anti-framing/browser-permission
headers, broader CSV formula guarding, safe focus restoration, loopback default
without company configuration, legacy password-hash upgrades, root installer
no-follow writes, random MSI temporary names, optional MSI SHA-256 pinning and
rejection of unsafe deployment paths/share mismatches.
Collector state is now root:service-group 0640 rather than world-readable, so
local accounts cannot bypass console authorization to read workstation/user metadata.

## Verification

- Five focused probes fail against the original `v2.0.0` and pass after fixes:
  plaintext login, cross-origin login, audit failure, mid-request revocation and
  ambiguous machine IDs.
- **39 Python tests pass on Ubuntu**, including real TLS, authorization/CSRF/rate
  limits, leakage checks, vault owner/schema/symlinks, resource limits and installer
  file permissions. Windows skips only Linux-specific checks when unavailable.
- Both browser suites pass, including expiry during password text selection.
  Passwords are absent from polling, CSV and persistent browser storage.
- PowerShell 5.1 checks pass for configuration, reporter behavior, unsafe paths,
  owner verification, log redaction and refusal to execute a mismatched MSI.
- **Bandit 1.9.4: no high/medium findings after review.** Remaining low findings
  are imports, fixed argument-list subprocess calls, expected network exceptions
  and `None` password sentinels. One documented B103 suppression covers the
  necessary root:service-group 0750 directory; its credential file is 0640.
- **Gitleaks 8.30.1: no detected secrets** in complete Git history/staged source,
  using redacted reports. This does not prove every possible secret is absent.
- The console uses no third-party Python runtime packages. pip-audit 2.10.1 checked
  the separate scanner environment; its bundled pip was upgraded to 26.2.1,
  leaving no reported advisories in that tool environment.

A least-privilege GitHub Actions workflow repeats Python/TLS tests, PowerShell
checks, Bandit, scanner-dependency auditing and full-history secret scans.
Actions are commit-pinned; the secret-scanner binary is pinned/checksum-verified.

## Limits and operating requirements

- This is a bounded review, not a guarantee of a vulnerability-free system.
  Bandit/pip-audit do not scan operating-system or RustDesk binaries for CVEs.
- Manage Ubuntu/OpenSSL/Samba/RustDesk updates separately. A private host report
  records available OS updates and services outside this repository.
- Keep the console on management networks. For broader exposure, place it behind
  a production reverse proxy with request deadlines/rate limits; Python's HTTP
  server has limited production hardening even with these application limits.
- Vault operations reject directories over 10,000 matching files; password lookups
  have a 15-second loop budget and scans have 45 seconds, plus an in-flight file/ACL
  operation's timeout. Large fleets need capacity planning before changing guards.
- Heartbeats and OS/name hints are observations, not signed identity proofs.
  A compromised PC controls its own report; owner checks prevent it from becoming
  another machine's NTFS owner, and duplicate ID claims are rejected.
- With blank `MsiSha256`, package trust depends on deployment-share administrators.
  Set an independently verified hash. RustDesk's password CLI transiently uses
  a process argument; local administrator/debug access must remain restricted.
- A GitHub release does not update running services or staged GPO scripts.
  Existing installations need the documented security update/migration.
