# Security boundaries

- Web service is unprivileged and sandboxed. The collector alone needs root for
  packet capture and hbbs database reads. TLS handshakes have separate workers/timeouts.
- Console account hashes, vault reader credentials and TLS keys are private
  runtime files outside Git. Console passwords use salted PBKDF2-SHA256; the vault
  contains workstation passwords on the DC, not in the application database.
- Protect the existing RustDesk server identity key and database from other local
  accounts. The key should be readable only by its actual service owner (0600).
  For a root-run native hbbs/hbbr installation, root ownership and UMask=0077 are
  appropriate; container or dedicated-user deployments need their own correct
  ownership. Do not blindly change ownership on another installation.
- Reveal requires HTTPS, an enabled Admin/Operator session, CSRF and rate limiting.
  Responses are no-store and reveal events identify the actual console user.
- Missing TLS never enables plaintext login. Audit entries must be written before
  releasing passwords. Values are escaped; logs rotate at 5 MiB with three backups.
  Reveals recheck revocation immediately before lookup.
- Passwords are absent from initial HTML, polling, CSV, application caches and logs.
  Collector name mapping reads the existing machine record, projects ID/name only,
  and discards its password. Reveal reads records on demand and does not cache them.
- Both vault records and session reports require the machine's NTFS computer-account
  owner in the configured AD NetBIOS domain. Unverifiable or mismatched ownership
  fails closed; file-change signatures invalidate metadata owner-cache entries.
- Duplicate RustDesk ID claims fail closed. Schema/size checks and no-follow reads
  reject malformed/redirected files; ACL queries explicitly require SMB encryption.
- SMB mounts are read-only and encrypted. A dedicated reader has only NTFS read/ACL
  permissions. Never use a Domain Admin password in the Linux credential file.
- Runtime configuration must be administrator-controlled. Public GPO configuration
  and scripts are readable by domain machines but writable only by deployment admins.
- No self-registration or AD SSO; only Admins create console users. The last active
  Admin is protected; role/password/enabled changes invalidate sessions.
- The repository excludes installers, vault/session records, local settings,
  credentials, private keys, databases and logs. Example domains/addresses are
  documentation values; replace them with the company's actual configuration.

This repository is public. Its history starts at release v2.0.4 and does not
include the earlier private component histories. Before committing, check that
no real company domain, address, hostname or credential enters the tree.

See the [security review](security-review-2026-10-15.md) for tests, corrections and
remaining deployment requirements.
