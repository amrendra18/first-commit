# Security policy

## Reporting

Report a vulnerability privately through GitHub: open the repository's
Security tab and choose "Report a vulnerability". Do not open a public issue
for a vulnerability, and never put credentials, private values, or exploit
details in a public issue. Fixes target the latest release.

## Limits

Local hooks reduce the risk of accidental publication. They do not prove a
repository is safe: hooks can be bypassed, scanners miss some secrets, and
signing settings do not verify signatures. Shared repositories also need
server-side rules and hosted secret scanning. [ARCHITECTURE.md](ARCHITECTURE.md#threats-and-known-gaps)
lists the known gaps.

## Exposed credentials

Revoke an exposed credential at its issuer and replace it. Deleting a file or
rewriting history does not revoke it.
