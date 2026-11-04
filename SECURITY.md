# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email [support@flotte.sh](mailto:support@flotte.sh) with:

- A description of the vulnerability
- Steps to reproduce the issue
- Any potential impact

We will acknowledge your report within 48 hours and work with you to understand and resolve the issue promptly.

The full policy, including scope, coordinated disclosure timelines, and good-faith research assurances, is at <https://docs.flotte.sh/security>.

## Supported Versions

Security updates are provided for each released version for at least five years from its release. Vulnerabilities are remediated in the most recent release; if you run an older version within its support period, upgrade to the most recent release to receive the fix.

## Security Considerations

This module operates in a security-sensitive context (PAM authentication and sudo authorization). Key security properties:

- The binary must be owned by root and not writable by group or others.
- The `/run/flotte/` directory and all auth files must be owned by root.
- SSH certificate extension matching is case-sensitive and exact.
- Process start times are validated to prevent PID reuse attacks.
- Stale auth files are swept during verification.
