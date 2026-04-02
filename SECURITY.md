# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in `@agent-receipts/sdk-ts`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following private channels:

- Use GitHub's **"Report a vulnerability"** feature for this repository (via **Security > Report a vulnerability**); or
- Email **otto@0tt0.net** with:
  - A description of the vulnerability
  - Steps to reproduce or a proof of concept
  - The impact you believe it has

You should receive an acknowledgement within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

The following are in scope for security reports:

- Signature forgery or bypass in receipt creation/verification
- Hash chain integrity violations
- Key material leakage
- SQL injection or other input-handling flaws in the SQLite store
- Canonicalization (RFC 8785) edge cases that could lead to hash collisions

## Disclosure Policy

- We aim to confirm and triage reports within 48 hours.
- We will coordinate a fix and release timeline with the reporter.
- We credit reporters in the release notes unless they prefer to remain anonymous.
- We ask that you give us reasonable time to address the issue before public disclosure.
