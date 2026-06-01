# Security Policy

## Scope

`oauth2-mock-server` is a **testing tool**, not a production security component. Its attack surface is intentionally minimal:

- It does not validate client credentials, user passwords, or token signatures on incoming requests.
- It does not store sensitive data beyond in-memory JWK key pairs.
- It is not intended to be exposed to the internet or run in production environments.

Security maintenance for this project focuses on **keeping dependencies free of known vulnerabilities**, rather than on hardening the server's OAuth2 behaviour.

## Supported versions

Only the latest published version on npm receives security fixes.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Open a [GitHub Security Advisory](https://github.com/axa-group/oauth2-mock-server/security/advisories/new) to report the issue confidentially. We will acknowledge the report and work with you to assess and address it.

Please include:

- A description of the vulnerability and its potential impact
- Full paths of affected source files
- Steps to reproduce
- Proof-of-concept or exploit code (if available)

You can expect an initial response within **7 days** and a resolution or mitigation plan within **30 days**.

## Dependency vulnerabilities

For a current view of known issues, use these independent scanners:

- [Snyk](https://security.snyk.io/package/npm/oauth2-mock-server)
- [Socket.dev](https://socket.dev/npm/package/oauth2-mock-server)
