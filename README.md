# `oauth2-mock-server`

> _OAuth 2 mock server. Intended to be used for development or testing purposes._

When developing an application that exposes or consumes APIs that are secured with an OAuth 2 authorization scheme, a mechanism for issuing access tokens is needed. Frequently, a developer needs to create custom code that fakes the creation of tokens for testing purposes, and these tokens cannot be properly verified, since there is no actual entity issuing those tokens.

The purpose of this package is to provide an easily configurable OAuth 2 server, that can be set up and teared down at will, and can be programatically run while performing automated tests.

> **Warning:** This tool is _not_ intended to be used as an actual OAuth 2 server. It lacks many features that would be required in a proper implementation.

## Development prerequisites

- [Node 8.0+](https://nodejs.org/)

## Attributions

- [`node-jose`](https://www.npmjs.com/package/node-jose), Copyright © Cisco Systems
