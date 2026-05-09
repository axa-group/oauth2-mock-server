# `oauth2-mock-server`

[![npm package](https://img.shields.io/npm/v/oauth2-mock-server.svg?logo=npm)](https://www.npmjs.com/package/oauth2-mock-server)
[![Node.js version](https://img.shields.io/node/v/oauth2-mock-server.svg)](https://nodejs.org/)
[![Build & test](https://github.com/axa-group/oauth2-mock-server/actions/workflows/main.yml/badge.svg)](https://github.com/axa-group/oauth2-mock-server/actions/workflows/main.yml)

> _OAuth 2 mock server. Intended to be used for development or testing purposes._

> **Warning:** This tool is _not_ intended to be used as an actual production grade OAuth 2 server. It lacks many features that would be required in a proper implementation.

## Table of Contents

- [Why this library?](#why-this-library)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [How to use](#how-to-use)
  - [Supported grant types](#supported-grant-types)
  - [Supported JWK formats](#supported-jwk-formats)
  - [Customization hooks](#customization-hooks)
  - [Custom endpoint paths](#custom-endpoint-paths)
  - [HTTPS support](#https-support)
- [Supported endpoints](#supported-endpoints)
- [Command-Line Interface](#command-line-interface)
- [Architecture](#architecture)
- [Default token claims](#default-token-claims)
- [Known limitations](#known-limitations)
- [Using in your project](#using-in-your-project)
- [Security](#security)
- [Contributing](#contributing)
- [Changelog & Migration](#changelog--migration)
- [Attributions](#attributions)

## Why this library?

- **Real cryptography.** Tokens are signed with actual JWK key pairs — consuming applications can verify them using the `/jwks` endpoint, without mocking the verification layer.
- **OIDC-conformant.** Exposes all the endpoints a real provider would: discovery, JWKS, authorization code flow with PKCE, userinfo, token introspection, revocation, and end session.
- **Per-test customization via event hooks.** Use `server.service.once(Events.BeforeTokenSigning, ...)` to alter token claims, simulate errors, or modify responses for a single test — without reconfiguring the server.
- **Programmatic and CLI.** Embed it in a JavaScript or TypeScript test suite (`beforeAll`/`afterAll`) or run it as a standalone process for Java, .NET, Python, and other non-JS projects.
- **TypeScript-first.** Full type definitions ship with the package. The entire codebase is written in strict TypeScript.

## Requirements

- [Node.js ^20.19, ^22.12, or ^24](https://nodejs.org/)

## Installation

Add it to your project as a development dependency:

```sh
npm install --save-dev oauth2-mock-server
```

**ESM and CommonJS:** this package ships as Universal ESM. Both `import` (ESM) and `require()` (CommonJS) work on Node.js ≥ 20.19 — no extra configuration needed.

## Quickstart

Create a server with a single random RSA key:

```js
import { OAuth2Server } from 'oauth2-mock-server';
// ...or in CommonJS style:
// const { OAuth2Server } = require('oauth2-mock-server');

let server = new OAuth2Server();

// Generate a new RSA key and add it to the keystore
await server.issuer.keys.generate('RS256');

// Start the server
await server.start(8080, 'localhost');
console.log('Issuer URL:', server.issuer.url); // -> http://localhost:8080

// Do some work with the server
// ...

// Stop the server
await server.stop();
```

Any number of existing JSON-formatted keys can be added to the keystore:

```js
await server.issuer.keys.add({
  kid: 'some-key',
  alg: 'RS256',
  kty: 'RSA',
  // ...
});
```

Tokens can also be built programmatically without going through the HTTP layer:

```js
import axios from 'axios';

let token = await server.issuer.buildToken();

axios.get('https://server.example.com/api/endpoint', {
  headers: { authorization: `Bearer ${token}` },
});
```

## How to use

### Supported grant types

| Grant type                           | `grant_type` value                   |
| ------------------------------------ | ------------------------------------ |
| Direct token building (no HTTP flow) | _(use `server.issuer.buildToken()`)_ |
| Client Credentials                   | `client_credentials`                 |
| Resource Owner Password Credentials  | `password`                           |
| Authorization Code (+ PKCE)          | `authorization_code`                 |
| Refresh Token                        | `refresh_token`                      |

### Supported JWK formats

| Crypto scheme     | `kty` | `alg`               |
| ----------------- | ----- | ------------------- |
| RSASSA-PKCS1-v1_5 | RSA   | RS256, RS384, RS512 |
| RSASSA-PSS        | RSA   | PS256, PS384, PS512 |
| ECDSA             | EC    | ES256, ES384, ES512 |
| EdDSA             | OKP   | EdDSA, Ed25519      |

### Customization hooks

`OAuth2Service` (accessible as `server.service`) is an `EventEmitter`. Use `service.on()` for persistent hooks or `service.once()` for a single-test override.

TypeScript users can import the `Events` enum to avoid raw strings:

```ts
import { Events } from 'oauth2-mock-server';

server.service.once(Events.BeforeTokenSigning, (token, req) => {
  /* ... */
});
```

#### beforeTokenSigning

Typed signature: `(token: MutableToken, req: TokenRequestIncomingMessage) => void`

Fires before each JWT is signed. Mutate `token.header` or `token.payload` to change the output.

```js
// Modify the expiration time on the next produced token
server.service.once('beforeTokenSigning', (token, req) => {
  const timestamp = Math.floor(Date.now() / 1000);
  token.payload.exp = timestamp + 400;
});
```

```js
import basicAuth from 'basic-auth';

// Add the client ID to a token
server.service.once('beforeTokenSigning', (token, req) => {
  const credentials = basicAuth(req);
  const clientId = credentials ? credentials.name : req.body.client_id;
  token.payload.client_id = clientId;
});
```

#### beforeResponse

Typed signature: `(tokenEndpointResponse: MutableResponse, req: TokenRequestIncomingMessage) => void`

```js
// Force the token endpoint to return an error on the next request
server.service.once('beforeResponse', (tokenEndpointResponse, req) => {
  tokenEndpointResponse.body = { error: 'invalid_grant' };
  tokenEndpointResponse.statusCode = 400;
});
```

#### beforeUserinfo

Typed signature: `(userInfoResponse: MutableResponse, req: IncomingMessage) => void`

```js
server.service.once('beforeUserinfo', (userInfoResponse, req) => {
  userInfoResponse.body = {
    error: 'invalid_token',
    error_message: 'token is expired',
  };
  userInfoResponse.statusCode = 401;
});
```

#### beforeRevoke

Typed signature: `(revokeResponse: StatusCodeMutableResponse, req: IncomingMessage) => void`

```js
server.service.once('beforeRevoke', (revokeResponse, req) => {
  revokeResponse.statusCode = 418;
});
```

#### beforeAuthorizeRedirect

Typed signature: `(authorizeRedirectUri: MutableRedirectUri, req: IncomingMessage) => void`

```js
server.service.once('beforeAuthorizeRedirect', (authorizeRedirectUri, req) => {
  authorizeRedirectUri.url.searchParams.set('foo', 'bar');
});
```

#### beforePostLogoutRedirect

Typed signature: `(postLogoutRedirectUri: MutableRedirectUri, req: IncomingMessage) => void`

```js
server.service.once(
  'beforePostLogoutRedirect',
  (postLogoutRedirectUri, req) => {
    postLogoutRedirectUri.url.searchParams.set('foo', 'bar');
  },
);
```

#### beforeIntrospect

Typed signature: `(introspectResponse: MutableResponse, req: IncomingMessage) => void`

```js
server.service.once('beforeIntrospect', (introspectResponse, req) => {
  introspectResponse.body = {
    active: true,
    scope: 'read write email',
    client_id: '<client_id>',
    username: 'dummy',
    exp: 1643712575,
  };
});
```

### Custom endpoint paths

All endpoint paths can be overridden via the `endpoints` option. Any omitted paths fall back to their defaults.

```js
const server = new OAuth2Server(undefined, undefined, {
  endpoints: {
    wellKnownDocument: '/.well-known/openid-configuration',
    token: '/oauth/token',
    jwks: '/oauth/jwks',
    authorize: '/oauth/authorize',
    userinfo: '/oauth/userinfo',
    revoke: '/oauth/revoke',
    endSession: '/oauth/logout',
    introspect: '/oauth/introspect',
  },
});
```

### HTTPS support

Pass paths to a PEM certificate and key file to enable HTTPS. We recommend [mkcert](https://github.com/FiloSottile/mkcert) to create a locally trusted certificate.

```js
let server = new OAuth2Server(
  'test-assets/mock-auth/key.pem',
  'test-assets/mock-auth/cert.pem',
);
```

Enabling HTTPS also updates the issuer URL to use `https://`.

## Supported endpoints

| Endpoint                            | Method | Description                                                                                                  |
| ----------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------ |
| `/.well-known/openid-configuration` | `GET`  | [OpenID Provider Configuration](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)   |
| `/jwks`                             | `GET`  | JSON Web Key Set of all configured keys                                                                      |
| `/token`                            | `POST` | Issues access tokens (and `id_token` + `refresh_token` for non-`client_credentials` grants)                  |
| `/authorize`                        | `GET`  | Simulates user authentication; redirects to `redirect_uri` with an authorization code                        |
| `/userinfo`                         | `GET`  | Returns userinfo claims                                                                                      |
| `/revoke`                           | `POST` | Simulates token revocation; always returns 200 ([RFC 7009](https://tools.ietf.org/html/rfc7009#section-2.2)) |
| `/endsession`                       | `GET`  | Simulates end session; redirects to `post_logout_redirect_uri`; echoes `state` if provided                   |
| `/introspect`                       | `POST` | Simulates [token introspection](https://www.oauth.com/oauth2-servers/token-introspection-endpoint/)          |

All paths are configurable — see [Custom endpoint paths](#custom-endpoint-paths).

## Command-Line Interface

The server can be run directly without writing any code:

```sh
npx oauth2-mock-server [options]
```

| Option                        | Description                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------- |
| `-h`, `--help`                | Show help                                                                             |
| `-a <address>`                | Address to listen on. Defaults to `[::]` (IPv6) or `0.0.0.0` if IPv6 is unavailable   |
| `-p <port>`                   | TCP port to listen on. Defaults to `8080`. Use `0` for an OS-assigned port            |
| `--issuer-url-trailing-slash` | Append a trailing slash to the issuer URL                                             |
| `-c <cert>`                   | Path to an SSL certificate file. Both `-c` and `-k` must be supplied to enable HTTPS  |
| `-k <key>`                    | Path to an SSL key file. Both `-c` and `-k` must be supplied to enable HTTPS          |
| `--jwk <filename>`            | Load a JSON-formatted JWK key file into the keystore. May be specified multiple times |
| `--save-jwk`                  | Save all keys in the keystore as `<kid>.json` files                                   |

If no `--jwk` keys are provided, a random RSA key is generated automatically. Use `--save-jwk` to persist it for later reuse across runs.

## Architecture

The library is composed of three independently usable classes that `OAuth2Server` combines into a ready-to-use façade:

- **`OAuth2Server`** — HTTP server lifecycle wrapper (start, stop, address). Extends `HttpServer`.
- **`OAuth2Service`** — request handler and `EventEmitter` for all OAuth2/OIDC endpoints. Composes `OAuth2Issuer`.
- **`OAuth2Issuer`** — JWT signing and key store management. Wraps `JWKStore`.

`HttpServer`, `OAuth2Service`, and `OAuth2Issuer` are all exported and can be used independently (available since v8.1.0).

See [ARCHITECTURE.md](./ARCHITECTURE.md) for a full component diagram, event flow, and guidance on using the classes independently.

## Default token claims

The `/token` endpoint sets the following claims automatically. Use a [`beforeTokenSigning`](#beforetokensigning) hook to override any of them.

### Access token

| Claim   | `client_credentials` | `password`            | `authorization_code`              | `refresh_token`                   |
| ------- | -------------------- | --------------------- | --------------------------------- | --------------------------------- |
| `iss`   | issuer URL           | issuer URL            | issuer URL                        | issuer URL                        |
| `iat`   | now                  | now                   | now                               | now                               |
| `exp`   | now + 3600 s         | now + 3600 s          | now + 3600 s                      | now + 3600 s                      |
| `nbf`   | now − 10 s           | now − 10 s            | now − 10 s                        | now − 10 s                        |
| `sub`   | —                    | username from request | `'johndoe'` ¹                     | `'johndoe'` ¹                     |
| `amr`   | —                    | `['pwd']`             | `['pwd']`                         | `['pwd']`                         |
| `scope` | from request         | from request          | from request (default: `'dummy'`) | from request (default: `'dummy'`) |
| `aud`   | from request         | —                     | —                                 | —                                 |

¹ Hardcoded. Use a `beforeTokenSigning` hook to set a dynamic subject.

### ID token and refresh token

All grants except `client_credentials` also return an `id_token` JWT and a `refresh_token` opaque string.

| Claim                      | Value                                                                              |
| -------------------------- | ---------------------------------------------------------------------------------- |
| `iss`, `iat`, `exp`, `nbf` | Same as access token                                                               |
| `sub`                      | `'johndoe'`                                                                        |
| `aud`                      | Client ID from `Authorization: Basic` header, or `client_id` from the request body |
| `nonce`                    | Echoed from the original `/authorize` request (authorization code flow only)       |

## Known limitations

These are deliberate simplifications. Use [event hooks](#customization-hooks) to work around most of them in specific tests.

- **Hardcoded subject.** `sub` is always `'johndoe'` for `authorization_code` and `refresh_token` grants (and in the `id_token` for all non-`client_credentials` grants).
- **No real user store.** Any `username`/`password` combination is accepted for the `password` grant.
- **No client authentication.** Any `client_id` and `client_secret` combination is accepted.
- **No scope validation.** Any scope string is accepted without checking.
- **No refresh token rotation.** Refresh tokens are random UUIDs that the server does not track; a new one is issued on every `/token` request.
- **Authorization code flow only.** The `/authorize` endpoint only supports `response_type=code`. Implicit and hybrid flows are not supported.
- **OIDC discovery understates algorithm support.** The `/.well-known/openid-configuration` document reports `id_token_signing_alg_values_supported: ['RS256']` regardless of which algorithms are actually loaded in the keystore.

## Using in your project

- **JS/TS test suite** — see [INTEGRATION.md § JS/TS test suite](./INTEGRATION.md#jsts-test-suite) for `beforeAll`/`afterAll` lifecycle examples with Vitest, Jest, and Mocha.
- **Non-JS project (Java, .NET, Python, etc.)** — see [INTEGRATION.md § Non-JS projects](./INTEGRATION.md#non-js-projects) for CLI setup, key management, and issuer URL handoff via environment variable.
- **CI pipeline** — see [INTEGRATION.md § CI pipeline](./INTEGRATION.md#ci-pipeline) for cross-platform patterns using `start-server-and-test` (zero scripting) or a Node.js orchestrator script (dynamic port support).

## Security

Tokens issued by this server are signed with real cryptographic keys and can be verified by any standard JWT library. However, the server performs **no validation of incoming requests** — any client ID, secret, username, or password is accepted. This is intentional for testing purposes.

**This library is not safe for production use.**

For dependency vulnerability reports and supply-chain analysis:

- [Snyk](https://security.snyk.io/package/npm/oauth2-mock-server) — CVE scan of the package and its dependency tree
- [Socket.dev](https://socket.dev/npm/package/oauth2-mock-server) — supply-chain analysis
- [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/axa-group/oauth2-mock-server) — repository security practices
- [OSV.dev](https://osv.dev/list?ecosystem=npm&q=oauth2-mock-server) — open vulnerability database

To report a vulnerability, see [SECURITY.md](./SECURITY.md).

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, coding conventions, and the pull request process.

AI coding agents working in this repository should read [AGENTS.md](./AGENTS.md) before making any changes.

## Changelog & Migration

- [CHANGELOG.md](./CHANGELOG.md) — full release history
- [MIGRATION.md](./MIGRATION.md) — breaking change guides between major versions

## Attributions

- [`jose`](https://www.npmjs.com/package/jose)
