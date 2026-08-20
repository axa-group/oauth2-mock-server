# `oauth2-mock-server`

[![npm package](https://img.shields.io/npm/v/oauth2-mock-server.svg?logo=npm)](https://www.npmjs.com/package/oauth2-mock-server)
[![Node.js version](https://img.shields.io/node/v/oauth2-mock-server.svg)](https://nodejs.org/)

> _OAuth 2 mock server. Intended to be used for development or testing purposes._

When developing an application that exposes or consumes APIs that are secured with an [OAuth 2](https://oauth.net/2/) authorization scheme, a mechanism for issuing access tokens is needed. Frequently, a developer needs to create custom code that fakes the creation of tokens for testing purposes, and these tokens cannot be properly verified, since there is no actual entity issuing those tokens.

The purpose of this package is to provide an easily configurable OAuth 2 server, that can be set up and torn down at will, and can be programmatically run while performing automated tests.

- **Real cryptography.** Tokens are signed with actual JWK key pairs. Consuming applications can verify them using the `/jwks` endpoint, without mocking the verification layer.
- **OIDC-conformant.** Exposes all the endpoints a real provider would: discovery, JWKS, authorization code flow with PKCE, userinfo, token introspection, revocation, and end session.
- **Programmatic and CLI.** Embed it in a JavaScript or TypeScript test suite (`beforeAll`/`afterAll`) or run it as a standalone process for Java, .NET, Python, and other non-JS projects.
- **Per-test customization via event hooks.** Use `server.service.once(Events.xxx, ...)` to alter token claims, simulate errors, or modify responses for a single test — without reconfiguring the server.
- **TypeScript-first.** Full type definitions ship with the package. The entire codebase is written in strict TypeScript.

> **Warning:** This tool is _not_ intended to be used as an actual production grade OAuth 2 server. It lacks many features that would be required in a proper implementation.

## Requirements

- [Node.js 22.12+](https://nodejs.org/)

## Installation

Add it to your Node.js project as a development dependency:

```sh
npm install --save-dev oauth2-mock-server
```

## CLI Usage

The server can be run from the command line.

```sh
npx oauth2-mock-server --help
```

## Library Usage

The server and its components can also be leveraged as a library, allowing finer control and configuration.

Here is an example for creating and running a server instance with a single random RSA key:

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

Any number of existing JSON-formatted keys can be added to the keystore.

```js
// Add an existing JWK key to the keystore
await server.issuer.keys.add({
  kid: 'some-key',
  alg: 'RS256',
  kty: 'RSA',
  // ...
});
```

JSON Web Tokens (JWT) can also be built programmatically:

```js
import axios from 'axios';

// Build a new token
let token = await server.issuer.buildToken();

// Call a remote API with the token
const response = await axios.get('https://server.example.com/api/endpoint', {
  headers: {
    authorization: `Bearer ${token}`,
  },
});
```

## HTTPS

To support HTTPS, an optional cert and key can be supplied to start the server with SSL/TLS using the in-built NodeJS [HTTPS](https://nodejs.org/api/https.html) module.

We recommend using a package to create a locally trusted certificate, like [mkcert](https://github.com/FiloSottile/mkcert).

```js
let server = new OAuth2Server(
  'test-assets/mock-auth/key.pem',  // Path to private key file
  'test-assets/mock-auth/cert.pem', // Path to public SSL/TLS certificate
);
```

> **Note:** Enabling HTTPS will also update the issuer URL to reflect the current protocol.

## Event Hooks

The library provides a convenient way, through event emitters, to programmatically customize the server processing. This is particularly useful when expecting the OIDC service to behave in a specific way for a single test.

The list of supported events is exported by the library for a guided usage.

```js
import { Events } from 'oauth2-mock-server';
// ...or in CommonJS style:
// const { Events } = require('oauth2-mock-server');
```

- **Events.BeforeTokenSigning**

  Typed signature: `(token: MutableToken, req: TokenRequestIncomingMessage) => void`

  ```js
  // Modify the expiration time on next produced token
  server.service.once(Events.BeforeTokenSigning, (token, req) => {
    const timestamp = Math.floor(Date.now() / 1000);
    token.payload.exp = timestamp + 400;
  });
  ```

  ```js
  import { parse } from 'basic-auth';

  // Add the client ID to a token
  server.service.once(Events.BeforeTokenSigning, (token, req) => {
    const credentials = parse(req.headers.authorization ?? '');
    const clientId = credentials ? credentials.name : req.body.client_id;
    token.payload.client_id = clientId;
  });
  ```

- **Events.BeforeResponse**

  Typed signature: `(tokenEndpointResponse: MutableResponse, req: TokenRequestIncomingMessage) => void`

  ```js
  // Force the oidc service to provide an invalid_grant response
  // on next call to the token endpoint
  server.service.once(Events.BeforeResponse, (tokenEndpointResponse, req) => {
    tokenEndpointResponse.body = {
      error: 'invalid_grant',
    };
    tokenEndpointResponse.statusCode = 400;
  });
  ```

- **Events.BeforeUserinfo**

  Typed signature: `(userInfoResponse: MutableResponse, req: IncomingMessage) => void`

  ```js
  // Force the oidc service to provide an error
  // on next call to userinfo endpoint
  server.service.once(Events.BeforeUserinfo, (userInfoResponse, req) => {
    userInfoResponse.body = {
      error: 'invalid_token',
      error_description: 'token is expired',
    };
    userInfoResponse.statusCode = 401;
  });
  ```

- **Events.BeforeRevoke**

  Typed signature: `(revokeResponse: StatusCodeMutableResponse, req: IncomingMessage) => void`

  ```js
  // Simulates a custom token revocation result code
  server.service.once(Events.BeforeRevoke, (revokeResponse, req) => {
    revokeResponse.statusCode = 418;
  });
  ```

- **Events.BeforeAuthorizeRedirect**

  Typed signature: `(authorizeRedirectUri: MutableRedirectUri, req: IncomingMessage) => void`

  ```js
  // Modify the uri and query parameters
  // before the authorization redirect
  server.service.once(Events.BeforeAuthorizeRedirect, (authorizeRedirectUri, req) => {
    authorizeRedirectUri.url.searchParams.set('foo', 'bar');
  });
  ```

- **Events.BeforePostLogoutRedirect**

  Typed signature: `(postLogoutRedirectUri: MutableRedirectUri, req: IncomingMessage) => void`

  ```js
  // Modify the uri and query parameters
  // before the post_logout_redirect_uri redirect
  server.service.once(Events.BeforePostLogoutRedirect, (postLogoutRedirectUri, req) => {
    postLogoutRedirectUri.url.searchParams.set('foo', 'bar');
  });
  ```

- **Events.BeforeIntrospect**

  Typed signature: `(introspectResponse: MutableResponse, req: IncomingMessage) => void`

  ```js
  // Simulate a custom token introspection response body
  server.service.once(Events.BeforeIntrospect, (introspectResponse, req) => {
    introspectResponse.body = {
      active: true,
      scope: 'read write email',
      client_id: '<client_id>',
      username: 'dummy',
      exp: 1643712575,
    };
  });
  ```

## Endpoints

### Standard endpoints

| Endpoint                                 | Description                                                                                                                                                                                                   |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET  /.well-known/openid-configuration` | Returns the [OpenID Provider Configuration Information](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) for the server.                                                            |
| `GET  /jwks`                             | Returns the JSON Web Key Set (JWKS) of all the keys configured in the server.                                                                                                                                 |
| `POST /token`                            | Issues access tokens.                                                                                                                                                                                         |
| `GET  /authorize`                        | Simulates user authentication. Automatically redirects to the callback endpoint. Supports only the `code` response type.                                                                                      |
| `GET  /userinfo`                         | Provides extra userinfo claims.                                                                                                                                                                               |
| `POST /revoke`                           | Simulates token revocation. Always returns 200 per [RFC 7009](https://tools.ietf.org/html/rfc7009#section-2.2).                                                                                               |
| `GET  /endsession`                       | Simulates the end session endpoint. When `post_logout_redirect_uri` is provided, redirects to it (appending `state` if supplied). When absent or empty, returns a `200` success response without redirecting. |
| `POST /introspect`                       | Simulates the [token introspection endpoint](https://www.oauth.com/oauth2-servers/token-introspection-endpoint/).                                                                                             |

### Path overrides

All endpoint paths can be overridden via the `endpoints` option. Handy when willing to mimic some vendors default configuration.
All fields are optional; any omitted path falls back to its default.

```js
const oAuth2Service = new OAuth2Service(oauth2Issuer, {
  // As 'wellKnownDocument' is purposefully omitted, it will be set to its default,
  token: '/oauth/token',
  jwks: '/oauth/jwks',
  authorize: '/oauth/authorize',
  userinfo: '/oauth/userinfo',
  revoke: '/oauth/revoke',
  endSession: '/oauth/logout',
  introspect: '/oauth/introspect',
});
```

### Custom routes

Additional routes can be registered via `addRoute()`. This may be useful when willing to stub vendor specific management routes, for instance

```js
oAuth2Service.addRoute('POST', '/api/v2/clients', (req, res) => {
  // Your custom implementation goes here
});
```

## Reference

### Supported grant types

- No authentication
- Client Credentials grant
- Resource Owner Password Credentials grant
- Authorization Code grant, with Proof Key for Code Exchange (PKCE) support
- Refresh token grant
- JWT Bearer token grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`)

### Supported JWK formats

| Crypto scheme     | `kty` | `alg`               |
| ----------------- | ----- | ------------------- |
| RSASSA-PKCS1-v1_5 | RSA   | RS256, RS384, RS512 |
| RSASSA-PSS        | RSA   | PS256, PS384, PS512 |
| ECDSA             | EC    | ES256, ES384, ES512 |
| EdDSA             | OKP   | EdDSA, Ed25519      |

## Security

Tokens issued by this server are signed with real cryptographic keys and can be verified by any standard JWT library. However, the server performs **no validation of incoming requests** — any client ID, secret, username, or password is accepted. This is intentional for testing purposes.

**This library is not safe for production use.**

Review the Security Policy in [SECURITY.md](./SECURITY.md) for more details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, coding conventions, and the pull request process.

AI coding agents working in this repository should read [AGENTS.md](./AGENTS.md) before making any changes.

## Attributions

- [`jose`](https://www.npmjs.com/package/jose)
