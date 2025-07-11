# `oauth2-mock-server`

[![npm package](https://img.shields.io/npm/v/oauth2-mock-server.svg?logo=npm)](https://www.npmjs.com/package/oauth2-mock-server)
[![Node.js version](https://img.shields.io/node/v/oauth2-mock-server.svg)](https://nodejs.org/)

> _OAuth 2 mock server. Intended to be used for development or testing purposes._

When developing an application that exposes or consumes APIs that are secured with an [OAuth 2](https://oauth.net/2/) authorization scheme, a mechanism for issuing access tokens is needed. Frequently, a developer needs to create custom code that fakes the creation of tokens for testing purposes, and these tokens cannot be properly verified, since there is no actual entity issuing those tokens.

The purpose of this package is to provide an easily configurable OAuth 2 server, that can be set up and teared down at will, and can be programmatically run while performing automated tests.

> **Warning:** This tool is _not_ intended to be used as an actual production grade OAuth 2 server. It lacks many features that would be required in a proper implementation.

## Development prerequisites

- [Node.js 20.19+](https://nodejs.org/)

## How to use

### Installation

Add it to your Node.js project as a development dependency:

```shell
npm install --save-dev oauth2-mock-server
```

### Quickstart

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

JSON Web Tokens (JWT) can be built programmatically:

```js
import axios from 'axios';

// Build a new token
let token = await server.issuer.buildToken();

// Call a remote API with the token
axios
  .get('https://server.example.com/api/endpoint', {
    headers: {
      authorization: `Bearer ${token}`,
    },
  })
  .then((response) => {
    /* ... */
  })
  .catch((error) => {
    /* ... */
  });
```

### Supported grant types

- No authentication
- Client Credentials grant
- Resource Owner Password Credentials grant
- Authorization Code grant, with Proof Key for Code Exchange (PKCE) support
- Refresh token grant

### Supported JWK formats

| Algorithm         | kty | alg                 |
| ----------------- | --- | ------------------- |
| RSASSA-PKCS1-v1_5 | RSA | RS256, RS384, RS512 |
| RSASSA-PSS        | RSA | PS256, PS384, PS512 |
| ECDSA             | EC  | ES256, ES384, ES512 |
| EdDSA             | OKP | Ed25519             |

### Customization hooks

It also provides a convenient way, through event emitters, to programmatically customize the server processing. This is particularly useful when expecting the OIDC service to behave in a specific way on one single test:

- The JWT access token

  ```js
  // Modify the expiration time on next token produced
  service.once('beforeTokenSigning', (token, req) => {
    const timestamp = Math.floor(Date.now() / 1000);
    token.payload.exp = timestamp + 400;
  });
  ```

  ```js
  const basicAuth = require('basic-auth');

  // Add the client ID to a token
  service.once('beforeTokenSigning', (token, req) => {
    const credentials = basicAuth(req);
    const clientId = credentials ? credentials.name : req.body.client_id;
    token.payload.client_id = clientId;
  });
  ```

- The token endpoint response body and status

  ```js
  // Force the oidc service to provide an invalid_grant response
  // on next call to the token endpoint
  service.once('beforeResponse', (tokenEndpointResponse, req) => {
    tokenEndpointResponse.body = {
      error: 'invalid_grant',
    };
    tokenEndpointResponse.statusCode = 400;
  });
  ```

- The userinfo endpoint response body and status

  ```js
  // Force the oidc service to provide an error
  // on next call to userinfo endpoint
  service.once('beforeUserinfo', (userInfoResponse, req) => {
    userInfoResponse.body = {
      error: 'invalid_token',
      error_message: 'token is expired',
    };
    userInfoResponse.statusCode = 401;
  });
  ```

- The revoke endpoint response body and status

  ```js
  // Simulates a custom token revocation body
  service.once('beforeRevoke', (revokeResponse, req) => {
    revokeResponse.body = {
      result: 'revoked',
    };
  });
  ```

- The authorization endpoint redirect uri and query parameters

  ```js
  // Modify the uri and query parameters
  // before the authorization redirect
  service.once('beforeAuthorizeRedirect', (authorizeRedirectUri, req) => {
    authorizeRedirectUri.url.searchParams.set('foo', 'bar');
  });
  ```

- The end session endpoint post logout redirect uri

  ```js
  // Modify the uri and query parameters
  // before the post_logout_redirect_uri redirect
  service.once('beforePostLogoutRedirect', (postLogoutRedirectUri, req) => {
    postLogoutRedirectUri.url.searchParams.set('foo', 'bar');
  });
  ```

- The introspect endpoint response body

  ```js
  // Simulate a custom token introspection response body
  service.once('beforeIntrospect', (introspectResponse, req) => {
    introspectResponse.body = {
      active: true,
      scope: 'read write email',
      client_id: '<client_id>',
      username: 'dummy',
      exp: 1643712575,
    };
  });
  ```

### HTTPS support

It also provides basic HTTPS support, an optional cert and key can be supplied to start the server with SSL/TLS using the in-built NodeJS [HTTPS](https://nodejs.org/api/https.html) module.

We recommend using a package to create a locally trusted certificate, like [mkcert](https://github.com/FiloSottile/mkcert).

```js
let server = new OAuth2Server(
  'test-assets/mock-auth/key.pem',
  'test-assets/mock-auth/cert.pem'
);
```

NOTE: Enabling HTTPS will also update the issuer URL to reflect the current protocol.

## Supported endpoints

### GET `/.well-known/openid-configuration`

Returns the [OpenID Provider Configuration Information](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) for the server.

### GET `/jwks`

Returns the JSON Web Key Set (JWKS) of all the keys configured in the server.

### POST `/token`

Issues access tokens.

### GET `/authorize`

It simulates the user authentication. It will automatically redirect to the callback endpoint sent as parameter.
It currently supports only 'code' response_type.

### GET `/userinfo`

It provides extra userinfo claims.

### POST `/revoke`

It simulates a token revocation. This endpoint should always return 200 as stated by [RFC 7009](https://tools.ietf.org/html/rfc7009#section-2.2).

### GET `/endsession`

It simulates the end session endpoint. It will automatically redirect to the post_logout_redirect_uri sent as parameter.

### POST `/introspect`

It simulates the [token introspection endpoint](https://www.oauth.com/oauth2-servers/token-introspection-endpoint/).

## Command-Line Interface

The server can be run from the command line.

```shell
npx oauth2-mock-server --help
```

## Attributions

- [`jose`](https://www.npmjs.com/package/jose)
