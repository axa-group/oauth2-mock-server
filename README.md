# `oauth2-mock-server`

> _OAuth 2 mock server. Intended to be used for development or testing purposes._

When developing an application that exposes or consumes APIs that are secured with an OAuth 2 authorization scheme, a mechanism for issuing access tokens is needed. Frequently, a developer needs to create custom code that fakes the creation of tokens for testing purposes, and these tokens cannot be properly verified, since there is no actual entity issuing those tokens.

The purpose of this package is to provide an easily configurable OAuth 2 server, that can be set up and teared down at will, and can be programatically run while performing automated tests.

> **Warning:** This tool is _not_ intended to be used as an actual OAuth 2 server. It lacks many features that would be required in a proper implementation.

## Development prerequisites

- [Node 8.0+](https://nodejs.org/)

## How to use

Add it to your Node.js project as a development dependency:

```shell
npm install --save-dev oauth2-mock-server
```

Here is an example for creating and running a server instance with a single random RSA key:

```js
const OAuth2Server = require('oauth2-mock-server');

let server = new OAuth2Server();

// Generate a new RSA key and add it to the keystore
await server.issuer.keys.generateRSA();

// Start the server
await server.start(8080, 'localhost');
console.log('Issuer URL:', server.issuer.url); // -> http://localhost:8080

// Do some work with the server
// ...

// Stop the server
await server.stop();
```

Any number of existing JSON-formatted or PEM-encoded keys can be added to the keystore:

```js
// Add an existing JWK key to the keystore
await server.issuer.keys.add({
    kid: 'some-key',
    kty: 'RSA',
    // ...
});

// Add an existing PEM-encoded key to the keystore
const fs = require('fs');

let pemKey = fs.readFileSync('some-key.pem');
await server.issuer.keys.addPEM(pemKey, 'some-key');
```

JSON Web Tokens (JWT) can be built programatically:

```js
const request = require('request');

// Build a new token
let token = server.issuer.buildToken(true);

// Call a remote API with the token
request.get(
    'https://server.example.com/api/endpoint',
    { auth: { bearer: token } },
    function callback(err, res, body) { /* ... */ }
);
```

## Supported endpoints

### GET `/.well-known/openid-configuration`

Returns the [OpenID Provider Configuration Information](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) for the server.

### GET `/jwks`

Returns the JSON Web Key Set (JWKS) of all the keys configured in the server.

### POST `/token`

Issues access tokens. Currently, this endpoint is limited to:

- No authentication
- Client Credentials grants only

## Command-Line Interface

The server can be run from the command line. Run `oauth2-mock-server --help` for details on its utilization.

## Attributions

- [`node-jose`](https://www.npmjs.com/package/node-jose), Copyright © Cisco Systems
