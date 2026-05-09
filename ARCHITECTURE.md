# Architecture

This document describes the internal structure of `oauth2-mock-server` for developers who want to understand how it works, extend it, or use its classes independently.

## Component overview

```
OAuth2Server
├── HttpServer          (HTTP/HTTPS lifecycle — start, stop, address)
├── OAuth2Service       (request handler + EventEmitter for all endpoints)
│   └── OAuth2Issuer    (JWT signing + issuer URL)
│       └── JWKStore    (JWK key pair management)
```

`OAuth2Server` is the main entry point. It wires the three core classes together and exposes a convenient API. All four classes are exported from the package root and can be used independently.

## Classes

### `OAuth2Server`

A convenience façade. Extends `HttpServer` and owns instances of `OAuth2Service` and `OAuth2Issuer`.

```ts
import { OAuth2Server } from 'oauth2-mock-server';

const server = new OAuth2Server(
  /* key?: string */,
  /* cert?: string */,
  /* oauth2Options?: OAuth2Options */
);

await server.start(8080, 'localhost');
// server.issuer  → OAuth2Issuer
// server.service → OAuth2Service
await server.stop();
```

**When to use `OAuth2Server`:** the typical case — you want a complete, ready-to-use OAuth2/OIDC server.

---

### `HttpServer`

A restartable wrapper around Node.js's built-in `node:http`/`node:https`. Accepts a `RequestListener` and optional TLS options.

```ts
import { HttpServer } from 'oauth2-mock-server';

const httpServer = new HttpServer(myRequestHandler, tlsOptions);
await httpServer.start(port, host);
await httpServer.stop();
```

**When to use `HttpServer` independently:** when you want to host a custom request handler with the same restartable lifecycle.

---

### `OAuth2Service`

The request handler for all OAuth2/OIDC endpoints. Extends `EventEmitter`. Composes an `OAuth2Issuer` instance.

```ts
import { OAuth2Issuer, OAuth2Service } from 'oauth2-mock-server';

const issuer = new OAuth2Issuer();
const service = new OAuth2Service(
  issuer /* endpoints?: OAuth2EndpointsInput */,
);

// service.requestHandler is a Node.js RequestListener
// service is an EventEmitter — attach hooks here
```

**When to use `OAuth2Service` independently (available since v8.1.0):** when you want to attach the OIDC handler to your own HTTP server, or compose multiple services on a single server.

#### Endpoints handled

| Route                                   | Handler                       |
| --------------------------------------- | ----------------------------- |
| `GET /.well-known/openid-configuration` | OpenID Provider Configuration |
| `GET /jwks`                             | JSON Web Key Set              |
| `POST /token`                           | Token issuance                |
| `GET /authorize`                        | Authorization code redirect   |
| `GET /userinfo`                         | Userinfo claims               |
| `POST /revoke`                          | Token revocation              |
| `GET /endsession`                       | End session redirect          |
| `POST /introspect`                      | Token introspection           |

All paths are configurable — see the `endpoints` option in `OAuth2Options`.

---

### `OAuth2Issuer`

Holds the issuer URL and manages the `JWKStore`. Signs JWTs using the `jose` library.

```ts
import { OAuth2Issuer } from 'oauth2-mock-server';

const issuer = new OAuth2Issuer();
issuer.url = 'http://localhost:8080';

await issuer.keys.generate('RS256');
const jwt = await issuer.buildToken({ scopesOrTransform: 'openid profile' });
```

**When to use `OAuth2Issuer` independently:** when you need to build tokens programmatically in tests without running an HTTP server.

---

### `JWKStore`

Manages a collection of JWK key pairs. Keys are selected in round-robin order when signing.

```ts
import { JWKStore } from 'oauth2-mock-server';

const store = new JWKStore();
await store.generate('ES256');
await store.add({ kid: 'my-key', alg: 'RS256', kty: 'RSA' /* ... */ });
const publicKeys = store.toJSON(); // public keys only
const allKeys = store.toJSON(true); // includes private key material
```

---

## Event flow: token signing

Understanding the event chain is important when writing `beforeTokenSigning` hooks.

```
POST /token
  └── OAuth2Service.tokenHandler
        ├── Parses request body, validates grant_type
        ├── Builds the transform function (xfn) for the grant type
        └── OAuth2Service.buildToken(req, expiresIn, xfn)
              └── OAuth2Issuer.once(InternalEvents.BeforeSigning, handler)
                    └── handler emits OAuth2Service#beforeTokenSigning(token, req)
                          ↑ ← user hook fires here, can mutate token.header / token.payload
              └── OAuth2Issuer.buildToken(opts)
                    ├── Selects a key from JWKStore (round-robin or by kid)
                    ├── Builds header { kid, alg } and payload { iss, iat, exp, nbf, ...xfn }
                    ├── Emits InternalEvents.BeforeSigning (triggers the chain above)
                    └── Signs the JWT with jose SignJWT → returns JWT string
```

The `beforeTokenSigning` event fires **once per JWT**, including once for the `access_token` and once for the `id_token` when both are issued.

---

## Source file map

| File                             | Role                                                                       |
| -------------------------------- | -------------------------------------------------------------------------- |
| `src/index.ts`                   | Public barrel — all library exports originate here                         |
| `src/oauth2-mock-server.ts`      | Binary entry point — delegates to `cli()` in `src/cli.ts`                  |
| `src/cli.ts`                     | CLI argument parsing and server startup; not part of the public API        |
| `src/lib/http-server.ts`         | `HttpServer` — restartable `node:http`/`node:https` wrapper                |
| `src/lib/jwk-store.ts`           | `JWKStore` — JWK key pair collection                                       |
| `src/lib/jwk-store.keys.ts`      | Algorithm registry (`supportedAlgs`) and public-key transformer — internal |
| `src/lib/oauth2-issuer.ts`       | `OAuth2Issuer` — issuer URL + JWT signing via `jose`                       |
| `src/lib/oauth2-service.ts`      | `OAuth2Service` — HTTP request handler and event emitter for all endpoints |
| `src/lib/oauth2-service.http.ts` | HTTP plumbing: body parsing, query parsing, route dispatch — internal      |
| `src/lib/oauth2-service.pkce.ts` | PKCE utilities: verifier validation and challenge verification — internal  |
| `src/lib/assertions.ts`          | Internal runtime assertion helpers                                         |
| `src/lib/types.ts`               | Public types and interfaces (exported via barrel)                          |
| `src/lib/types-internals.ts`     | Internal types not re-exported publicly                                    |

---

## Key dependency

[`jose`](https://www.npmjs.com/package/jose) is the only cryptographic dependency. It provides:

- `generateKeyPair` — async JWK key pair generation
- `importJWK` — loading a stored JWK for signing
- `SignJWT` — building and signing JWTs
- `exportJWK` — exporting a key as a plain JWK object
