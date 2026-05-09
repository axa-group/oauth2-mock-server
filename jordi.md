## Issue: `token_endpoint_auth_methods_supported: ['none']` may break strict OAuth2 clients

The OpenID Configuration endpoint currently advertises:

```json
"token_endpoint_auth_methods_supported": ["none"]
```

This field is **optional** per [OIDC Discovery §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata). When omitted, the spec defines a default of `client_secret_basic`. The current explicit `['none']` therefore actively signals to clients that only public (unauthenticated) clients are supported.

In practice, most client libraries ignore this field and work fine. However, stricter enterprise/security-focused clients that validate the advertised methods against their configured auth method may refuse to proceed — silently misconfiguring or outright failing tests — when they're configured with `client_secret_basic` or `client_secret_post`.

Note: the mock server doesn't actually _enforce_ any authentication method regardless of what is advertised here.

**Options:**

1. **Drop the field** — defers to the spec default (`client_secret_basic`), fixes strict Basic-auth clients, minimal change.
2. **Advertise `['client_secret_basic', 'client_secret_post', 'none']`** — maximises compatibility across all client configurations; overstates capabilities but inconsequential for a mock.
3. **Keep `['none']`** — status quo; honest about enforcement (none), but risks breaking strict clients.

For a mock whose goal is to be usable out-of-the-box by as many clients as possible, option 2 seems most pragmatic. Option 1 is simpler but shifts the risk from Basic-auth clients to public clients.

## `id_token_signing_alg_values_supported` hardcodes `['RS256']` regardless of loaded keys

**Context**

The OIDC discovery document (`/.well-known/openid-configuration`) always advertises:

```json
"id_token_signing_alg_values_supported": ["RS256"],
"token_endpoint_auth_signing_alg_values_supported": ["RS256"]
```

But the keystore already supports RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, and Ed25519. If you load an ES256 key and call the discovery endpoint, the response still claims only RS256 is supported — which is misleading and can break real OIDC clients that rely on this field to decide which algorithm to use.

**Proposal**

Derive `id_token_signing_alg_values_supported` dynamically from the algorithms of the keys currently in the keystore, rather than hardcoding `['RS256']`.

Per [OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata), this field is **REQUIRED** and must list the JWS signing algorithms actually supported for ID Tokens. The [IANA JOSE Algorithms registry](https://www.iana.org/assignments/jose/jose.xhtml) defines the algorithm identifiers; `jose` (already a dependency) handles all of the ones in `supportedAlgs`.

For `token_endpoint_auth_signing_alg_values_supported`: since `token_endpoint_auth_methods_supported` is `['none']`, this field is not applicable per [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2) and should arguably be removed entirely.

> To be confirmed in the context of the issue above

**Behaviour change**

- If no keys are loaded → `[]` (honest; the server can't sign anything)
- If one ES256 key is loaded → `['ES256']`
- If RS256 + EdDSA keys are loaded → `['RS256', 'EdDSA']`

The existing test suite loads a single RS256 key, so it would continue to pass unchanged.
