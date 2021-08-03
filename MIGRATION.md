# Migration guide

## From 3.2.0 to 4.0.0

Complete diff available in pull request [#80](https://github.com/axa-group/oauth2-mock-server/pull/80)
and more specifically in commit TODO.

### High level impact

- Removed PEM handling related functions. As such, the cli no longer supports
  `--save-pem ` nor ` --pem <filename>` options. One can leverage external
  tooling to convert PEM to JWK format
  (eg: https://www.npmjs.com/search?q=pem%20jwk).

- When feeding the store with existing keys, serialized JWK format expects the
  `alg` property to be defined and valued. (Refer to [README.md](./README.md)
  for the complete list of supported algorithms).

- Although not previously documented, the store was previously supporting
  symmetric algorithms (eg. `HS256`). This is no longer the case.

- Generation of unsigned tokens (`alg`: `none`) is no longer supported

### Low level impact

Most of the changes impact the lowest layers of the library. However, some of
them eventually altered the higher ones.

Below a quick recap of the most impactful changes would you use the library
programatically. For a more detailed view of all the changes, please refer to
the pull request mentioned above.

- Key generation has been made a little more versatile and can now issue keys
  that are not only RSA based.

  ```diff
  -const key = await authServer.issuer.keys.generateRSA();
  +const key = await authServer.issuer.keys.generate("RS256")
  ```

- Token generation method `buildToken()` now returns a promise

  ```diff
  -const jwt = authServer.issuer.buildToken(true, undefined, jwtTransformer);
  +const jwt = await authServer.issuer.buildToken({ scopesOrTransform: jwtTransformer });
  ```

- Keys were previously being type [defined](https://github.com/DefinitelyTyped/DefinitelyTyped/blob/2d2c4ced74bb356ec1c7b931dedd263bcfb5c4a1/types/node-jose/index.d.ts#L254-L265)
  as `JWK.Key` from the `@types/node-jose` package.

  They're now type defined as `JWK` and properly exported from by this package

- `JWKStore.toJSON()` now directly returns a `JWK[]` rather than a Json object
  exposing a `keys` property.

- From a TypeScript standpoint, inner type definitions are now exported
  from the root. This means that you can safely turn those lines

  ```ts
  import { OAuth2Server } from 'oauth2-mock-server';
  import { Payload } from 'oauth2-mock-server/dist/lib/types';
  ```

  into

  ```ts
  import { OAuth2Server, Payload } from 'oauth2-mock-server';
  ```
