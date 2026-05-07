/**
 * Copyright (c) AXA Assistance France
 *
 * Licensed under the AXA Assistance France License (the "License"); you
 * may not use this file except in compliance with the License.
 * A copy of the License can be found in the LICENSE.md file distributed
 * together with this file.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * OAuth2 Service library
 * @module lib/oauth2-service
 */

import type {
  IncomingMessage,
  ServerResponse,
  RequestListener,
} from 'node:http';
import { URL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { AssertionError } from 'node:assert';

import basicAuth from 'basic-auth';

import type { OAuth2Issuer } from './oauth2-issuer';
import {
  applyCorsHeaders,
  assertIsString,
  assertIsStringOrUndefined,
  assertIsValidTokenRequest,
  defaultTokenTtl,
  isValidPkceCodeVerifier,
  normalizePath,
  parseBody,
  parseQuery,
  pkceVerifierMatchesChallenge,
  sendEmpty,
  sendJson,
  sendRedirect,
  supportedPkceAlgorithms,
} from './helpers';
import type {
  CodeChallenge,
  JwtTransform,
  MutableRedirectUri,
  MutableResponse,
  MutableToken,
  OAuth2Endpoints,
  OAuth2EndpointsInput,
  PKCEAlgorithm,
  ScopesOrTransform,
  StatusCodeMutableResponse,
  TokenRequestIncomingMessage,
} from './types';
import { Events } from './types';
import {
  type AugmentedRequest,
  InternalEvents,
  type RouteHandler,
} from './types-internals';

const DEFAULT_ENDPOINTS: OAuth2Endpoints = Object.freeze({
  wellKnownDocument: '/.well-known/openid-configuration',
  token: '/token',
  jwks: '/jwks',
  authorize: '/authorize',
  userinfo: '/userinfo',
  revoke: '/revoke',
  endSession: '/endsession',
  introspect: '/introspect',
});

/**
 * Provides a request handler for an OAuth 2 server.
 */
export class OAuth2Service extends EventEmitter {
  /**
   * Creates a new instance of OAuth2Server.
   * @param {OAuth2Issuer} oauth2Issuer The OAuth2Issuer instance
   *     that will be offered through the service.
   * @param {OAuth2EndpointsInput | undefined} paths Endpoint path name overrides.
   */

  #issuer: OAuth2Issuer;
  #requestHandler: RequestListener;
  #nonce: Record<string, string>;
  #codeChallenges: Map<string, CodeChallenge>;
  #endpoints: OAuth2Endpoints;

  constructor(oauth2Issuer: OAuth2Issuer, endpoints?: OAuth2EndpointsInput) {
    super();

    assertEndpointsStartWithAForwardSlash(endpoints);

    this.#issuer = oauth2Issuer;

    this.#endpoints = { ...DEFAULT_ENDPOINTS, ...endpoints };
    this.#requestHandler = this.buildRequestHandler();
    this.#nonce = {};
    this.#codeChallenges = new Map();
  }

  /**
   * Returns the OAuth2Issuer instance bound to this service.
   * @returns The OAuth2Issuer instance.
   */
  get issuer(): OAuth2Issuer {
    return this.#issuer;
  }

  /**
   * Builds a JWT with a key in the keystore. The key will be selected in a round-robin fashion.
   * @param req The incoming HTTP request.
   * @param expiresIn Time in seconds for the JWT to expire. Default: 3600 seconds.
   * @param scopesOrTransform A scope, array of scopes,
   *     or JWT transformation callback.
   * @returns The produced JWT.
   * @fires OAuth2Service#beforeTokenSigning
   */
  async buildToken(
    req: TokenRequestIncomingMessage,
    expiresIn: number,
    scopesOrTransform: ScopesOrTransform | undefined,
  ): Promise<string> {
    this.issuer.once(InternalEvents.BeforeSigning, (token: MutableToken) => {
      /**
       * Before token signing event.
       * @event OAuth2Service#beforeTokenSigning
       * @param {MutableToken} token The unsigned JWT header and payload.
       * @param {TokenRequestIncomingMessage} req The incoming HTTP request.
       */
      this.emit(Events.BeforeTokenSigning, token, req);
    });

    return await this.issuer.buildToken({ scopesOrTransform, expiresIn });
  }

  /**
   * Returns a request handler to be used as a callback for http.createServer().
   * @returns The request handler.
   */
  get requestHandler(): RequestListener {
    return this.#requestHandler;
  }

  private buildRequestHandler = (): RequestListener => {
    const routes = new Map<string, RouteHandler>([
      [
        `GET:${this.#endpoints.wellKnownDocument}`,
        this.openidConfigurationHandler,
      ],
      [`GET:${this.#endpoints.jwks}`, this.jwksHandler],
      [`POST:${this.#endpoints.token}`, this.tokenHandler],
      [`GET:${this.#endpoints.authorize}`, this.authorizeHandler],
      [`GET:${this.#endpoints.userinfo}`, this.userInfoHandler],
      [`POST:${this.#endpoints.revoke}`, this.revokeHandler],
      [`GET:${this.#endpoints.endSession}`, this.endSessionHandler],
      [`POST:${this.#endpoints.introspect}`, this.introspectHandler],
    ]);

    return (req, res) => {
      dispatch(routes, req, res).catch((err: unknown) => {
        errorHandler(err, res);
      });
    };
  };

  private openidConfigurationHandler: RouteHandler = (_req, res) => {
    assertIsString(this.issuer.url, 'Unknown issuer url.');

    const issuer = this.issuer.url;

    const openidConfig = {
      issuer,
      token_endpoint: urlCombine(issuer, this.#endpoints.token),
      authorization_endpoint: urlCombine(issuer, this.#endpoints.authorize),
      userinfo_endpoint: urlCombine(issuer, this.#endpoints.userinfo),
      token_endpoint_auth_methods_supported: ['none'],
      jwks_uri: urlCombine(issuer, this.#endpoints.jwks),
      response_types_supported: ['code'],
      grant_types_supported: [
        'client_credentials',
        'authorization_code',
        'password',
      ],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      response_modes_supported: ['query'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: urlCombine(issuer, this.#endpoints.revoke),
      subject_types_supported: ['public'],
      end_session_endpoint: urlCombine(issuer, this.#endpoints.endSession),
      introspection_endpoint: urlCombine(issuer, this.#endpoints.introspect),
      code_challenge_methods_supported: supportedPkceAlgorithms,
    };

    sendJson(res, openidConfig);
  };

  private jwksHandler: RouteHandler = (_req, res) => {
    sendJson(res, { keys: this.issuer.keys.toJSON() });
  };

  private tokenHandler: RouteHandler = async (req, res) => {
    const reqBody = await parseBody(req);
    assertIsValidTokenRequest(reqBody);

    req.body = reqBody;

    const tokenTtl = defaultTokenTtl;

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    let xfn: ScopesOrTransform | undefined;

    if ('code_verifier' in reqBody && 'code' in reqBody) {
      const code = reqBody.code;
      const verifier = reqBody.code_verifier;
      const savedCodeChallenge = this.#codeChallenges.get(code);
      if (savedCodeChallenge === undefined) {
        throw new AssertionError({ message: 'code_challenge required' });
      }
      this.#codeChallenges.delete(code);
      if (!isValidPkceCodeVerifier(verifier)) {
        throw new AssertionError({
          message:
            "Invalid 'code_verifier'. The verifier does not conform with the RFC7636 spec. Ref: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1",
        });
      }
      const doesVerifierMatchCodeChallenge = await pkceVerifierMatchesChallenge(
        verifier,
        savedCodeChallenge,
      );
      if (!doesVerifierMatchCodeChallenge) {
        throw new AssertionError({
          message: 'code_verifier provided does not match code_challenge',
        });
      }
    }

    let { scope } = reqBody;
    const { aud } = reqBody;

    switch (reqBody.grant_type) {
      case 'client_credentials':
        xfn = (_header, payload) => {
          Object.assign(payload, { scope, aud });
        };
        break;
      case 'password':
        xfn = (_header, payload) => {
          Object.assign(payload, {
            sub: reqBody.username,
            amr: ['pwd'],
            scope,
          });
        };
        break;
      case 'authorization_code':
        scope = scope ?? 'dummy';
        xfn = (_header, payload) => {
          Object.assign(payload, { sub: 'johndoe', amr: ['pwd'], scope });
        };
        break;
      case 'refresh_token':
        scope = scope ?? 'dummy';
        xfn = (_header, payload) => {
          Object.assign(payload, { sub: 'johndoe', amr: ['pwd'], scope });
        };
        break;
      default:
        sendJson(res, { error: 'invalid_grant' }, 400);
        return;
    }

    const token = await this.buildToken(
      req as unknown as TokenRequestIncomingMessage,
      tokenTtl,
      xfn,
    );
    const resBody: Record<string, unknown> = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: tokenTtl,
      scope,
    };

    if (reqBody.grant_type !== 'client_credentials') {
      const credentials = basicAuth(req);
      const clientId = credentials ? credentials.name : reqBody.client_id;

      const xfn: JwtTransform = (_header, payload) => {
        Object.assign(payload, { sub: 'johndoe', aud: clientId });
        if (reqBody.code !== undefined && reqBody.code in this.#nonce) {
          Object.assign(payload, { nonce: this.#nonce[reqBody.code] });
          // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
          delete this.#nonce[reqBody.code];
        }
      };

      resBody['id_token'] = await this.buildToken(
        req as unknown as TokenRequestIncomingMessage,
        tokenTtl,
        xfn,
      );
      resBody['refresh_token'] = randomUUID();
    }

    const tokenEndpointResponse: MutableResponse = {
      body: resBody,
      statusCode: 200,
    };

    /**
     * Before token response event.
     * @event OAuth2Service#beforeResponse
     * @param {MutableResponse} response The response body and status code.
     * @param {TokenRequestIncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeResponse, tokenEndpointResponse, req);

    sendJson(res, tokenEndpointResponse.body, tokenEndpointResponse.statusCode);
  };

  private authorizeHandler: RouteHandler = (req, res) => {
    req.query = parseQuery(req);

    const code = randomUUID();
    const {
      nonce,
      scope,
      redirect_uri: redirectUri,
      response_type: responseType,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query;

    assertIsString(redirectUri, 'Invalid redirectUri type');
    assertIsStringOrUndefined(nonce, 'Invalid nonce type');
    assertIsStringOrUndefined(scope, 'Invalid scope type');
    assertIsStringOrUndefined(state, 'Invalid state type');
    assertIsStringOrUndefined(code_challenge, 'Invalid code_challenge type');
    assertIsStringOrUndefined(
      code_challenge_method,
      'Invalid code_challenge_method type',
    );

    const url = new URL(redirectUri);

    if (responseType === 'code') {
      if (code_challenge) {
        const codeChallengeMethod = code_challenge_method ?? 'plain';
        assertIsString(
          codeChallengeMethod,
          "Invalid 'code_challenge_method' type",
        );
        if (
          !supportedPkceAlgorithms.includes(
            codeChallengeMethod as PKCEAlgorithm,
          )
        ) {
          sendJson(
            res,
            {
              error: 'invalid_request',
              error_description: `Unsupported code_challenge method ${codeChallengeMethod}. The following code_challenge_method are supported: ${supportedPkceAlgorithms.join(
                ', ',
              )}`,
            },
            400,
          );
          return;
        }
        this.#codeChallenges.set(code, {
          challenge: code_challenge,
          method: codeChallengeMethod as PKCEAlgorithm,
        });
      }
      if (nonce !== undefined) {
        this.#nonce[code] = nonce;
      }
      url.searchParams.set('code', code);
    } else {
      url.searchParams.set('error', 'unsupported_response_type');
      url.searchParams.set(
        'error_description',
        'The authorization server does not support obtaining an access token using this response_type.',
      );
    }

    if (state) {
      url.searchParams.set('state', state);
    }

    const authorizeRedirectUri: MutableRedirectUri = { url };

    /**
     * Before authorize redirect event.
     * @event OAuth2Service#beforeAuthorizeRedirect
     * @param {MutableRedirectUri} authorizeRedirectUri The redirect uri and query params to redirect to.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeAuthorizeRedirect, authorizeRedirectUri, req);

    // Note: This is a textbook definition of an "open redirect" vuln
    // cf. https://cwe.mitre.org/data/definitions/601.html
    //
    // However, this whole library is expected to be used as a test helper,
    // so there's no real point in making the exposed API more complex (by
    // exposing an endpoint to preregister whitelisted urls, for instance)
    // for the sake of security.
    //
    // This is *not* a real oAuth2 server. This is *not* to be run in production.
    sendRedirect(res, url.href);
  };

  private userInfoHandler: RouteHandler = (req, res) => {
    const userInfoResponse: MutableResponse = {
      body: { sub: 'johndoe' },
      statusCode: 200,
    };

    /**
     * Before user info event.
     * @event OAuth2Service#beforeUserinfo
     * @param {MutableResponse} response The response body and status code.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeUserinfo, userInfoResponse, req);

    sendJson(res, userInfoResponse.body, userInfoResponse.statusCode);
  };

  private revokeHandler: RouteHandler = (req, res) => {
    const revokeResponse: StatusCodeMutableResponse = { statusCode: 200 };

    /**
     * Before revoke event.
     * @event OAuth2Service#beforeRevoke
     * @param {StatusCodeMutableResponse} response The response status code.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeRevoke, revokeResponse, req);

    sendEmpty(res, revokeResponse.statusCode);
  };

  private endSessionHandler: RouteHandler = (req, res) => {
    req.query = parseQuery(req);

    assertIsString(
      req.query['post_logout_redirect_uri'],
      'Invalid post_logout_redirect_uri type',
    );
    assertIsStringOrUndefined(req.query['state'], 'Invalid state type');

    const redirectUrl = new URL(req.query['post_logout_redirect_uri']);

    if (req.query['state']) {
      redirectUrl.searchParams.set('state', req.query['state']);
    }

    const postLogoutRedirectUri: MutableRedirectUri = {
      url: redirectUrl,
    };

    /**
     * Before post logout redirect event.
     * @event OAuth2Service#beforePostLogoutRedirect
     * @param {MutableRedirectUri} postLogoutRedirectUri
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforePostLogoutRedirect, postLogoutRedirectUri, req);

    sendRedirect(res, postLogoutRedirectUri.url.href);
  };

  private introspectHandler: RouteHandler = (req, res) => {
    const introspectResponse: MutableResponse = {
      body: { active: true },
      statusCode: 200,
    };

    /**
     * Before introspect event.
     * @event OAuth2Service#beforeIntrospect
     * @param {MutableResponse} response The response body and status code.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeIntrospect, introspectResponse, req);

    sendJson(res, introspectResponse.body, introspectResponse.statusCode);
  };
}

const assertEndpointsStartWithAForwardSlash = (
  endpoints: Partial<OAuth2Endpoints> | undefined,
): void => {
  if (endpoints === undefined) {
    return;
  }

  const invalidEndpoints = Object.entries(endpoints)
    .filter(([, path]) => !path.startsWith('/'))
    .map(([name, path]) => `"${name}": "${path}"`);

  if (invalidEndpoints.length > 0) {
    throw new AssertionError({
      message: `All endpoint paths must start with a forward slash. Invalid endpoints: ${invalidEndpoints.join(
        ', ',
      )}`,
    });
  }
};

const urlCombine = (base: string, path: string): string => {
  if (!base.endsWith('/')) {
    return `${base}${path}`;
  }

  return `${base.slice(0, -1)}${path}`;
};

const errorHandler = (err: unknown, res: ServerResponse) => {
  let status = 400;
  const errorBody: Record<string, unknown> = {};

  if (err instanceof AssertionError) {
    errorBody['error'] = 'invalid_request';
    errorBody['error_description'] = err.message;
  } else {
    console.error('Unexpected error:', err);

    status = 500;
    errorBody['error'] =
      'Most certainly a bug in the library code. ' +
      'Check the logs for more details and report this to the maintainers.';
  }

  sendJson(res, errorBody, status);
};

const dispatch = async (
  routes: Map<string, RouteHandler>,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> => {
  applyCorsHeaders(res);

  assertIsString(req.method, 'Invalid HTTP method');

  if (req.method === 'OPTIONS') {
    sendEmpty(res, 204);
    return;
  }

  // Mimics Express default lenient routing behavior (trailing slashes are ignored)
  const pathname = normalizePath(req.url ?? '/');

  const handler = routes.get(`${req.method}:${pathname}`);

  if (handler === undefined) {
    sendEmpty(res, 404);
    return;
  }

  await handler(req as AugmentedRequest, res);
};
