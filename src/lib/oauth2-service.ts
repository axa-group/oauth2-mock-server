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

import { IncomingMessage, type RequestListener } from 'http';
import { URL } from 'url';
import express, { type RequestHandler } from 'express';
import cors from 'cors';
import basicAuth from 'basic-auth';
import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';

import { OAuth2Issuer } from './oauth2-issuer';
import {
  assertIsCodeChallenge,
  assertIsString,
  assertIsStringOrUndefined,
  assertIsValidPkceCodeChallengeMethod,
  assertIsValidTokenRequest,
  defaultTokenTtl,
  isValidPkceCodeVerifier,
  pkceVerifierMatchesChallenge,
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
  ScopesOrTransform,
  StatusCodeMutableResponse,
} from './types';
import { Events } from './types';
import { InternalEvents } from './types-internals';
import { AssertionError } from 'assert';

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
    this.#issuer = oauth2Issuer;

    this.#endpoints = { ...DEFAULT_ENDPOINTS, ...endpoints };
    this.#requestHandler = this.buildRequestHandler();
    this.#nonce = {};
    this.#codeChallenges = new Map();
  }

  /**
   * Returns the OAuth2Issuer instance bound to this service.
   * @type {OAuth2Issuer}
   */
  get issuer(): OAuth2Issuer {
    return this.#issuer;
  }

  /**
   * Builds a JWT with a key in the keystore. The key will be selected in a round-robin fashion.
   * @param {IncomingMessage} req The incoming HTTP request.
   * @param {number} expiresIn Time in seconds for the JWT to expire. Default: 3600 seconds.
   * @param {ScopesOrTransform} [scopesOrTransform] A scope, array of scopes,
   *     or JWT transformation callback.
   * @returns {Promise<string>} The produced JWT.
   * @fires OAuth2Service#beforeTokenSigning
   */
  async buildToken(
    req: IncomingMessage,
    expiresIn: number,
    scopesOrTransform: ScopesOrTransform | undefined,
  ): Promise<string> {
    this.issuer.once(InternalEvents.BeforeSigning, (token: MutableToken) => {
      /**
       * Before token signing event.
       * @event OAuth2Service#beforeTokenSigning
       * @param {MutableToken} token The unsigned JWT header and payload.
       * @param {IncomingMessage} req The incoming HTTP request.
       */
      this.emit(Events.BeforeTokenSigning, token, req);
    });

    return await this.issuer.buildToken({ scopesOrTransform, expiresIn });
  }

  /**
   * Returns a request handler to be used as a callback for http.createServer().
   * @type {Function}
   */
  get requestHandler(): RequestListener {
    return this.#requestHandler;
  }

  private buildRequestHandler = (): RequestListener => {
    const app = express();
    app.disable('x-powered-by');
    app.use(express.json());
    app.use(cors());
    app.get(this.#endpoints.wellKnownDocument, this.openidConfigurationHandler);
    app.get(this.#endpoints.jwks, this.jwksHandler);
    app.post(
      this.#endpoints.token,
      express.urlencoded({ extended: false }),
      this.tokenHandler,
    );
    app.get(this.#endpoints.authorize, this.authorizeHandler);
    app.get(this.#endpoints.userinfo, this.userInfoHandler);
    app.post(this.#endpoints.revoke, this.revokeHandler);
    app.get(this.#endpoints.endSession, this.endSessionHandler);
    app.post(this.#endpoints.introspect, this.introspectHandler);

    return app;
  };

  private openidConfigurationHandler: RequestHandler = (_req, res) => {
    assertIsString(this.issuer.url, 'Unknown issuer url.');

    const openidConfig = {
      issuer: this.issuer.url,
      token_endpoint: `${this.issuer.url}${this.#endpoints.token}`,
      authorization_endpoint: `${this.issuer.url}${this.#endpoints.authorize}`,
      userinfo_endpoint: `${this.issuer.url}${this.#endpoints.userinfo}`,
      token_endpoint_auth_methods_supported: ['none'],
      jwks_uri: `${this.issuer.url}${this.#endpoints.jwks}`,
      response_types_supported: ['code'],
      grant_types_supported: [
        'client_credentials',
        'authorization_code',
        'password',
      ],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      response_modes_supported: ['query'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: `${this.issuer.url}${this.#endpoints.revoke}`,
      subject_types_supported: ['public'],
      end_session_endpoint: `${this.issuer.url}${this.#endpoints.endSession}`,
      introspection_endpoint: `${this.issuer.url}${this.#endpoints.introspect}`,
      code_challenge_methods_supported: supportedPkceAlgorithms,
    };

    return res.json(openidConfig);
  };

  private jwksHandler: RequestHandler = (_req, res) => {
    return res.json({ keys: this.issuer.keys.toJSON() });
  };

  private tokenHandler: RequestHandler = async (req, res, next) => {
    try {
      const tokenTtl = defaultTokenTtl;

      res.set({
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
      });

      let xfn: ScopesOrTransform | undefined;

      assertIsValidTokenRequest(req.body);

      if ('code_verifier' in req.body && 'code' in req.body) {
        try {
          const code = req.body.code;
          const verifier = req.body['code_verifier'];
          const savedCodeChallenge = this.#codeChallenges.get(code);
          assertIsCodeChallenge(savedCodeChallenge);
          this.#codeChallenges.delete(code);
          if (!isValidPkceCodeVerifier(verifier)) {
            throw new AssertionError({
              message:
                "Invalid 'code_verifier'. The verifier does not confirm with the RFC7636 spec. Ref: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1",
            });
          }
          const doesVerifierMatchCodeChallenge =
            await pkceVerifierMatchesChallenge(verifier, savedCodeChallenge);
          if (!doesVerifierMatchCodeChallenge) {
            throw new AssertionError({
              message: 'code_verifier provided does not match code_challenge',
            });
          }
        } catch (e) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: (e as AssertionError).message,
          });
        }
      }

      const reqBody = req.body;

      let { scope } = reqBody;
      const { aud } = reqBody;

      switch (req.body.grant_type) {
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
            Object.assign(payload, {
              sub: 'johndoe',
              amr: ['pwd'],
              scope,
            });
          };
          break;
        case 'refresh_token':
          scope = scope ?? 'dummy';
          xfn = (_header, payload) => {
            Object.assign(payload, {
              sub: 'johndoe',
              amr: ['pwd'],
              scope,
            });
          };
          break;
        default:
          return res.status(400).json({
            error: 'invalid_grant',
          });
      }

      const token = await this.buildToken(req, tokenTtl, xfn);
      const body: Record<string, unknown> = {
        access_token: token,
        token_type: 'Bearer',
        expires_in: tokenTtl,
        scope,
      };

      if (req.body.grant_type !== 'client_credentials') {
        const credentials = basicAuth(req);
        const clientId = credentials ? credentials.name : req.body.client_id;

        const xfn: JwtTransform = (_header, payload) => {
          Object.assign(payload, {
            sub: 'johndoe',
            aud: clientId,
          });
          if (reqBody.code !== undefined && this.#nonce[reqBody.code]) {
            Object.assign(payload, {
              nonce: this.#nonce[reqBody.code],
            });
            delete this.#nonce[reqBody.code];
          }
        };

        body['id_token'] = await this.buildToken(req, tokenTtl, xfn);
        body['refresh_token'] = randomUUID();
      }

      const tokenEndpointResponse: MutableResponse = {
        body,
        statusCode: 200,
      };

      /**
       * Before token response event.
       * @event OAuth2Service#beforeResponse
       * @param {MutableResponse} response The response body and status code.
       * @param {IncomingMessage} req The incoming HTTP request.
       */
      this.emit(Events.BeforeResponse, tokenEndpointResponse, req);

      return res
        .status(tokenEndpointResponse.statusCode)
        .json(tokenEndpointResponse.body);
    } catch (e) {
      return next(e);
    }
  };

  private authorizeHandler: RequestHandler = (req, res) => {
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
      'Invalid code_challenge_method type'
    );

    const url = new URL(redirectUri);

    if (responseType === 'code') {
      if (code_challenge) {
        const codeChallengeMethod = code_challenge_method ?? 'plain';
        assertIsValidPkceCodeChallengeMethod(codeChallengeMethod);
        this.#codeChallenges.set(code, {
          challenge: code_challenge,
          method: codeChallengeMethod,
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
    return res.redirect(url.href);
  };

  private userInfoHandler: RequestHandler = (req, res) => {
    const userInfoResponse: MutableResponse = {
      body: {
        sub: 'johndoe',
      },
      statusCode: 200,
    };

    /**
     * Before user info event.
     * @event OAuth2Service#beforeUserinfo
     * @param {MutableResponse} response The response body and status code.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeUserinfo, userInfoResponse, req);

    return res.status(userInfoResponse.statusCode).json(userInfoResponse.body);
  };

  private revokeHandler: RequestHandler = (req, res) => {
    const revokeResponse: StatusCodeMutableResponse = {
      statusCode: 200,
    };

    /**
     * Before revoke event.
     * @event OAuth2Service#beforeRevoke
     * @param {StatusCodeMutableResponse} response The response status code.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeRevoke, revokeResponse, req);

    return res.status(revokeResponse.statusCode).send('');
  };

  private endSessionHandler: RequestHandler = (req, res) => {
    assertIsString(
      req.query['post_logout_redirect_uri'],
      'Invalid post_logout_redirect_uri type',
    );

    const postLogoutRedirectUri: MutableRedirectUri = {
      url: new URL(req.query['post_logout_redirect_uri']),
    };

    /**
     * Before post logout redirect event.
     * @event OAuth2Service#beforePostLogoutRedirect
     * @param {MutableRedirectUri} postLogoutRedirectUri
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforePostLogoutRedirect, postLogoutRedirectUri, req);

    return res.redirect(postLogoutRedirectUri.url.href);
  };

  private introspectHandler: RequestHandler = (req, res) => {
    const introspectResponse: MutableResponse = {
      body: {
        active: true,
      },
      statusCode: 200,
    };

    /**
     * Before introspect event.
     * @event OAuth2Service#beforeIntrospect
     * @param {MutableResponse} response The response body and status code.
     * @param {IncomingMessage} req The incoming HTTP request.
     */
    this.emit(Events.BeforeIntrospect, introspectResponse, req);

    return res
      .status(introspectResponse.statusCode)
      .json(introspectResponse.body);
  };
}
