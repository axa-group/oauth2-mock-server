import type { ServerOptions } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';

import type { JWKWithKid, supportedPkceAlgorithms } from './types-internals';

export interface TokenRequest {
  scope?: string;
  grant_type: string;
  username?: unknown;
  client_id?: unknown;
  code?: string;
  aud?: string[] | string;
  code_verifier?: string;
}

export interface TokenRequestIncomingMessage extends IncomingMessage {
  body: TokenRequest;
}

export interface Options {
  host?: string;
  port: number;
  cert?: string;
  key?: string;
  keys: Record<string, unknown>[];
  saveJWK: boolean;
  issuerUrlTrailingSlash: boolean;
}

export type HttpServerOptions = Pick<ServerOptions, 'key'> &
  Pick<ServerOptions, 'cert'>;

export interface MutableRedirectUri {
  url: URL;
}

export interface MutableToken {
  header: Header;
  payload: Payload;
}

export interface Header {
  kid: string;
  [key: string]: unknown;
}

export interface Payload {
  iss: string;
  iat: number;
  exp: number;
  nbf: number;
  [key: string]: unknown;
}

export interface StatusCodeMutableResponse {
  statusCode: number;
}

export interface MutableResponse extends StatusCodeMutableResponse {
  body: Record<string, unknown> | '';
}

export type ScopesOrTransform = string | string[] | JwtTransform;

export type JwtTransform = (header: Header, payload: Payload) => void;

/**
 * Events emitted by {@link OAuth2Service} at key points in request processing.
 * Register handlers via `service.on(Events.Xxx, handler)` for persistent hooks,
 * or `service.once(Events.Xxx, handler)` to intercept a single request.
 * Each handler receives a mutable object that can be modified in-place to
 * customise the server's behaviour — no return value is required.
 */
export enum Events {
  /**
   * Raised by the `POST /token` endpoint before the JWT is signed.
   * Allows mutating the token's header and payload — e.g. adding custom claims,
   * overriding the expiry, or attaching a client ID.
   *
   * Handler signature: `(token: MutableToken, req: TokenRequestIncomingMessage) => void`
   */
  BeforeTokenSigning = 'beforeTokenSigning',

  /**
   * Raised by the `POST /token` endpoint after the access token is built,
   * immediately before the HTTP response is sent.
   * Allows mutating the response body and status code — e.g. simulating an
   * `invalid_grant` error or injecting additional response fields.
   *
   * Handler signature: `(tokenEndpointResponse: MutableResponse, req: TokenRequestIncomingMessage) => void`
   */
  BeforeResponse = 'beforeResponse',

  /**
   * Raised by the `GET /userinfo` endpoint before the response is sent.
   * Allows mutating the response body and status code — e.g. adding extra
   * claims or simulating an authorization error.
   *
   * Handler signature: `(userInfoResponse: MutableResponse, req: IncomingMessage) => void`
   */
  BeforeUserinfo = 'beforeUserinfo',

  /**
   * Raised by the `POST /revoke` endpoint before the response is sent.
   * Allows mutating the response status code only — e.g. simulating a
   * non-200 revocation result.
   *
   * Handler signature: `(revokeResponse: StatusCodeMutableResponse, req: IncomingMessage) => void`
   */
  BeforeRevoke = 'beforeRevoke',

  /**
   * Raised by the `GET /authorize` endpoint before the authorization code
   * redirect is performed.
   * Allows mutating the redirect URL and its query parameters — e.g. injecting
   * extra parameters into the callback URI.
   *
   * Handler signature: `(authorizeRedirectUri: MutableRedirectUri, req: IncomingMessage) => void`
   */
  BeforeAuthorizeRedirect = 'beforeAuthorizeRedirect',

  /**
   * Raised by the `GET /endsession` endpoint before the post-logout redirect
   * is performed.
   * Allows mutating the redirect URL and its query parameters — e.g. appending
   * extra state to the `post_logout_redirect_uri`.
   *
   * Handler signature: `(postLogoutRedirectUri: MutableRedirectUri, req: IncomingMessage) => void`
   */
  BeforePostLogoutRedirect = 'beforePostLogoutRedirect',

  /**
   * Raised by the `POST /introspect` endpoint before the response is sent.
   * Allows mutating the response body and status code — e.g. adding token
   * metadata such as scope, username, and expiry, or simulating an inactive token.
   *
   * Handler signature: `(introspectResponse: MutableResponse, req: IncomingMessage) => void`
   */
  BeforeIntrospect = 'beforeIntrospect',
}

export interface TokenBuildOptions {
  /**
   * The 'kid' of the key that will be used to sign the JWT.
   * If omitted, the next key in the round - robin will be used.
   */
  kid?: string | undefined;

  /**
   * A scope, array of scopes, or JWT transformation callback.
   */
  scopesOrTransform?: ScopesOrTransform | undefined;

  /**
   * Time in seconds before the JWT to expire. Default: 3600 seconds.
   */
  expiresIn?: number | undefined;
}

export interface JWK extends JWKWithKid {
  alg: string;
}

export interface OAuth2Endpoints {
  wellKnownDocument: string;
  token: string;
  jwks: string;
  authorize: string;
  userinfo: string;
  revoke: string;
  endSession: string;
  introspect: string;
}

export type OAuth2EndpointsInput = Partial<OAuth2Endpoints>;

export interface OAuth2Options {
  endpoints?: OAuth2EndpointsInput;
  shouldIssuerUrlBeSuffixedWithATralingSlash?: boolean;
}

export type PKCEAlgorithm = (typeof supportedPkceAlgorithms)[number];

export interface CodeChallenge {
  challenge: string;
  method: PKCEAlgorithm;
}

export interface AugmentedRequest extends IncomingMessage {
  body: Record<string, unknown> | unknown[] | undefined;
  query: Record<string, string | string[] | undefined>;
}

export type RouteHandler = (
  req: AugmentedRequest,
  res: ServerResponse,
) => Promise<void> | void;
