import {
  OAuth2Server,
  type JWKStore,
  Events,
  type MutableToken,
  type Header,
  type Payload,
  type TokenRequest,
  type MutableResponse,
  type MutableRedirectUri,
  type ScopesOrTransform,
  type JwtTransform,
  type TokenBuildOptions,
  type OAuth2Options,
  type OAuth2Endpoints,
} from 'oauth2-mock-server';

// Classes
const server: OAuth2Server = new OAuth2Server();
const store: JWKStore = server.issuer.keys;

// Enum
const event: string = Events.BeforeTokenSigning;

// Interfaces — structural assignments
const header: Header = { kid: 'test-key' };

const payload: Payload = {
  iss: 'https://example.com',
  iat: 0,
  exp: 3600,
  nbf: 0,
};

const token: MutableToken = { header, payload };

const request: TokenRequest = {
  grant_type: 'client_credentials',
  scope: 'openid',
};

const response: MutableResponse = {
  statusCode: 200,
  body: { access_token: 'abc' },
};

const redirectUri: MutableRedirectUri = {
  url: new URL('https://example.com/callback'),
};

const buildOptions: TokenBuildOptions = {
  kid: 'my-key',
  expiresIn: 3600,
};

const oauth2Options: OAuth2Options = {
  shouldIssuerUrlBeSuffixedWithATralingSlash: false,
};

const endpoints: OAuth2Endpoints = {
  wellKnownDocument: '/.well-known/openid-configuration',
  token: '/token',
  jwks: '/jwks',
  authorize: '/authorize',
  userinfo: '/userinfo',
  revoke: '/revoke',
  endSession: '/end-session',
  introspect: '/introspect',
};

// Type aliases
const transform: JwtTransform = (h: Header, p: Payload): void => {
  h.custom = 'value';
  p.sub = 'user1';
};

const scopeString: ScopesOrTransform = 'openid profile';
const scopeArray: ScopesOrTransform = ['openid', 'profile'];
const scopeTransform: ScopesOrTransform = transform;

// Suppress unused variable warnings for a pure type-check file
void server;
void store;
void event;
void token;
void request;
void response;
void redirectUri;
void buildOptions;
void oauth2Options;
void endpoints;
void scopeString;
void scopeArray;
void scopeTransform;
