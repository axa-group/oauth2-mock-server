import { IncomingMessage, type RequestListener } from 'http';
import qs from 'querystring';

import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';

import { OAuth2Issuer, OAuth2Service  } from '../src';
import type { MutableRedirectUri } from '../src/lib/types';
import {
  createPKCECodeChallenge,
  createPKCEVerifier,
} from '../src/lib/helpers';

import * as testKeys from './keys';
import { verifyTokenWithKey } from './lib/test_helpers';

describe('OAuth2Service endpoint validation', () => {
  it('should accept undefined endpoints', () => {
    expect(() => new OAuth2Service(new OAuth2Issuer(), undefined)).not.toThrow();
  });

  it('should list all invalid endpoints in error message', () => {
    const issuer = new OAuth2Issuer();

    expect(() => new OAuth2Service(issuer, {
      token: 'invalid-token',
      authorize: '/valid-auth',
      jwks: 'invalid-jwks'
    })).toThrow(
      'All endpoint paths must start with a forward slash. Invalid endpoints: "token": "invalid-token", "jwks": "invalid-jwks"'
    );
  });
});

describe.each([
  'https://issuer.example.com',
  'https://issuer.example.com/'
])
  ('OAuth 2 service with issuer %s', (issuerUrl: string) => {

  let issuer: OAuth2Issuer;
  let service: OAuth2Service;

  beforeAll(async () => {
    issuer = new OAuth2Issuer();
    issuer.url = issuerUrl;
    await issuer.keys.add(testKeys.getParsed('test-rs256-key.json'));

    service = new OAuth2Service(issuer);
  });

  it('should use custom endpoint paths', async () => {
    const customService = new OAuth2Service(issuer, {
      wellKnownDocument: '/custom-well-known',
      jwks: '/custom-jwks',
      token: '/custom-token',
      authorize: '/custom-authorize',
      userinfo: '/custom-userinfo',
      // 'revoke', 'endSession' purposefully omitted to test defaults,
      introspect: '/custom-introspect',
    });

    // OpenID well known document
    const res = await request(customService.requestHandler)
      .get('/custom-well-known')
      .expect(200);

    const endpointsPrefix = wellKnownEndpointsPrefixFrom(customService.issuer);

    expect(res.body).toMatchObject({
      jwks_uri: `${endpointsPrefix}/custom-jwks`,
      token_endpoint: `${endpointsPrefix}/custom-token`,
      authorization_endpoint: `${endpointsPrefix}/custom-authorize`,
      userinfo_endpoint: `${endpointsPrefix}/custom-userinfo`,
      revocation_endpoint: `${endpointsPrefix}/revoke`,
      end_session_endpoint: `${endpointsPrefix}/endsession`,
      introspection_endpoint: `${endpointsPrefix}/custom-introspect`,
    });

    const getTestCases: [string, number, string?][] = [
      ['/custom-jwks', 200],
      ['/jwks', 404],
      ['/custom-userinfo', 200],
      ['/userinfo', 404],
      ['/authorize', 404],
      ['/custom-authorize', 302, 'redirect_uri=http://example.com&scope=dummy_scope&state=1'],
      ['/endsession', 302, 'post_logout_redirect_uri=http://example.com']
    ];

    // GET
    for (const [path, expectedStatus, query] of getTestCases) {
      await request(customService.requestHandler)
        .get(path)
        .query(query ?? '')
        .expect(expectedStatus);
    }

    const postTestCases: [string, number][] = [
      ['/custom-token', 500], // 500 implies it was routed successfully
      ['/token', 404],
      ['/revoke', 200],
      ['/custom-introspect', 200],
    ];

    // POST
    for (const [path, expectedStatus] of postTestCases) {
      await request(customService.requestHandler)
        .post(path)
        .expect(expectedStatus);
    }
  });

  const wellKnownEndpointsPrefixFrom = (issuer: OAuth2Issuer) => {
    const { url } = issuer;
    expect(url).not.toBeUndefined();

    return url!.endsWith('/') ? url!.slice(0, -1) : url!;
  };

  it('should expose an OpenID configuration endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/.well-known/openid-configuration')
      .expect(200);

    const endpointsPrefix = wellKnownEndpointsPrefixFrom(service.issuer);

    expect(res.body).toEqual({
      issuer: service.issuer.url,
      token_endpoint: `${endpointsPrefix}/token`,
      authorization_endpoint: `${endpointsPrefix}/authorize`,
      userinfo_endpoint: `${endpointsPrefix}/userinfo`,
      token_endpoint_auth_methods_supported: ['none'],
      jwks_uri: `${endpointsPrefix}/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['client_credentials', 'authorization_code', 'password'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      response_modes_supported: ['query'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: `${endpointsPrefix}/revoke`,
      subject_types_supported: ['public'],
      introspection_endpoint: `${endpointsPrefix}/introspect`,
      code_challenge_methods_supported: ['plain', 'S256'],
      end_session_endpoint: `${endpointsPrefix}/endsession`,
    });

    expect(JSON.stringify(res.body)).not.toMatch(/(?<!https:|http:)\/\//);
  });

  it('should expose an JWKS endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/jwks')
      .expect(200);

    expect(res.body).toMatchObject({
      keys: [
        {
          kty: 'RSA',
          kid: 'test-rs256-key',
          n: expect.any(String),
          e: expect.any(String),
        },
      ],
    });

    expect(res.body.keys[0]).not.toHaveProperty('d');
  });

  it('should expose a token endpoint that handles Client Credentials grants', async () => {
    const res = await tokenRequest(service.requestHandler)
      .send({
        grant_type: 'client_credentials',
        scope: 'urn:first-scope urn:second-scope',
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'urn:first-scope urn:second-scope',
    });

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string; scope: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: resBody.scope,
    });
  });

  it.each([
    'aud',
    ['aud1', 'aud2']
  ])('should expose a token endpoint that includes an aud claim on Client Credentials grants', async (aud) => {
    const res = await tokenRequest(service.requestHandler)
      .send(qs.stringify({
        grant_type: 'client_credentials',
        aud,
      }))
      .expect(200);

    const resBody = res.body as { access_token: string; };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({ aud });
  });


  it('should expose a token endpoint that handles Resource Owner Password Credentials grants', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'password',
        username: 'the-resource-owner@example.com',
        scope: 'urn:first-scope urn:second-scope',
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'urn:first-scope urn:second-scope',
      refresh_token: expect.any(String),
    });

    const resBody = res.body as { access_token: string; scope: string };

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: resBody.scope,
      sub: 'the-resource-owner@example.com',
      amr: ['pwd'],
    });
  });

  it('should expose a token endpoint that handles authorization_code grants', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        grant_type: 'authorization_code',
        code: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        redirect_uri: 'https://example.com/callback',
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'dummy',
      id_token: expect.any(String),
      refresh_token: expect.any(String),
    });

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
      sub: 'johndoe',
      amr: ['pwd'],
    });
  });

  it('should expose a token endpoint that copies scope for authorization_code grants', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        grant_type: 'authorization_code',
        code: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        redirect_uri: 'https://example.com/callback',
        scope: 'test'
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'test',
      id_token: expect.any(String),
      refresh_token: expect.any(String),
    });

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: 'test',
      sub: 'johndoe',
      amr: ['pwd'],
    });
  });

  it('should expose a token endpoint that handles authorization_code grants without the basic authorization', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        redirect_uri: 'https://example.com/callback',
        client_id: 'client_id_sample',
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'dummy',
      id_token: expect.any(String),
      refresh_token: expect.any(String),
    });

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const resBody = res.body as {
      access_token: string;
      scope: string;
      id_token: string;
    };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
      sub: 'johndoe',
      amr: ['pwd'],
    });

    const decodedIdToken = await verifyTokenWithKey(service.issuer, resBody.id_token, 'test-rs256-key');

    expect(decodedIdToken.payload).toMatchObject({
      aud: 'client_id_sample',
    });
  });

  it('should expose a token endpoint that handles refresh_token grants', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        grant_type: 'refresh_token',
        refresh_token: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'dummy',
      id_token: expect.any(String),
      refresh_token: expect.any(String),
    });

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
      sub: 'johndoe',
      amr: ['pwd'],
    });
  });

  it('should expose a token endpoint that copies scope for refresh_token grants', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        grant_type: 'refresh_token',
        refresh_token: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        scope: 'test'
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'test',
      id_token: expect.any(String),
      refresh_token: expect.any(String),
    });

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: service.issuer.url,
      scope: 'test',
      sub: 'johndoe',
      amr: ['pwd'],
    });
  });

  it('should expose a token endpoint that remembers nonce', async () => {
    const resAuth = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754');

    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
      })
      .expect(200);

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      id_token: expect.any(String),
    });
    const resBody = res.body as { id_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.id_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      sub: 'johndoe',
      aud: 'abcecedf',
      nonce: '21ba8e4a-26af-4538-b98a-bccf031f6754',
    });
  });

  it('should expose a token endpoint that remembers nonces of multiple clients', async () => {
    const resAuth = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754');

    await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state456&client_id=abcecedf&nonce=7184422e-f260-11ea-adc1-0242ac120002');

    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
      })
      .expect(200);

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      id_token: expect.any(String),
    });
    const resBody = res.body as { id_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.id_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      sub: 'johndoe',
      aud: 'abcecedf',
      nonce: '21ba8e4a-26af-4538-b98a-bccf031f6754',
    });
  });

  it('should expose a token endpoint that forgets nonce used', async () => {
    await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754');

    await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
      });

    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
      })
      .expect(200);

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      id_token: expect.any(String),
    });
    const resBody = res.body as { id_token: string };
    const decoded = await verifyTokenWithKey(service.issuer, resBody.id_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      sub: 'johndoe',
      aud: 'abcecedf',
    });
  });

  it('should expose a token endpoint that accepts a JSON request body', async () => {
    const res = await request(service.requestHandler)
      .post('/token')
      .type('json')
      .send({
        grant_type: 'password',
        username: 'the-resource-owner@example.com',
        scope: 'urn:first-scope urn:second-scope',
      })
      .expect(200);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'urn:first-scope urn:second-scope',
      refresh_token: expect.any(String),
    });
  });

  it('should redirect to callback url when calling authorize endpoint with code response type and no state', async () => {
    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res).toMatchObject({
      headers: {
        location: expect.stringMatching(/http:\/\/example\.com\/callback\?code=[^&]*/)
      }
    });
  });

  it('should redirect to callback url keeping state when calling authorize endpoint with code response type', async () => {
    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res).toMatchObject({
      headers: {
        location: expect.stringMatching(/http:\/\/example\.com\/callback\?code=[^&]*&state=state123/)
      }
    });
  });

  it('should be able to manipulate url and query params when redirecting within authorize endpoint', async () => {
    service.once('beforeAuthorizeRedirect', (authorizeRedirectUri: MutableRedirectUri, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);

      expect(authorizeRedirectUri.url.toString()).toMatch(/http:\/\/example.com\/callback\?code=[^&]+&state=state123/);

      authorizeRedirectUri.url.hostname = 'foo.com';
      authorizeRedirectUri.url.pathname = '/cb';
      authorizeRedirectUri.url.protocol = 'https';
      authorizeRedirectUri.url.searchParams.set('code', 'testcode');
      authorizeRedirectUri.url.searchParams.set('extra_param', 'value');
      authorizeRedirectUri.url.searchParams.delete('state');
    });

    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res).toMatchObject({
      headers: {
        location: expect.stringMatching(/https:\/\/foo\.com\/cb\?code=testcode&extra_param=value/)
      }
    });
  });

  it('should redirect to callback url with an error and keeping state when calling authorize endpoint with an invalid response type', async () => {
    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=invalid_response_type&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res).toMatchObject({
      headers: {
        location: 'http://example.com/callback?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+obtaining+an+access+token+using+this+response_type.&state=state123'
      }
    });
  });

  it('should not handle token requests unsupported grant types', async () => {
    const res = await tokenRequest(service.requestHandler)
      .send({
        grant_type: 'INVALID_GRANT_TYPE',
      })
      .expect(400);

    expect(res.body).toMatchObject({
      error: 'invalid_grant',
    });
  });

  it('should be able to transform the token endpoint response', async () => {
    service.once('beforeResponse', (tokenEndpointResponse, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);
      tokenEndpointResponse.body.expires_in = 9000;
      tokenEndpointResponse.body.some_stuff = 'whatever';
      tokenEndpointResponse.statusCode = 302;
    });

    const res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        grant_type: 'authorization_code',
        code: '6b575dd1-2c3b-4284-81b1-e281138cdbbd',
        redirect_uri: 'https://example.com/callback',
      })
      .expect(302);

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 9000,
      scope: 'dummy',
      id_token: expect.any(String),
      refresh_token: expect.any(String),
      some_stuff: 'whatever',
    });
  });

  it('should allow customizing the token response through a beforeTokenSigning event', async () => {
    service.once('beforeTokenSigning', (token, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);
      token.payload.custom_header = req.headers['custom-header'];
      token.payload.iss = "https://tada.com";
    });

    const res = await tokenRequest(service.requestHandler)
      .set('Custom-Header', 'custom-token-value')
      .send({
        grant_type: 'client_credentials',
        scope: 'a-test-scope',
      })
      .expect(200);

    const key = service.issuer.keys.get('test-rs256-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
    });
    const resBody = res.body as { access_token: string };

    const decoded = await verifyTokenWithKey(service.issuer, resBody.access_token, 'test-rs256-key');

    expect(decoded.payload).toMatchObject({
      iss: "https://tada.com",
      scope: 'a-test-scope',
      custom_header: 'custom-token-value',
    });
  });

  it('should expose the userinfo endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/userinfo')
      .expect(200);

    expect(res.body).toMatchObject({
      sub: 'johndoe',
    });
  });

  it('should allow customizing the userinfo response through a beforeUserinfo event', async () => {
    service.once('beforeUserinfo', (userInfoResponse, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);
      userInfoResponse.body = {
        error: 'invalid_token',
        error_message: 'token is expired',
      };
      userInfoResponse.statusCode = 401;
    });
    const res = await request(service.requestHandler)
      .get('/userinfo')
      .expect(401);

    expect(res.body).toMatchObject({
      error: 'invalid_token',
      error_message: 'token is expired',
    });
  });

  it('should expose the revoke endpoint', async () => {
    const res = await request(service.requestHandler)
      .post('/revoke')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        token: 'authorization_code',
        token_type_hint: 'refresh_token',
      })
      .expect(200);

    expect(res.text).toBe('');
  });

  it('should allow customizing the revoke response through a beforeRevoke event', async () => {
    service.once('beforeRevoke', (revokeResponse, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);
      revokeResponse.body = '';
      revokeResponse.statusCode = 204;
    });
    const res = await request(service.requestHandler)
      .post('/revoke')
      .type('form')
      .set('authorization', `Basic ${Buffer.from('dummy_client_id:dummy_client_secret').toString('base64')}`)
      .send({
        token: 'authorization_code',
        token_type_hint: 'refresh_token',
      })
      .expect(204);

    expect(res.text).toBeFalsy();
  });

  it('should expose CORS headers in a GET request', async () => {
    const res = await request(service.requestHandler)
      .get('/.well-known/openid-configuration')
      .expect(200);

    expect(res).toMatchObject({
      headers: { 'access-control-allow-origin': '*' },
    });
  });

  it('should expose CORS headers in an OPTIONS request', async () => {
    const res = await request(service.requestHandler)
      .options('/token')
      .expect(204);

    expect(res).toMatchObject({
      headers: { 'access-control-allow-origin': '*' },
    });
  });

  it('should redirect to post_logout_redirect_uri when calling end_session_endpoint', async () => {
    const postLogoutRedirectUri = 'http://example.com/signin?param=test';

    const res = await request(service.requestHandler)
      .get('/endsession')
      .query(`post_logout_redirect_uri=${encodeURIComponent(postLogoutRedirectUri)}`)
      .redirects(0)
      .expect(302);

    expect(res.headers['location']).toBe(postLogoutRedirectUri);
  });

  it('should be able to manipulate url and query params when redirecting within post_logout_redirect_uri', async () => {
    const postLogoutRedirectUri = 'http://example.com/signin?param=test';

    service.once('beforePostLogoutRedirect', (postLogoutRedirectURL: MutableRedirectUri, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);

      expect(postLogoutRedirectURL.url.toString()).toBe(postLogoutRedirectUri);

      postLogoutRedirectURL.url.hostname = 'post-logout.com';
    });

    const res = await request(service.requestHandler)
      .get('/endsession')
      .query(`post_logout_redirect_uri=${encodeURIComponent(postLogoutRedirectUri)}`)
      .redirects(0)
      .expect(302);

    expect(res.headers['location']).toBe('http://post-logout.com/signin?param=test');
  });

  it('should expose a token introspection endpoint that returns information about a token', async () => {
    const res = await request(service.requestHandler)
      .post('/introspect')
      .type('form')
      .expect(200);

    expect(res.body).toMatchObject({
      active: true,
    });
  });

  it('should allow customizing the introspect response through a beforeIntrospect event', async () => {
    service.once('beforeIntrospect', (introspectResponse, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);
      introspectResponse.body = {
        active: true,
        scope: 'dummy',
        username: 'johndoe',
      };
      introspectResponse.statusCode = 200;
    });
    const res = await request(service.requestHandler)
      .post('/introspect')
      .expect(200);

    expect(res.body).toMatchObject({
      active: true,
      scope: 'dummy',
      username: 'johndoe',
    });
  });

  describe('PKCE', () => {
    it('should grant access in normal PKCE flow with SHA-256 code_verifier', async () => {
      const verifier = createPKCEVerifier();

      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
        code_challenge: await createPKCECodeChallenge(verifier, 'S256'),
        code_challenge_method: 'S256',
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      const res = await tokenRequest(service.requestHandler).send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
        code_verifier: verifier,
      });
      expect(res.statusCode).toBe(200);
    });

    it('should grant access in normal PKCE flow with plain code_verifier', async () => {
      const verifier = createPKCEVerifier();

      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
        code_challenge: await createPKCECodeChallenge(verifier),
        code_challenge_method: 'plain',
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      const res = await tokenRequest(service.requestHandler).send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
        code_verifier: verifier,
      });
      expect(res.statusCode).toBe(200);
    });

    it('should revoke on mismatching code_challenge_method', async () => {
      const verifier = createPKCEVerifier();

      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
        code_challenge: await createPKCECodeChallenge(verifier, 'plain'),
        code_challenge_method: 'S256',
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      const res = await tokenRequest(service.requestHandler).send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
        code_verifier: verifier,
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).toMatchInlineSnapshot(`
        {
          "error": "invalid_request",
          "error_description": "code_verifier provided does not match code_challenge",
        }
      `);
    });

    it('should revoke on invalid code_verifier', async () => {
      const verifier = createPKCEVerifier();

      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
        code_challenge: await createPKCECodeChallenge(verifier),
        code_challenge_method: 'S256',
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      const res = await tokenRequest(service.requestHandler).send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
        code_verifier: 'invalid',
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).toMatchInlineSnapshot(`
        {
          "error": "invalid_request",
          "error_description": "Invalid 'code_verifier'. The verifier does not conform with the RFC7636 spec. Ref: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1",
        }
      `);
    });

    it('should revoke on non-matching challenge', async () => {
      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      const res = await tokenRequest(service.requestHandler).send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
        code_verifier: createPKCEVerifier(),
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).toMatchInlineSnapshot(`
        {
          "error": "invalid_request",
          "error_description": "code_challenge required",
        }
      `);
    });

    it('should revoke on unsupported code_challende_method', async () => {
      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
        code_challenge: await createPKCECodeChallenge(),
        code_challenge_method: 'invalid'
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      expect(resAuth.statusCode).toBe(400);
      expect(resAuth.body).toMatchInlineSnapshot(`
        {
          "error": "invalid_request",
          "error_description": "Unsupported code_challenge method invalid. The following code_challenge_method are supported: plain, S256",
        }
      `);


    });

    it('should default to plain code_challenge_method if not provided', async () => {
      const verifier = createPKCEVerifier();

      const searchParams = new URLSearchParams({
        response_type: 'code',
        redirect_uri: 'http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf&nonce=21ba8e4a-26af-4538-b98a-bccf031f6754',
        code_challenge: await createPKCECodeChallenge(verifier, 'plain'),
      });

      const resAuth = await request(service.requestHandler)
        .get('/authorize')
        .query(searchParams.toString());

      const res = await tokenRequest(service.requestHandler).send({
        grant_type: 'authorization_code',
        code: getCode(resAuth),
        redirect_uri: 'https://example.com/callback',
        client_id: 'abcecedf',
        code_verifier: verifier,
      });
      expect(res.statusCode).toBe(200);
    });
  });
});

function getCode(response: request.Response) {
  expect(response).toMatchObject({
    header: { location: expect.any(String) },
  });
  const parsed = response as unknown as { header: { location: string } };
  const url = new URL(parsed.header.location);
  return url.searchParams.get('code');
}

function tokenRequest(app: RequestListener) {
  return request(app)
    .post('/token')
    .type('form')
    .expect('Cache-Control', 'no-store')
    .expect('Pragma', 'no-cache');
}
