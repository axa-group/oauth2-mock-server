'use strict';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const OAuth2Issuer = require('../lib/oauth2-issuer');
const OAuth2Service = require('../lib/oauth2-service');
const testKeys = require('./keys');

describe('OAuth 2 service', () => {
  let service;

  beforeAll(async () => {
    const issuer = new OAuth2Issuer();
    issuer.url = 'https://issuer.example.com';
    await issuer.keys.add(testKeys.get('test-rsa-key.json'));

    service = new OAuth2Service(issuer);
  });

  it('should expose an OpenID configuration endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/.well-known/openid-configuration')
      .expect(200);

    const { url } = service.issuer;

    expect(res.body).toMatchObject({
      issuer: url,
      token_endpoint: `${url}/token`,
      authorization_endpoint: `${url}/authorize`,
      userinfo_endpoint: `${url}/userinfo`,
      token_endpoint_auth_methods_supported: ['none'],
      jwks_uri: `${url}/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['client_credentials', 'authorization_code', 'password'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      response_modes_supported: ['query'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: `${url}/revoke`,
    });
  });

  it('should expose an JWKS endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/jwks')
      .expect(200);

    expect(res.body).toMatchObject({
      keys: [
        {
          kty: 'RSA',
          kid: 'test-rsa-key',
          n: expect.any(String),
          e: expect.any(String),
        },
      ],
    });
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

    const key = service.issuer.keys.get('test-rsa-key');

    const decoded = jwt.verify(res.body.access_token, key.toPEM(false));

    expect(decoded.iss).toEqual(service.issuer.url);
    expect(decoded.scope).toEqual(res.body.scope);
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

    const key = service.issuer.keys.get('test-rsa-key');

    const decoded = jwt.verify(res.body.access_token, key.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: res.body.scope,
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

    const key = service.issuer.keys.get('test-rsa-key');

    const decoded = jwt.verify(res.body.access_token, key.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
      sub: 'johndoe',
      amr: ['pwd'],
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

    const key = service.issuer.keys.get('test-rsa-key');

    const decoded = jwt.verify(res.body.access_token, key.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
      sub: 'johndoe',
      amr: ['pwd'],
    });
  });

  it('should redirect to callback url keeping state when calling authorize endpoint with code response type', async () => {
    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res.headers.location).toMatch(/http:\/\/example\.com\/callback\?code=[^&]*&scope=dummy_scope&state=state123/);
  });

  it('should redirect to callback url with an error and keeping state when calling authorize endpoint with an invalid response type', async () => {
    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=invalid_response_type&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res.headers.location).toMatch('http://example.com/callback?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+obtaining+an+access+token+using+this+response_type.&state=state123');
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
    service.once('beforeResponse', (tokenEndpointResponse) => {
      /* eslint-disable no-param-reassign */
      tokenEndpointResponse.body.expires_in = 9000;
      tokenEndpointResponse.body.some_stuff = 'whatever';
      tokenEndpointResponse.statusCode = 302;
      /* eslint-enable no-param-reassign */
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

  it('should expose the userinfo endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/userinfo')
      .expect(200);

    expect(res.body).toMatchObject({
      sub: 'johndoe',
    });
  });

  it('should allow customizing the userinfo response through a beforeUserinfo event', async () => {
    service.once('beforeUserinfo', (userInfoResponse) => {
      /* eslint-disable no-param-reassign */
      userInfoResponse.body = {
        error: 'invalid_token',
        error_message: 'token is expired',
      };
      userInfoResponse.statusCode = 401;
      /* eslint-enable no-param-reassign */
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

    expect(res.body).toEqual(null);
  });

  it('should allow customizing the revoke response through a beforeRevoke event', async () => {
    service.once('beforeRevoke', (revokeResponse) => {
      /* eslint-disable no-param-reassign */
      revokeResponse.body = '';
      revokeResponse.statusCode = 204;
      /* eslint-enable no-param-reassign */
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
});

function tokenRequest(app) {
  return request(app)
    .post('/token')
    .type('form')
    .expect('Cache-Control', 'no-store')
    .expect('Pragma', 'no-cache');
}
