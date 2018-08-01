'use strict';

const OAuth2Issuer = require('../lib/oauth2-issuer');
const OAuth2Service = require('../lib/oauth2-service');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const testKeys = require('./keys');

describe('OAuth 2 service', () => {
  let service;

  beforeAll(async () => {
    let issuer = new OAuth2Issuer();
    issuer.url = 'https://issuer.example.com';
    await issuer.keys.add(testKeys.get('test-rsa-key.json'));
    
    service = new OAuth2Service(issuer);
  });

  it('should expose an OpenID configuration endpoint', async () => {
    let res = await request(service.requestHandler)
      .get('/.well-known/openid-configuration')
      .expect(200);
    
    let url = service.issuer.url;

    expect(res.body).toMatchObject({
      issuer: url,
      token_endpoint: `${url}/token`,
      token_endpoint_auth_methods_supported: [ 'none' ],
      jwks_uri: `${url}/jwks`,
      response_types_supported: [ 'code' ],
      grant_types_supported: [ 'client_credentials', 'password' ]
    });
  });

  it('should expose an JWKS endpoint', async () => {
    let res = await request(service.requestHandler)
      .get('/jwks')
      .expect(200);
    
    expect(res.body).toMatchObject({
      keys: [
        {
          kty: 'RSA',
          kid: 'test-rsa-key',
          n: expect.any(String),
          e: expect.any(String)
        }
      ]
    });
  });

  it('should expose a token endpoint that handles Client Credentials grants', async () => {
    let res = await tokenRequest(service.requestHandler)
      .send({
        grant_type: 'client_credentials',
        scope: 'urn:first-scope urn:second-scope'
      })
      .expect(200);
    
    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'urn:first-scope urn:second-scope'
    });

    let key = service.issuer.keys.get('test-rsa-key');

    let decoded = jwt.verify(res.body.access_token, key.toPEM(false));
    
    expect(decoded.iss).toEqual(service.issuer.url);
    expect(decoded.scope).toEqual(res.body.scope);
  });

  it('should expose a token endpoint that handles Resource Owner Password Credentials grants', async () => {
    let res = await request(service.requestHandler)
      .post('/token')
      .type('form')
      .send({
        grant_type: 'password',
        username: 'the-resource-owner@example.com',
        scope: 'urn:first-scope urn:second-scope'
      })
      .expect(200);
    
    expect(res.body).toMatchObject({
      access_token: expect.any(String),
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'urn:first-scope urn:second-scope'
    });

    let key = service.issuer.keys.get('test-rsa-key');

    let decoded = jwt.verify(res.body.access_token, key.toPEM(false));
    
    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: res.body.scope,
      sub: 'the-resource-owner@example.com',
      amr: [ 'pwd' ]
    });
  });

  it.each([
    [ 'authorization_code' ],
    [ 'INVALID_GRANT_TYPE' ],
  ])('should not handle token requests unsupported grant types', async (grantType) => {
    let res = await tokenRequest(service.requestHandler)
      .send({
        grant_type: grantType
      })
      .expect(400);
    
    expect(res.body).toMatchObject({
      error: 'invalid_grant'
    });
  });
});

function tokenRequest(app) {
  return request(app)
    .post('/token')
    .type('form')
    .expect('Cache-Control', 'no-store')
    .expect('Pragma', 'no-cache');
}
