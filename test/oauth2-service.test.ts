import request from 'supertest';
import jwt from 'jsonwebtoken';
import { IncomingMessage } from 'http';
import type { Express } from 'express';

import { OAuth2Issuer } from '../src/lib/oauth2-issuer';
import { OAuth2Service } from '../src/lib/oauth2-service';
import * as testKeys from './keys';
import { MutableRedirectUri } from '../src/lib/types';

describe('OAuth 2 service', () => {
  let service: OAuth2Service;

  beforeAll(async () => {
    const issuer = new OAuth2Issuer();
    issuer.url = 'https://issuer.example.com';
    await issuer.keys.add(testKeys.getParsed('test-rsa-key.json'));

    service = new OAuth2Service(issuer);
  });

  it('should expose an OpenID configuration endpoint', async () => {
    const res = await request(service.requestHandler)
      .get('/.well-known/openid-configuration')
      .expect(200);

    const { url } = service.issuer;
    expect(url).not.toBeNull();

    expect(res.body).toMatchObject({
      issuer: url,
      token_endpoint: `${url!}/token`,
      authorization_endpoint: `${url!}/authorize`,
      userinfo_endpoint: `${url!}/userinfo`,
      token_endpoint_auth_methods_supported: ['none'],
      jwks_uri: `${url!}/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['client_credentials', 'authorization_code', 'password'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      response_modes_supported: ['query'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: `${url!}/revoke`,
      subject_types_supported: ['public'],
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
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string; scope: string };
    const decoded = jwt.verify(resBody.access_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: resBody.scope,
    });
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    const decoded = jwt.verify(resBody.access_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string };
    const decoded = jwt.verify(resBody.access_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    const resBody = res.body as {
      access_token: string;
      scope: string;
      id_token: string;
    };
    const decoded = jwt.verify(resBody.access_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
      sub: 'johndoe',
      amr: ['pwd'],
    });

    const decodedIdToken = jwt.verify(resBody.id_token, key!.toPEM(false));
    expect(decodedIdToken).toMatchObject({
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    const resBody = res.body as { access_token: string };
    const decoded = jwt.verify(resBody.access_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
      scope: 'dummy',
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      id_token: expect.any(String),
    });
    const resBody = res.body as { id_token: string };
    const decoded = jwt.verify(resBody.id_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      id_token: expect.any(String),
    });
    const resBody = res.body as { id_token: string };
    const decoded = jwt.verify(resBody.id_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
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

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      id_token: expect.any(String),
    });
    const resBody = res.body as { id_token: string };
    const decoded = jwt.verify(resBody.id_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
      sub: 'johndoe',
      aud: 'abcecedf',
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
        location: expect.stringMatching(/http:\/\/example\.com\/callback\?code=[^&]*&scope=dummy_scope&state=state123/)
      }
    })
  });

  it('should be able to manipulate url and query params when redirecting within authorize endpoint', async () => {
    service.once('beforeAuthorizeRedirect', (authorizeRedirectUri: MutableRedirectUri, req) => {
      expect(req).toBeInstanceOf(IncomingMessage);

      expect(authorizeRedirectUri.url.toString()).toMatch(/http:\/\/example.com\/callback\?code=[^&]+&scope=dummy_scope&state=state123/);

      authorizeRedirectUri.url.hostname = 'foo.com';
      authorizeRedirectUri.url.pathname = '/cb';
      authorizeRedirectUri.url.protocol = 'https';
      authorizeRedirectUri.url.searchParams.set('code', 'testcode');
      authorizeRedirectUri.url.searchParams.set('extra_param', 'value');
      authorizeRedirectUri.url.searchParams.delete('scope');
    });

    const res = await request(service.requestHandler)
      .get('/authorize')
      .query('response_type=code&redirect_uri=http://example.com/callback&scope=dummy_scope&state=state123&client_id=abcecedf')
      .redirects(0)
      .expect(302);

    expect(res).toMatchObject({
      headers: {
        location: expect.stringMatching(/https:\/\/foo\.com\/cb\?code=testcode&state=state123&extra_param=value/)
      }
    })
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
    })
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
    });

    const res = await tokenRequest(service.requestHandler)
      .set('Custom-Header', 'custom-token-value')
      .send({
        grant_type: 'client_credentials',
        scope: 'a-test-scope',
      })
      .expect(200);

    const key = service.issuer.keys.get('test-rsa-key');
    expect(key).not.toBeNull();

    expect(res.body).toMatchObject({
      access_token: expect.any(String),
    });
    const resBody = res.body as { access_token: string };

    const decoded = jwt.verify(resBody.access_token, key!.toPEM(false));

    expect(decoded).toMatchObject({
      iss: service.issuer.url,
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

    expect(res.body).toEqual(null);
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
      .query(`post_logout_redirect_uri=${postLogoutRedirectUri}`)
      .redirects(0)
      .expect(302);

    expect(res.headers.location).toBe(postLogoutRedirectUri)
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
      .query(`post_logout_redirect_uri=${postLogoutRedirectUri}`)
      .redirects(0)
      .expect(302);

    expect(res.headers.location).toBe('http://post-logout.com/signin?param=test')
  });
});

function getCode(response: request.Response) {
  expect(response).toMatchObject({
    header: { location: expect.any(String) },
  });
  const parsed = response as { header: { location: string } };
  const url = new URL(parsed.header.location);
  return url.searchParams.get('code');
}

function tokenRequest(app: Express) {
  return request(app)
    .post('/token')
    .type('form')
    .expect('Cache-Control', 'no-store')
    .expect('Pragma', 'no-cache');
}
