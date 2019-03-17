'use strict';

const jwt = require('jsonwebtoken');
const OAuth2Issuer = require('../lib/oauth2-issuer');
const testKeys = require('./keys');

describe('OAuth 2 issuer', () => {
  let issuer;

  beforeAll(async () => {
    issuer = new OAuth2Issuer();
    issuer.url = 'https://issuer.example.com';

    await issuer.keys.add(testKeys.get('test-rsa-key.json'));
    await issuer.keys.add(testKeys.get('test-rsa384-key.json'));
    await issuer.keys.add(testKeys.get('test-ec-key.json'));
    await issuer.keys.add(testKeys.get('test-oct-key.json'));
  });

  it('should not allow to build tokens for an unknown \'kid\'', () => {
    expect(() => issuer.buildToken(true, 'unknown-kid')).toThrow('Cannot build token: Unknown key.');
  });

  it('should be able to build unsigned tokens', () => {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 1000;

    const token = issuer.buildToken(false, 'test-rsa-key', null, expiresIn);

    expect(token).toMatch(/^[\w-]+\.[\w-]+\.$/);

    const decoded = jwt.decode(token, { complete: true });

    expect(decoded.header).toEqual({
      alg: 'none',
      typ: 'JWT',
      kid: 'test-rsa-key',
    });

    const p = decoded.payload;

    expect(p).toMatchObject({
      iss: issuer.url,
      iat: expect.any(Number),
      exp: expect.any(Number),
      nbf: expect.any(Number),
    });

    expect(p.iat).toBeGreaterThanOrEqual(now);
    expect(p.exp - p.iat).toEqual(expiresIn);
    expect(p.nbf).toBeLessThan(now);
  });

  it.each([
    ['RSA', 'test-rsa-key'],
    ['EC', 'test-ec-key'],
    ['oct', 'test-oct-key'],
  ])('should be able to build %s-signed tokens', async (keyType, kid) => {
    const testKey = issuer.keys.get(kid);
    const token = issuer.buildToken(true, kid);

    expect(token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    expect(() => jwt.verify(token, getSecret(testKey))).not.toThrow();
  });

  it('should be able to build signed tokens with the algorithm hinted by the key', () => {
    const testKey = issuer.keys.get('test-rsa384-key');
    const token = issuer.buildToken(true, testKey.kid);

    expect(() => jwt.verify(token, getSecret(testKey))).not.toThrow();
  });

  it.each([
    ['urn:scope-1 urn:scope-2'],
    [['urn:scope-1', 'urn:scope-2']],
  ])('should be able to build tokens with a scope', (scopes) => {
    const token = issuer.buildToken(true, 'test-rsa-key', scopes);

    const decoded = jwt.decode(token);

    expect(decoded.scope).toEqual('urn:scope-1 urn:scope-2');
  });

  it('should be able to build tokens and modify the header or the payload before signing', () => {
    /* eslint-disable no-param-reassign */
    const transform = (header, payload) => {
      header.x5t = 'a-new-value';
      payload.sub = 'the-subject';
    };
    /* eslint-enable no-param-reassign */

    const token = issuer.buildToken(true, 'test-rsa-key', transform);

    const decoded = jwt.decode(token, { complete: true });

    expect(decoded.header.x5t).toEqual('a-new-value');
    expect(decoded.payload.sub).toEqual('the-subject');
  });
});

function getSecret(key) {
  switch (key.kty) {
    case 'RSA':
    case 'EC':
      return key.toPEM(false);
    default:
      return key.toObject(true).k;
  }
}
