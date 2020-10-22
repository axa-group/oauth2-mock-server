import jwt from 'jsonwebtoken';
import type { JWK } from 'node-jose';

import { OAuth2Issuer } from '../src/lib/oauth2-issuer';
import type { JwtTransform } from '../src/lib/types';
import * as testKeys from './keys';

describe('OAuth 2 issuer', () => {
  let issuer: OAuth2Issuer;

  beforeAll(async () => {
    issuer = new OAuth2Issuer();
    issuer.url = 'https://issuer.example.com';

    await issuer.keys.add(testKeys.getParsed('test-rsa-key.json'));
    await issuer.keys.add(testKeys.getParsed('test-rsa384-key.json'));
    await issuer.keys.add(testKeys.getParsed('test-ec-key.json'));
    await issuer.keys.add(testKeys.getParsed('test-oct-key.json'));
  });

  it('should not allow to build tokens for an unknown \'kid\'', () => {
    expect(() => issuer.buildToken(true, 'unknown-kid')).toThrow('Cannot build token: Unknown key.');
  });

  it('should be able to build unsigned tokens', () => {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 1000;

    const token = issuer.buildToken(false, 'test-rsa-key', undefined, expiresIn);

    expect(token).toMatch(/^[\w-]+\.[\w-]+\.$/);

    const decoded = jwt.decode(token, { complete: true });
    expect(typeof decoded).not.toBe('string');

    const decodedObj = decoded as Record<string, unknown>;
    expect(decodedObj.header).toEqual({
      alg: 'none',
      typ: 'JWT',
      kid: 'test-rsa-key',
    });

    const p = decodedObj.payload;

    expect(p).toMatchObject({
      iss: issuer.url,
      iat: expect.any(Number),
      exp: expect.any(Number),
      nbf: expect.any(Number),
    });

    const parsedP = p as { iss: string; iat: number; exp: number; nbf: number };
    expect(parsedP.iat).toBeGreaterThanOrEqual(now);
    expect(parsedP.exp - parsedP.iat).toEqual(expiresIn);
    expect(parsedP.nbf).toBeLessThan(now);
  });

  it.each([
    ['RSA', 'test-rsa-key'],
    ['EC', 'test-ec-key'],
    ['oct', 'test-oct-key'],
  ])('should be able to build %s-signed tokens', (_keyType, kid) => {
    const testKey = issuer.keys.get(kid);
    expect(testKey).not.toBeNull();
    const token = issuer.buildToken(true, kid);

    expect(token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    expect(() => jwt.verify(token, getSecret(testKey!))).not.toThrow();
  });

  it('should be able to build signed tokens with the algorithm hinted by the key', () => {
    const testKey = issuer.keys.get('test-rsa384-key');
    expect(testKey).not.toBeNull();
    const token = issuer.buildToken(true, testKey!.kid);

    expect(() => jwt.verify(token, getSecret(testKey!))).not.toThrow();
  });

  it.each([
    ['urn:scope-1 urn:scope-2'],
    [['urn:scope-1', 'urn:scope-2']],
  ])('should be able to build tokens with a scope', (scopes) => {
    const token = issuer.buildToken(true, 'test-rsa-key', scopes);

    const decoded = jwt.decode(token);
    expect(decoded).not.toBeNull()
    expect(decoded).toHaveProperty("scope")

    const parsed = decoded as { scope: unknown }
    expect(parsed.scope).toEqual('urn:scope-1 urn:scope-2');
  });

  it('should be able to build tokens and modify the header or the payload before signing', () => {
    const transform: JwtTransform = (header, payload) => {
      header.x5t = 'a-new-value';
      payload.sub = 'the-subject';
    };

    const token = issuer.buildToken(true, 'test-rsa-key', transform);

    const decoded = jwt.decode(token, { complete: true });
    expect(decoded).not.toBeNull();

    expect(decoded).toMatchObject({
      header: { x5t: 'a-new-value' },
      payload: {
        sub: 'the-subject'
      },
    });
  });

  it('should be able to modify the header and the payload through a beforeSigning event', () => {
    issuer.once('beforeSigning', (token) => {
      token.header.x5t = 'a-new-value';
      token.payload.sub = 'the-subject';
    });

    const token = issuer.buildToken(true, 'test-rsa-key');
    const decoded = jwt.decode(token, { complete: true });
    expect(decoded).not.toBeNull();

    expect(decoded).toMatchObject({
      header: { x5t: 'a-new-value' },
      payload: {
        sub: 'the-subject'
      },
    });
  });
});

function getSecret(key: JWK.Key): string {
  switch (key.kty) {
    case 'RSA':
    case 'EC':
      return key.toPEM(false);
    default: {
      const parsed = key.toJSON(true);
      expect(parsed).toMatchObject({ k: expect.any(String) });
      return (parsed as { k: string }).k;
    }
  }
}
