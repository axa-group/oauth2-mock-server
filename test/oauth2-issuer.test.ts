import { describe, it, expect, beforeAll } from 'vitest';

import { OAuth2Issuer } from '../src/lib/oauth2-issuer';
import type { JwtTransform } from '../src/lib/types';

import * as testKeys from './keys';
import { verifyTokenWithKey } from './lib/test_helpers';

describe('OAuth 2 issuer', () => {
  let issuer: OAuth2Issuer;

  beforeAll(async () => {
    issuer = new OAuth2Issuer();
    issuer.url = 'https://issuer.example.com';

    await issuer.keys.add(testKeys.getParsed('test-rs256-key.json'));
    await issuer.keys.add(testKeys.getParsed('test-es256-key.json'));
    await issuer.keys.add(testKeys.getParsed('test-eddsa-key.json'));
  });

  it('should not allow to build tokens for an unknown \'kid\'', async () => {
    await expect(() => issuer.buildToken({ kid: 'unknown-kid' })).rejects.toThrow('Cannot build token: Unknown key.');
  });

  it.each([
    ['test-rs256-key', "RS256"],
    ['test-es256-key', "ES256"],
    ['test-eddsa-key', "EdDSA"],
  ])('should be able to build tokens (%s)', async (kid: string, expectedAlg: string) => {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 1000;

    const token = await issuer.buildToken({ kid, expiresIn });

    expect(token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    const decoded = await verifyTokenWithKey(issuer, token, kid);

    expect(decoded.protectedHeader).toEqual({
      alg: expectedAlg,
      typ: 'JWT',
      kid
    });

    const p = decoded.payload;

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

  const scopeInjector: JwtTransform = (_header, payload) => {
    payload['scope'] = "urn:scope-1 urn:scope-2";
  };

  it.each([
    ['urn:scope-1 urn:scope-2'],
    [['urn:scope-1', 'urn:scope-2']],
    [scopeInjector],
  ])('should be able to build tokens with a scope', async (scopes) => {
    const token = await issuer.buildToken({ kid: 'test-rs256-key', scopesOrTransform: scopes });

    const decoded = await verifyTokenWithKey(issuer, token, 'test-rs256-key');

    expect(decoded.payload).toHaveProperty("scope");

    expect(decoded.payload['scope']).toBe('urn:scope-1 urn:scope-2');
  });

  it('should be able to build tokens and modify the header or the payload before signing', async () => {
    const transform: JwtTransform = (header, payload) => {
      header['x5t'] = 'a-new-value';
      payload['sub'] = 'the-subject';
    };

    const token = await issuer.buildToken({ kid: 'test-rs256-key', scopesOrTransform: transform });

    const decoded = await verifyTokenWithKey(issuer, token, 'test-rs256-key');

    expect(decoded).toMatchObject({
      protectedHeader: { x5t: 'a-new-value' },
      payload: {
        sub: 'the-subject'
      },
    });
  });

  it('should be able to modify the header and the payload through a beforeSigning event', async () => {
    issuer.once('beforeSigning', (token) => {
      token.header.x5t = 'a-new-value';
      token.payload.sub = 'the-subject';
    });

    const token = await issuer.buildToken({ kid: 'test-rs256-key' });
    const decoded = await verifyTokenWithKey(issuer, token, 'test-rs256-key');

    expect(decoded).toMatchObject({
      protectedHeader: { x5t: 'a-new-value' },
      payload: {
        sub: 'the-subject'
      },
    });
  });
});
