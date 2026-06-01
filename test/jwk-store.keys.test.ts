import { describe, it, expect } from 'vitest';

import { type JWK } from '../src';
import { privateToPublicKeyTransformer } from '../src/lib/jwk-store.keys';

import { getParsedKey } from './keys';

describe('privateToPublicKeyTransformer', () => {
  it('throws on unsupported algorithm', () => {
    const invalidKey = { alg: 'INVALID_ALG' } as JWK;
    expect(() => privateToPublicKeyTransformer(invalidKey)).toThrow("Unsupported algo 'INVALID_ALG'");
  });

  it('strips all private fields from an RSA (RS256) key', () => {
    const privateKey = getParsedKey('test-rs256-key.json') as JWK;

    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(privateKey).toHaveProperty(field);
    }

    const publicKey = privateToPublicKeyTransformer(privateKey);

    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(publicKey).not.toHaveProperty(field);
    }

    expect(publicKey).toMatchObject({
      kty: 'RSA',
      alg: 'RS256',
      kid: privateKey.kid,
    });
  });

  it('strips private fields from an EC (ES256) key', () => {
    const privateKey = getParsedKey('test-es256-key.json') as JWK;

    expect(privateKey).toHaveProperty('d');

    const publicKey = privateToPublicKeyTransformer(privateKey);

    expect(publicKey).not.toHaveProperty('d');

    expect(publicKey).toMatchObject({
      kty: 'EC',
      alg: 'ES256',
      kid: privateKey.kid,
    });
  });

  it('strips private fields from an EdDSA (OKP) key', () => {
    const privateKey = getParsedKey('test-eddsa-key.json') as JWK;

    expect(privateKey).toHaveProperty('d');

    const publicKey = privateToPublicKeyTransformer(privateKey);

    expect(publicKey).not.toHaveProperty('d');

    expect(publicKey).toMatchObject({
      kty: 'OKP',
      alg: 'EdDSA',
      kid: privateKey.kid,
    });
  });

  it('strips private fields from an Ed25519 (OKP) key', () => {
    const privateKey = getParsedKey('test-ed25519-key.json') as JWK;

    expect(privateKey).toHaveProperty('d');

    const publicKey = privateToPublicKeyTransformer(privateKey);

    expect(publicKey).not.toHaveProperty('d');

    expect(publicKey).toMatchObject({
      kty: 'OKP',
      alg: 'Ed25519',
      kid: privateKey.kid,
    });
  });
});
