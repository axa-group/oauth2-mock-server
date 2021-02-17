import { JWKStore } from '../src/lib/jwk-store';
import * as testKeys from './keys';

describe('JWK Store', () => {
  describe('generate()', () => {
    it.each([
      ["RSASSA-PKCS1-v1_5", "RS256", "RSA"],
      ["RSASSA-PKCS1-v1_5", "RS384", "RSA"],
      ["RSASSA-PKCS1-v1_5", "RS512", "RSA"],
      ["RSASSA-PSS", "PS256", "RSA"],
      ["RSASSA-PSS", "PS384", "RSA"],
      ["RSASSA-PSS", "PS512", "RSA"],
      ["ECDSA", "ES256", "EC"],
      ["ECDSA", "ES384", "EC"],
      ["ECDSA", "ES512", "EC"],
    ])('should be able to generate a new %s based key (alg = %s)', async (_kind: string, alg: string, expectedKty: string) => {
      const store = new JWKStore();
      const key = await store.generate(alg);
      expect(key).toMatchObject({
        alg: alg,
        kty: expectedKty,
        kid: expect.stringMatching(/^[\w-]+$/),
      });
    });

    it.each([
      "Ed25519",
      "Ed448",
    ])('should be able to generate a new EdDSA based key (crv = %s)', async (crv: string) => {
      const store = new JWKStore();
      const key = await store.generate('EdDSA', { crv });
      expect(key).toMatchObject({
        alg: 'EdDSA',
        kty: 'OKP',
        crv,
        kid: expect.stringMatching(/^[\w-]+$/),
      });
    });

    it.each([
      "RS123",
      "dunno",
    ])('throws on unsupported algs (alg = %s)', async (alg: string) => {
      const store = new JWKStore();

      await expect(() => store.generate(alg)).rejects.toThrow("unsupported or invalid JWK \"alg\" (Algorithm) Parameter value");
    });

    it.each([
      "Ed007",
      "dunno",
    ])('throws on unsupported crv for EdDSA alg (crv = %s)', async (crv: string) => {
      const store = new JWKStore();

      await expect(() => store.generate('EdDSA', { crv })).rejects.toThrow("invalid or unsupported crv option provided, supported values are Ed25519 and Ed448");
    });

    it.each([
      ['RS256', ['e', 'n', 'd', 'p', 'q', 'dp', 'dq', 'qi']]
    ])('should return the private key of a key (alg = %s)', async (alg: string, expectedProps: string[]) => {
      const store = new JWKStore();
      const jwk = await store.generate(alg);

      for (const prop of expectedProps) {
        expect(jwk).toHaveProperty(prop);
      }
    });
  });

  describe("add()", () => {
    it.each([
      ['RSA', testKeys.getParsed('test-rs256-key.json')],
      ['EC', testKeys.getParsed('test-es256-key.json')],
      ['OKP', testKeys.getParsed('test-eddsa-key.json')],
    ])('should be able to add a JWK key to the store (kty = %s)', async (keyType, testKey) => {
      const store = new JWKStore();
      const key = await store.add(testKey);

      expect(key).toMatchObject({
        kty: keyType,
        kid: testKey.kid,
      });
    });

    it('throws when serialized key lacks the "alg" property', async () => {
      const store = new JWKStore();

      const jwk = testKeys.getParsed('test-rs256-key.json');
      delete jwk.alg;

      await expect(() => store.add(jwk)).rejects.toThrow("Unspecified alg");
    });

    it('adding a key will overwrite an existing key in the store bearing the same "kid"', async () => {
      const store = new JWKStore();

      const one = testKeys.getParsed('test-rs256-key.json');
      expect(one.kty).toEqual("RSA");
      one.kid = "new_id";
      await store.add(one);

      const retrievedOne = store.get("new_id");
      expect(retrievedOne).not.toBeNull();
      expect(retrievedOne!.kty).toEqual(one.kty);

      const two = testKeys.getParsed('test-es256-key.json');
      expect(two.kty).toEqual("EC");
      two.kid = "new_id";
      await store.add(two);

      const retrievedTwo = store.get("new_id");
      expect(retrievedTwo).not.toBeNull();
      expect(retrievedTwo!.kty).toEqual(two.kty);
    });
  });

  describe("get()", () => {
    it('should be able to retrieve a key by its \'kid\'', async () => {
      const store = new JWKStore();
      const key1 = await store.generate('RS256', { kid: 'key-one' });
      const key2 = await store.generate('RS256', { kid: 'key-two' });

      expect(key1.kid).not.toEqual(key2.kid);

      const stored1 = store.get('key-one');
      const stored2a = store.get('key-two');
      const stored2b = store.get('key-two');
      const stored3 = store.get('non-existing-kid');

      expect(stored1).toBe(key1);
      expect(stored2a).toBe(key2);
      expect(stored2b).toBe(key2);
      expect(stored3).toBeUndefined();
    });

    it('should be able to retrieve keys in a round-robin manner', async () => {
      const store = new JWKStore();
      await store.generate('RS256', { kid: 'key-one' });
      await store.generate('RS256', { kid: 'key-two' });
      await store.generate('RS256', { kid: 'key-three' });

      const key1 = store.get();
      expect(key1).not.toBeNull();

      const key2 = store.get();
      expect(key2).not.toBeNull();
      expect(key2!.kid).not.toEqual(key1!.kid);

      const key3 = store.get();
      expect(key3).not.toBeNull();
      expect(key3!.kid).not.toEqual(key1!.kid);
      expect(key3!.kid).not.toEqual(key2!.kid);

      const key4 = store.get();
      expect(key4).not.toBeNull();
      expect(key4!.kid).toEqual(key1!.kid);
    });

    it('should return undefined when trying to retrieve a key from an empty store', () => {
      const store = new JWKStore();

      const res1 = store.get();
      const res2 = store.get('non-existing-kid');

      expect(res1).toBeUndefined();
      expect(res2).toBeUndefined();
    });
  });

  describe("toJSON()", () => {
    it.each([
      undefined,
      true,
      false
    ])('should be able to produce a JSON representation of the public keys in the key store (including private fields: %s)', async (shouldIncludePrivates?: boolean) => {
      const store = new JWKStore();
      await store.generate('RS256', { kid: 'key-one' });
      await store.generate('RS256', { kid: 'key-two' });
      await store.generate('RS256', { kid: 'key-three' });

      const jwks = store.toJSON(shouldIncludePrivates);
      expect(jwks).toHaveProperty("keys");
      expect(jwks.keys).toBeInstanceOf(Array);

      const keys = jwks.keys as unknown[];
      expect(keys).toHaveLength(3);

      for (const key of keys) {
        expect(key).toBeInstanceOf(Object);
        expect(key).toHaveProperty("kid");
        expect(typeof (key as Record<string, unknown>).kid).toBe("string");
      }

      const keysWithKid = keys as { kid: string }[];
      expect(keysWithKid.map((key) => key.kid).sort()).toEqual(['key-one', 'key-three', 'key-two']);

      keysWithKid.forEach((jwk) => {
        expect(store.get(jwk.kid)).not.toBeNull();

        ['e', 'n'].forEach((prop) => {
          expect(jwk).toHaveProperty(prop);
        });

        ['d', 'p', 'q', 'dp', 'dq', 'qi'].forEach((prop) => {
          if (shouldIncludePrivates === true) {
            expect(jwk).toHaveProperty(prop);
          } else {
            expect(jwk).not.toHaveProperty(prop);
          }
        });
      });
    });
  });
});
