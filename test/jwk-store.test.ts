import { JWK } from 'jose/types';

import { JWKStore } from '../src/lib/jwk-store';
import * as testKeys from './keys';

describe('JWK Store', () => {
  it('should be able to generate a new RSA key', async () => {
    const store = new JWKStore();
    const key = await store.generate('RS256');

    expect(key).toMatchObject({
      kty: 'RSA',
      use: 'sig',
      kid: expect.stringMatching(/^[\w-]+$/),
    });
  });

  it('should be able to specify a new RSA key size', async () => {
    const store = new JWKStore();
    const key = await store.generate('RS256');

    expect(key).toMatchObject({
      kty: 'RSA',
      use: 'sig',
      kid: expect.stringMatching(/^[\w-]+$/),
    });
  });

  it('throws when a specified key size is less than 2048', async () => {
    const store = new JWKStore();

    await expect(() => store.generate('RS256')).rejects.toThrow();
  });

  it.each([
    ['RSA', testKeys.getParsed('test-rsa-key.json')],
    ['EC', testKeys.getParsed('test-ec-key.json')],
    ['oct', testKeys.getParsed('test-oct-key.json')],
  ])('should be able to add a JWK \'%s\' key to the store', async (keyType, testKey) => {
    const store = new JWKStore();
    const key = await store.add(testKey);

    expect(key).toMatchObject({
      kty: keyType,
      use: 'sig',
      kid: testKey.kid,
    });
  });

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
    expect(stored3).toBeNull();
  });

  it('should return null when trying to retrieve a key from an empty store', () => {
    const store = new JWKStore();

    const res1 = store.get();
    const res2 = store.get('non-existing-kid');

    expect(res1).toBeNull();
    expect(res2).toBeNull();
  });

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

  it('should be able to retrieve the private key of a key', async () => {
    const store = new JWKStore();
    const jwk = await store.generate('RS256');

    ['e', 'n', 'd', 'p', 'q', 'dp', 'dq', 'qi'].forEach((prop) => {
      expect(jwk).toHaveProperty(prop);
    });
  });

  it('should normalize key "use" value to "sig" when unset', async () => {
    const initialKey = testKeys.getParsed('test-rsa-key.json');

    expect(initialKey).not.toHaveProperty("use");

    const store = new JWKStore();
    const key = await store.add(initialKey);

    expect(key).toHaveProperty("use");
    expect(key.use).toEqual("sig");

    const retrievedKey = store.get(key.kid);

    expect(retrievedKey).toHaveProperty("use");
    expect(key.use).toEqual("sig");
  });

  it('adding a key will overwrite an existing key in the store bearing the same "kid"', async () => {
    const store = new JWKStore();

    const one = testKeys.getParsed('test-rsa-key.json');
    expect(one.kty).toEqual("RSA");
    one.kid = "new_id";
    await store.add(one);

    const retrievedOne = store.get("new_id");
    expect(retrievedOne).not.toBeNull();
    expect(retrievedOne!.kty).toEqual(one.kty);

    const two = testKeys.getParsed('test-ec-key.json');
    expect(two.kty).toEqual("EC");
    two.kid = "new_id";
    await store.add(two);

    const retrievedTwo = store.get("new_id");
    expect(retrievedTwo).not.toBeNull();
    expect(retrievedTwo!.kty).toEqual(two.kty);
  });

  it('should preserve key "use" value when set', async () => {
    const initialKey = testKeys.getParsed('test-rsa-key.json');

    expect(initialKey).not.toHaveProperty("use");

    const keyWithUseProperty: JWK = { ...initialKey, use: 'enc' };

    const store = new JWKStore();
    const key = await store.add(keyWithUseProperty);

    expect(key).toHaveProperty("use");
    expect(key.use).toEqual("enc");

    const retrievedKey = store.get(key.kid);

    expect(retrievedKey).toHaveProperty("use");
    expect(key.use).toEqual("enc");
  });
});
