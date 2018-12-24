'use strict';

const JWKStore = require('../lib/jwk-store');
const testKeys = require('./keys');

describe('JWK Store', () => {
  it('should be able to generate a new RSA key', async () => {
    let store = new JWKStore();
    let key = await store.generateRSA(256);

    expect(key).toMatchObject({
      length: 256,
      kty: 'RSA',
      use: 'sig',
      kid: expect.stringMatching(/^[\w-]+$/)
    });
  });

  it.each([
    [ 'RSA', testKeys.get('test-rsa-key.json'), 512 ],
    [ 'EC', testKeys.get('test-ec-key.json'), 256 ],
    [ 'oct', testKeys.get('test-oct-key.json'), 512 ]
  ])('should be able to add a JWK \'%s\' key to the store', async (keyType, testKey, expectedLength) => {
    let store = new JWKStore();
    let key = await store.add(testKey);

    expect(key).toMatchObject({
      length: expectedLength,
      kty: keyType,
      use: 'sig',
      kid: testKey.kid
    });
  });

  it.each([
    [ 'RSA', testKeys.get('test-rsa-key.pem'), 512 ],
    [ 'EC', testKeys.get('test-ec-key.pem'), 256 ]
  ])('should be able to add a PEM-encoded \'%s\' key to the store', async (keyType, testPEMKey, expectedLength) => {
    let store = new JWKStore();
    let key = await store.addPEM(testPEMKey, null, 'sig');

    expect(key).toMatchObject({
      length: expectedLength,
      kty: keyType,
      kid: expect.stringMatching(/^[\w-]+$/),
      use: 'sig'
    });
  });

  it('should be able to retrieve a key by its \'kid\'', async () => {
    let store = new JWKStore();
    let key1 = await store.generateRSA(512, 'key-one');
    let key2a = await store.generateRSA(512, 'key-two');
    let key2b = await store.generateRSA(512, 'key-two');

    expect(key1.kid).not.toEqual(key2a.kid);
    expect(key2a.kid).toEqual(key2b.kid);

    let stored1 = store.get('key-one');
    let stored2a = store.get('key-two');
    let stored2b = store.get('key-two');
    let stored2c = store.get('key-two');
    let stored3 = store.get('non-existing-kid');

    expect(stored1).toBe(key1);
    expect(stored2a).toBe(key2a);
    expect(stored2b).toBe(key2b);
    expect(stored2c).toBe(key2a);
    expect(stored3).toBeNull();
  });

  it('should return null when trying to retrieve a key from an empty store', async () => {
    let store = new JWKStore();

    let res1 = store.get();
    let res2 = store.get('non-existing-kid');

    expect(res1).toBeNull();
    expect(res2).toBeNull();
  });

  it('should be able to produce a JSON representation of the public keys in the key store', async () => {
    let store = new JWKStore();
    await store.generateRSA(512, 'key-one');
    await store.generateRSA(512, 'key-two');
    await store.generateRSA(512, 'key-two');

    let jwks = store.toJSON();

    expect(jwks.keys).toHaveLength(3);
    expect(jwks.keys.map(key => key.kid).sort()).toEqual([ 'key-one', 'key-two', 'key-two']);

    for (let jwk of jwks.keys) {
      expect(store.get(jwk.kid)).not.toBeNull();

      ['e', 'n'].forEach(prop => {
        expect(jwk).toHaveProperty(prop);
      });

      ['d', 'p', 'q', 'dp', 'dq', 'qi'].forEach(prop => {
        expect(jwk).not.toHaveProperty(prop);
      });
    }
  });

  it('should be able to retrieve the private key of a key', async () => {
    let store = new JWKStore();
    let key = await store.generateRSA(512);
    
    let jwk = key.toJSON(true);

    ['e', 'n', 'd', 'p', 'q', 'dp', 'dq', 'qi'].forEach(prop => {
      expect(jwk).toHaveProperty(prop);
    });
  });
});
