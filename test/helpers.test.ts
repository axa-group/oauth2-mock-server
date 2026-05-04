import type { AddressInfo } from 'net';

import { describe, expect, it } from 'vitest';

import {
  assertIsAddressInfo,
  assertIsPlainObject,
  assertIsString,
  assertIsStringOrUndefined,
  assertIsValidTokenRequest,
  createPKCECodeChallenge,
  createPKCEVerifier,
  isValidPkceCodeVerifier,
  normalizePath,
  parseBody,
  parseQuery,
  pkceVerifierMatchesChallenge,
  shift,
  privateToPublicKeyTransformer,
} from '../src/lib/helpers';
import type { CodeChallenge, PKCEAlgorithm, JWK } from '../src';

import { getParsedKey } from './keys';
import { createMockRequest } from './lib/test_helpers';

describe('helpers', () => {
  describe('assertIsString', () => {
    it.each([
      null,
      1,
      true,
      {},
      []
    ])('throws on wrong types (%s)', (input) => {
      expect(() => { assertIsString(input, "boom"); }).toThrow();
    });

    it('does not throw on strings', () => {
      expect(() => { assertIsString("good", "will not throw"); }).not.toThrow();
    });
  });

  describe('assertIsStringOrUndefined', () => {
    it.each([
      null,
      1,
      true,
      {},
      []
    ])('throws on wrong types (%s)', (input) => {
      expect(() => { assertIsStringOrUndefined(input, "boom"); }).toThrow();
    });

    it('does not throw on strings', () => {
      expect(() => { assertIsStringOrUndefined("good", "will not throw"); }).not.toThrow();
    });

    it('does not throw on undefined', () => {
      expect(() => { assertIsStringOrUndefined(undefined, "will not throw"); }).not.toThrow();
    });
  });

  describe('assertIsAddressInfo', () => {
    it.each([
      "nope",
      null,
    ])('throws on wrong values (%s)', (input) => {
      expect(() => { assertIsAddressInfo(input); }).toThrow();
    });

    it('does not throw on valid input', () => {
      const input: AddressInfo = {
        address: "here",
        family: "We are family!",
        port: 42
      };
      expect(() => { assertIsAddressInfo(input); }).not.toThrow();
    });
  });

  describe('assertIsPlainObject', () => {
    it.each([
      "nope",
      null,
      1,
      false,
      []
    ])('throws on wrong values (%s)', (input) => {
      expect(() => { assertIsPlainObject(input, "boom"); }).toThrow();
    });

    it.each([
      {},
      { a: 1 },
    ])('does not throw on valid input (%s)', (input) => {
      expect(() => { assertIsPlainObject(input, "boom"); }).not.toThrow();
    });
  });

  describe('assertIsValidTokenRequest', () => {
    it.each([
      "nope",
      null,
      1,
      false,
      [],
      { grant_type: 1 },
      { grant_type: "g", code: 1 },
      { grant_type: "g", scope: 1 },
      { grant_type: "g", scope: "s", code: 1 },
      { grant_type: "g", scope: 1, code: "c" },
      { grant_type: "g", scope: "1", code: "c", aud: 1 },
      { grant_type: "g", scope: "1", code: "c", aud: [1] },
    ])('throws on wrong values (%s)', (input) => {
      expect(() => { assertIsValidTokenRequest(input); }).toThrow();
    });

    it.each([
      { grant_type: "g" },
      { grant_type: "g", code: "c" },
      { grant_type: "g", scope: "s" },
      { grant_type: "g", scope: "s", code: "c" },
      { grant_type: "g", scope: "s", code: "c", aud: "a" },
      { grant_type: "g", scope: "s", code: "c", aud: ["a", "b"] },
    ])('does not throw on valid input (%s)', (input) => {
      expect(() => { assertIsValidTokenRequest(input); }).not.toThrow();
    });
  });

  describe('shift', () => {
    it('throws on empty array', () => {
      expect(() => shift([])).toThrow();
    });

    it('throws on array containing an undefined entry', () => {
      expect(() => shift([undefined])).toThrow();
    });

    it('does not throw on valid input', () => {
      expect(() => shift(["a"])).not.toThrow();
    });
  });

  describe('pkce', () => {
    describe('code_verifier', () => {
      it('should accept a valid PKCE code_verifier', () => {
        const verifier128 =
          'PXa7p8YHHUAJGrcG2eW0x7FY_EBtRTlaUHnyz1jKWnNp0G-2HZt9KjA0UOp87DmuIqoV4Y_owVsM-QICvrSa5dWxOndVEhSsFMMgy68AYkw4PGHkGaN_aIRIHJ8mQ4EZ';
        const verifier42 = 'xyo94uhy3zKvgB0NJwLms86SwcjtWviEOpkBnGgaLlo';
        expect(isValidPkceCodeVerifier(verifier128)).toBe(true);
        expect(isValidPkceCodeVerifier(verifier42)).toBe(true);

        const verifierWith129chars = `${verifier128}a`;
        expect(isValidPkceCodeVerifier(verifierWith129chars)).toBe(false);
        expect(
          isValidPkceCodeVerifier(verifier42.slice(0, verifier42.length - 1))
        ).toBe(false);
      });

      it('should create a valid code_verifier', () => {
        expect(isValidPkceCodeVerifier(createPKCEVerifier())).toBe(true);
      });

      it('should create a valid code_challenge', async () => {
        const verifier = 'xyo94uhy3zKvgB0NJwLms86SwcjtWviEOpkBnGgaLlo';
        const expectedChallenge = 'b7elB7ZyxIXgFyvBznKvxl7wOB-H17Pz0a3B62NIMFI';
        const generatedCodeChallenge = await createPKCECodeChallenge(
          verifier,
          'S256'
        );
        expect(generatedCodeChallenge).toBe(expectedChallenge);
        const expectedCodeLength = 43; // BASE64-urlencoded sha256 hashes should always be 43 characters in length.
        expect(
          await createPKCECodeChallenge(createPKCEVerifier(), 'S256')
        ).toHaveLength(expectedCodeLength);
      });

      it('should match code_verifier and code_challenge', async () => {
        const verifier = createPKCEVerifier();
        const codeChallengeMethod = 'S256';
        const challenge: CodeChallenge = {
          challenge: await createPKCECodeChallenge(
            verifier,
            codeChallengeMethod
          ),
          method: codeChallengeMethod,
        };
        expect(await pkceVerifierMatchesChallenge(verifier, challenge)).toBe(true);
      });

      it('should throw on an unsupported method', async () => {
        const verifier = createPKCEVerifier();
        await expect(createPKCECodeChallenge(verifier, 'BAD-METHOD' as PKCEAlgorithm)).rejects.toThrow('Unsupported PKCE method ("BAD-METHOD")');
      });
    });
  });

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
  });

  describe('normalizePath', () => {
    it('trims a trailing slash', () => {
      expect(normalizePath('/foo/')).toBe('/foo');
    });

    it('does not trim when there is no trailing slash', () => {
      expect(normalizePath('/foo')).toBe('/foo');
    });

    it('preserves root path', () => {
      expect(normalizePath('/')).toBe('/');
    });
  });

  describe('parseBody', () => {
    describe('JSON body', () => {
      const validBody = '{"foo":"bar"}';
      const validContentType = 'application/json';

      it('throws when JSON body is a primitive', async () => {
        const req = createMockRequest({ body: '42', contentType: validContentType });
        await expect(parseBody(req)).rejects.toThrow();
      });

      it('parses when matching content type', async () => {
        const req = createMockRequest({ body: validBody, contentType: validContentType });
        await expect(parseBody(req)).resolves.toEqual({ foo: 'bar' });
      });

      it('supports array', async () => {
        const req = createMockRequest({ body: '[1,2,3]', contentType: validContentType });
        await expect(parseBody(req)).resolves.toEqual([1, 2, 3]);
      });

      it('returns undefined when non matching content type', async () => {
        const req = createMockRequest({
          body: validBody,
          contentType: 'application/unknown',
        });
        await expect(parseBody(req)).resolves.toBeUndefined();
      });

      it('returns undefined when content-type is absent', async () => {
        const req = createMockRequest({ body: validBody });
        await expect(parseBody(req)).resolves.toBeUndefined();
      });
    });

    describe('URL-encoded body', () => {
      const validBody = 'foo=bar&baz=qux';
      const validContentType = 'application/x-www-form-urlencoded';

      it('parses when matching content type', async () => {
        const req = createMockRequest({
          body: validBody,
          contentType: validContentType,
        });
        await expect(parseBody(req)).resolves.toEqual({ foo: 'bar', baz: 'qux' });
      });

      it('returns undefined when non matching content type', async () => {
        const req = createMockRequest({
          body: validBody,
          contentType: 'application/unknown',
        });
        await expect(parseBody(req)).resolves.toBeUndefined();
      });

      it('returns undefined when content-type is absent', async () => {
        const req = createMockRequest({ body: validBody });
        await expect(parseBody(req)).resolves.toBeUndefined();
      });
    });
  });

  describe('parseQuery', () => {
    it('returns a single value for a non-repeated key', () => {
      const req = createMockRequest({ url: '/?key=val' });
      expect(parseQuery(req)).toEqual({ key: 'val' });
    });

    it('returns an array for a key repeated twice', () => {
      const req = createMockRequest({ url: '/?key=v1&key=v2' });
      expect(parseQuery(req)).toEqual({ key: ['v1', 'v2'] });
    });

    it('returns an array for a key repeated three times', () => {
      const req = createMockRequest({ url: '/?key=v1&key=v2&key=v3' });
      expect(parseQuery(req)).toEqual({ key: ['v1', 'v2', 'v3'] });
    });

    it('returns an empty object when there are no query params', () => {
      const req = createMockRequest({ url: '/' });
      expect(parseQuery(req)).toEqual({});
    });
  });
});
