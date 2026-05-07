import type { AddressInfo } from 'net';

import { describe, expect, it } from 'vitest';

import { assertIsAddressInfo, assertIsJwtWithKid, assertIsPlainObject, assertIsString, assertIsStringOrUndefined, assertIsValidTokenRequest } from '../src/lib/assertions';


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

describe('assertIsJwtWithKid', () => {
  it.each([
    'nope',
    null,
    1,
    false,
    [],
  ])('throws on non-plain-object values (%s)', (input) => {
    expect(() => { assertIsJwtWithKid(input); }).toThrow();
  });

  it('assigns a generated kid when jwk has no kid and no opts provided', () => {
    const jwk: Record<string, unknown> = { alg: 'RS256' };
    assertIsJwtWithKid(jwk);
    expect(typeof jwk.kid).toBe('string');
    expect((jwk.kid).length).toBeGreaterThan(0);
  });

  it('assigns a generated kid when jwk has no kid and opts.kid is undefined', () => {
    const jwk: Record<string, unknown> = { alg: 'RS256' };
    assertIsJwtWithKid(jwk, {});
    expect(typeof jwk.kid).toBe('string');
  });

  it('assigns opts.kid when jwk has no kid and opts.kid is provided', () => {
    const jwk: Record<string, unknown> = { alg: 'RS256' };
    assertIsJwtWithKid(jwk, { kid: 'my-key-id' });
    expect(jwk.kid).toBe('my-key-id');
  });

  it('preserves existing kid when jwk already has one', () => {
    const jwk: Record<string, unknown> = { alg: 'RS256', kid: 'existing-kid' };
    assertIsJwtWithKid(jwk, { kid: 'should-be-ignored' });
    expect(jwk.kid).toBe('existing-kid');
  });
});
