import type { AddressInfo } from 'net';

import {
  assertIsAddressInfo,
  assertIsPlainObject,
  assertIsString,
  assertIsValidTokenRequest,
  shift,
} from '../src/lib/helpers';

describe('helpers', () => {
  describe('assertIsString', () => {
    it.each([
      null,
      1,
      true,
      {},
      []
    ])('throws on wrong types (%s)', (input) => {
      expect(() => assertIsString(input, "boom")).toThrow();
    });

    it('does not throw on strings', () => {
      expect(() => assertIsString("good", "will not throw")).not.toThrow();
    });
  });

  describe('assertIsAddressInfo', () => {
    it.each([
      "nope",
      null,
    ])('throws on wrong values (%s)', (input) => {
      expect(() => assertIsAddressInfo(input)).toThrow();
    });

    it('does not throw on valid input', () => {
      const input: AddressInfo = {
        address: "here",
        family: "We are family!",
        port: 42
      };
      expect(() => assertIsAddressInfo(input)).not.toThrow();
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
      expect(() => assertIsPlainObject(input, "boom")).toThrow();
    });

    it.each([
      {},
      { a: 1 },
    ])('does not throw on valid input (%s)', (input) => {
      expect(() => assertIsPlainObject(input, "boom")).not.toThrow();
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
    ])('throws on wrong values (%s)', (input) => {
      expect(() => assertIsValidTokenRequest(input)).toThrow();
    });

    it.each([
      { grant_type: "g" },
      { grant_type: "g", code: "c" },
      { grant_type: "g", scope: "s" },
      { grant_type: "g", scope: "s", code: "c" },
    ])('does not throw on valid input (%s)', (input) => {
      expect(() => assertIsValidTokenRequest(input)).not.toThrow();
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
});
