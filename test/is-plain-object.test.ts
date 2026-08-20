import { describe, expect, it } from 'vitest';

import { isPlainObject } from '../src/lib/is-plain-object';

describe('isPlainObject', () => {
  describe('returns false for falsy values', () => {
    it.each([null, undefined, false, 0, ''])('(%s)', (input) => {
      expect(isPlainObject(input)).toBe(false);
    });
  });

  describe('returns false for non-object primitives', () => {
    it.each(['hello', 42, true, Symbol('s'), () => undefined])('(%s)', (input) => {
      expect(isPlainObject(input)).toBe(false);
    });
  });

  describe('returns false for objects with non-plain prototypes', () => {
    class MyClass {
      value = 1;
    }

    it.each([
      [[], 'array'],
      [new Date(), 'Date'],
      [new Map(), 'Map'],
      [new Set(), 'Set'],
      [/re/, 'RegExp'],
      [new MyClass(), 'class instance'],
      // custom non-null prototype that is not Object.prototype
      [Object.create({ x: 1 }), 'Object.create(obj)'],
    ])('(%s)', (input) => {
      expect(isPlainObject(input)).toBe(false);
    });
  });

  describe('returns true for plain objects', () => {
    it('accepts an empty object literal', () => {
      expect(isPlainObject({})).toBe(true);
    });

    it('accepts a non-empty object literal', () => {
      expect(isPlainObject({ a: 1, b: [1, 2] })).toBe(true);
    });

    it('accepts an object with a null prototype', () => {
      expect(isPlainObject(Object.create(null))).toBe(true);
    });
  });
});
