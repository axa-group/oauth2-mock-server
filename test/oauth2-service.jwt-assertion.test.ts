import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';

import { parseJwtBearerAssertionPayload } from '../src/lib/oauth2-service.jwt-assertion';

import { createJwtAssertion } from './lib/test_helpers';

describe('parseJwtBearerAssertionPayload', () => {
  describe('format validation', () => {
    it('throws when assertion contains no dot (single segment)', () => {
      expect(() => parseJwtBearerAssertionPayload('notajwt')).toThrow(
        "Invalid 'assertion' format: expected at least header.payload",
      );
    });

    it('throws when assertion is an empty string', () => {
      expect(() => parseJwtBearerAssertionPayload('')).toThrow(
        "Invalid 'assertion' format: expected at least header.payload",
      );
    });
  });

  describe('payload JSON validation', () => {
    it('throws when the payload segment decodes to invalid JSON', () => {
      // 'abc' in base64url decodes to bytes whose utf-8 text is not valid JSON
      const assertion = `eyJhbGciOiJub25lIn0.abc.ignored`;

      expect(() => parseJwtBearerAssertionPayload(assertion)).toThrow(
        "Invalid 'assertion' payload: malformed JSON",
      );
    });

    it('throws when the payload segment is a valid JSON string but not an object', () => {
      const assertion = `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify([1, 2, 3])).toString('base64url')}.ignored`;

      expect(() => parseJwtBearerAssertionPayload(assertion)).toThrow(
        "Invalid 'assertion' payload: expected an object",
      );
    });

    it('throws when the payload segment is a valid JSON number', () => {
      const assertion = `eyJhbGciOiJub25lIn0.${Buffer.from('42').toString('base64url')}.ignored`;

      expect(() => parseJwtBearerAssertionPayload(assertion)).toThrow(
        "Invalid 'assertion' payload: expected an object",
      );
    });

    it('throws when the payload segment is missing a sub claim', () => {
      const assertion = createJwtAssertion({ iss: 'client-app' });

      expect(() => parseJwtBearerAssertionPayload(assertion)).toThrow(
        "Invalid 'assertion' payload: 'sub' claim is expected to be a string",
      );
    });

    it('throws when the payload segment is exposing a non string sub claim', () => {
      const assertion = createJwtAssertion({ iss: 'client-app', sub: 123 });

      expect(() => parseJwtBearerAssertionPayload(assertion)).toThrow(
        "Invalid 'assertion' payload: 'sub' claim is expected to be a string",
      );
    });
  });

  describe('successful decoding', () => {
    const payload = {
      sub: 'user@example.com',
      iss: 'client-app',
      aud: 'https://resource.example.com',
      iat: 1700000000,
      exp: 1700003600,
      custom_claim: 'custom-value',
    };

    it('returns the decoded payload from a 2-part assertion (no signature)', () => {
      const assertion = createJwtAssertion(payload);

      const result = parseJwtBearerAssertionPayload(assertion);

      expect(result).toEqual(payload);
    });

    it('returns the decoded payload from a 3-part assertion (with signature segment)', () => {
      const assertion = createJwtAssertion(payload) + '.ignored-signature';

      const result = parseJwtBearerAssertionPayload(assertion);

      expect(result).toEqual(payload);
    });
  });
});
