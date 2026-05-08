import { describe, it, expect } from 'vitest';

import {
  normalizePath,
  parseBody,
  parseQuery,
  urlCombine,
} from '../src/lib/oauth2-service.http';

import { createMockRequest } from './lib/test_helpers';

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

describe('urlCombine', () => {
  it('appends path to a base without a trailing slash', () => {
    expect(urlCombine('https://example.com', '/token')).toBe(
      'https://example.com/token',
    );
  });

  it('strips the trailing slash from the base before appending path', () => {
    expect(urlCombine('https://example.com/', '/token')).toBe(
      'https://example.com/token',
    );
  });
});
