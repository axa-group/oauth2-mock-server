import { describe, it, expect } from 'vitest';

import {
  normalizePath,
  urlCombine,
} from '../src/lib/oauth2-service.http';

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
