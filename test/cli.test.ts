import { writeFile } from 'fs/promises';

import { afterEach, describe, it, expect, vi } from 'vitest';

import { exec } from './lib/child-script';

vi.mock('fs/promises', () => ({
  writeFile: vi.fn().mockImplementation(() => ''),
}));

const mockWriteFileAsync = vi.mocked(writeFile);

describe('CLI', () => {
  afterEach(() => {
    vi.resetModules();
  });

  it.each([
    ['-h'],
    ['--help'],
  ])('should be able to print out usage information (%s)', async (arg) => {
    const res = await executeCli(arg);

    expect(res.result).toBeNull();
    expect(res.exitCode).toBeUndefined();
    expect(res.stdout).toMatch(/^Usage: oauth2-mock-server \[options\]/);
  });

  it.each([
    ['-unknown'],
    ['--unknown'],
    ['123'],
    [' '],
  ])('should not allow unrecognized options', async (arg) => {
    const res = await executeCli(arg);

    expect(res).toEqual(errorResponse(`Unrecognized option '${arg}'.`));
  });

  it.each([
    ['0.0.0.0'],
    ['::'],
    ['localhost'],
    ['127.0.0.1'],
    ['::1'],
  ])('should accept a binding address (%s)', async (address) => {
    const res = await executeCli('-a', address, '-p', '0');

    expect(res).toEqual({
      result: expect.any(Object),
      exitCode: undefined,
      stdout: expect.any(String),
      stderr: '',
    });

    expect(res.stdout).toMatch(/^OAuth 2 server listening on http:\/\/.+?:\d+$/m);
    expect(res.stdout).toMatch(/^OAuth 2 issuer is http:\/\/localhost:\d+$/m);
  });

  it.each([
    ['not-a-number'],
    ['-1'],
    ['65536'],
  ])('should not allow invalid port number \'%s\'', async (port) => {
    const res = await executeCli('-p', port);

    expect(res).toEqual(errorResponse('Invalid port number.'));
  });

  it('should allow importing JSON-formatted keys', async () => {
    const res = await executeCli('--jwk', 'test/keys/test-rs256-key.json', '--jwk', 'test/keys/test-es256-key.json', '--jwk', 'test/keys/test-eddsa-key.json', '-p', '0');

    expect(res.stdout).toMatch(/^Added key with kid "test-rs256-key"$/m);
    expect(res.stdout).toMatch(/^Added key with kid "test-es256-key"$/m);
    expect(res.stdout).toMatch(/^Added key with kid "test-eddsa-key"$/m);

    expect(res.result).not.toBeNull();
    const { keys } = res.result!.issuer;

    expect(keys.get('test-rs256-key')).toBeDefined();
    expect(keys.get('test-es256-key')).toBeDefined();
    expect(keys.get('test-eddsa-key')).toBeDefined();
  });

  it('should allow exporting JSON-formatted keys', async () => {

    let generatedPath = '';

    mockWriteFileAsync.mockImplementation((p) => {
      if (typeof (p) !== 'string') {
        throw new Error("Unepextected path type.");
      }

      generatedPath = p;

      return Promise.resolve();
    });

    const res = await executeCli('--save-jwk', '-p', '0');

    expect(res.result).not.toBeNull();
    const key = res.result!.issuer.keys.get();

    expect(key).toBeDefined();
    expect(key).toHaveProperty('kid');

    expect(generatedPath).toBe(`${key!.kid}.json`);

    expect(res.stdout).toMatch(/^Generated new RSA key with kid "[\w-]+"$/m);
    expect(res.stdout).toMatch(/^JSON web key written to file "[\w-]+\.json"\.$/m);
  });
});

async function executeCli(...args: string[]) {
  const res = await exec(args);

  if (res.result) {
    await res.result.stop();
  }

  return res;
}

function errorResponse(message: string) {
  return {
    err: expect.any(Error),
    result: null,
    exitCode: 1,
    stdout: '',
    stderr: `${message}\n`,
  };
}
