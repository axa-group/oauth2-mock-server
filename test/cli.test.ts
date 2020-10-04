import { exec } from './lib/child-script';

const cliPath = require.resolve('../src/oauth2-mock-server');

describe('CLI', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  it.each([
    ['-h'],
    ['--help'],
  ])('should be able to print out usage information (%s)', async (arg) => {
    const res = await executeCli(arg);

    expect(res.result).toBeNull();
    expect(res.exitCode).toBe(0);
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
    const res = await executeCli('--jwk', 'test/keys/test-rsa-key.json', '--jwk', 'test/keys/test-ec-key.json', '--jwk', 'test/keys/test-oct-key.json', '-p', '0');

    expect(res.stdout).toMatch(/^Added key with kid "test-rsa-key"$/m);
    expect(res.stdout).toMatch(/^Added key with kid "test-ec-key"$/m);
    expect(res.stdout).toMatch(/^Added key with kid "test-oct-key"$/m);

    expect(res.result).not.toBeNull();
    const { keys } = res.result!.issuer;

    expect(keys.get('test-rsa-key')).not.toBeNull();
    expect(keys.get('test-ec-key')).not.toBeNull();
    expect(keys.get('test-oct-key')).not.toBeNull();
  });

  it('should allow importing PEM-encoded keys', async () => {
    const res = await executeCli('--pem', 'test/keys/test-rsa-key.pem', '--pem', 'test/keys/test-ec-key.pem', '-p', '0');

    expect(res.stdout).toMatch(/^Added key with kid "test-rsa-key"$/m);
    expect(res.stdout).toMatch(/^Added key with kid "test-ec-key"$/m);

    expect(res.result).not.toBeNull();
    const { keys } = res.result!.issuer;

    expect(keys.get('test-rsa-key')).not.toBeNull();
    expect(keys.get('test-ec-key')).not.toBeNull();
  });

  it('should allow exporting JSON-formatted keys', async () => {
    const fs = require('fs');
    const wfn = jest.spyOn(fs, 'writeFileSync').mockImplementation();

    const res = await executeCli('--save-jwk', '-p', '0');

    expect(res.result).not.toBeNull();
    const key = res.result!.issuer.keys.get();

    expect(key).not.toBeNull();
    expect(key).toHaveProperty('kid');

    expect(wfn).toHaveBeenCalledWith(
      `${key!.kid}.json`,
      expect.stringMatching(/^{(.|\n)+}$/),
    );

    wfn.mockRestore();

    expect(res.stdout).toMatch(/^Generated new RSA key with kid "[\w-]+"$/m);
    expect(res.stdout).toMatch(/^JSON web key written to file "[\w-]+\.json"\.$/m);
  });

  it('should allow exporting PEM-encoded keys', async () => {
    const fs = require('fs');
    const wfn = jest.spyOn(fs, 'writeFileSync').mockImplementation();

    const res = await executeCli('--save-pem', '-p', '0');

    expect(res.result).not.toBeNull();
    const key = res.result!.issuer.keys.get();
    expect(key).not.toBeNull();
    expect(key).toHaveProperty('kid');

    expect(wfn).toHaveBeenCalledWith(
      `${key!.kid}.pem`,
      expect.stringMatching(/^-----BEGIN RSA PRIVATE KEY-----\r\n(.|\r\n)+\r\n-----END RSA PRIVATE KEY-----\r\n$/),
    );

    wfn.mockRestore();

    expect(res.stdout).toMatch(/^Generated new RSA key with kid "[\w-]+"$/m);
    expect(res.stdout).toMatch(/^PEM-encoded key written to file "[\w-]+\.pem"\.$/m);
  });
});

async function executeCli(...args: string[]) {
  const res = await exec(cliPath, args);

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
