import util from 'node:util';

import { vi } from 'vitest';

import type { OAuth2Server } from '../../src';
import { cli } from '../../src/cli';

export interface Output {
  result: OAuth2Server | null;
  err?: unknown;
  exitCode: string | number | undefined;
  stdout: string;
  stderr: string;
}

export async function exec(args: string[]): Promise<Output> {
  const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

  const res: Output = {
    result: null,
    err: undefined,
    exitCode: undefined,
    stdout: '',
    stderr: '',
  };

  try {
    res.result = await cli(args);
  } catch (err) {
    res.err = err;
  } finally {
    res.exitCode = process.exitCode;
    process.exitCode = undefined;
    res.stdout = logSpy.mock.calls.map((callArgs) => util.format(...callArgs) + '\n').join('');
    res.stderr = errorSpy.mock.calls.map((callArgs) => util.format(...callArgs) + '\n').join('');
    logSpy.mockRestore();
    errorSpy.mockRestore();
  }

  return res;
}
