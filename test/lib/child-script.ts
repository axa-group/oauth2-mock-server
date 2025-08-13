import util from 'node:util';

import type { OAuth2Server } from '../../src';

interface Output {
  result: OAuth2Server | null;
  err?: unknown;
  exitCode: number | undefined;
  stdout: string;
  stderr: string;
}

export async function exec(args: string[]): Promise<Output> {
  process.argv = ['irrelevant', 'irrelevant as well', ...args];

  const log = ConsoleOutHook('log');
  const error = ConsoleOutHook('error');

  const res: Output = {
    result: null,
    err: undefined,
    exitCode: 0,
    stdout: '',
    stderr: ''
  };

  try {
    const mod = await import('../../src/oauth2-mock-server');
    res.result = await mod.default;
  } catch (err) {
    res.err = err;
  } finally {
    log.mockRestore();
    error.mockRestore();
    res.exitCode = process.exitCode;
    process.exitCode = undefined;
  }

  res.stdout = log.output();
  res.stderr = error.output();

  return res;
}

function ConsoleOutHook(method: 'log' | 'error') {
  let entries: string[] = [];

  const old = console[method];
  console[method] = function (msg?: unknown, ...args: unknown[]): void {
    entries.push(util.format(msg, ...args));
    entries.push('\n');
  };

  return {
    mockClear: function mockClear() {
      entries = [];
    },

    mockRestore: function mockRestore() {
      console[method] = old;
    },

    output: function output() {
      return entries.join('');
    },
  };
}
