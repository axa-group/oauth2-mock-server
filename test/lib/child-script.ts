import util from 'util';
import { OAuth2Server } from '../../src';

interface Output {
  result: OAuth2Server | null;
  err?: unknown;
  exitCode: number | undefined;
  stdout: string;
  stderr: string;
}

export async function exec(scriptPath: string, args: string[]): Promise<Output> {
  const argv = process.argv;
  process.argv = [argv[0], scriptPath, ...args];

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
    res.result = await Promise.resolve(require(scriptPath)) as OAuth2Server | null;
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
