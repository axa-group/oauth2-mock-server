'use strict';

const util = require('util');

/* eslint no-console: off */

async function exec(scriptPath, ...args) {
  const argv = process.argv; /* eslint-disable-line prefer-destructuring */
  process.argv = [argv[0], scriptPath, ...args];

  const log = new ConsoleOutHook('log');
  const error = new ConsoleOutHook('error');

  const res = {};

  try {
    /* eslint-disable-next-line global-require, import/no-dynamic-require */
    res.result = await Promise.resolve(require(scriptPath));
  } catch (err) {
    res.err = err;
  } finally {
    log.mockRestore();
    error.mockRestore();
    res.exitCode = process.exitCode;
    process.exitCode = undefined;
  }

  res.stdout = log.output;
  res.stderr = error.output;

  return res;
}

function ConsoleOutHook(method) {
  this.output = '';

  const old = console[method];
  console[method] = (format, ...param) => {
    this.output += util.format(`${format}\n`, ...param);
  };

  this.mockClear = function mockClear() {
    this.output = '';
  };

  this.mockRestore = function mockRestore() {
    console[method] = old;
  };
}

module.exports = {
  exec,
};
