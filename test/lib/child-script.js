'use strict';

const util = require('util');

/* eslint no-console: off */

async function exec(scriptPath, ...args) {
  let argv = process.argv;
  process.argv = [ argv[0], scriptPath, ...args ];

  let log = new ConsoleOutHook('log');
  let error = new ConsoleOutHook('error');

  let res = {};

  try {
    res.result = await new Promise(resolve => resolve(require(scriptPath)));
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

  let old = console[method];
  console[method] = (format, ...param) => {
    this.output += util.format(format, ...param) + '\n';
  };

  this.mockClear = function() {
    this.output = '';
  };

  this.mockRestore = function() {
    console[method] = old;
  };
}

module.exports = {
  exec
};
