#!/usr/bin/env node

/**
 * Copyright (c) AXA Assistance France
 *
 * Licensed under the AXA Assistance France License (the "License"); you
 * may not use this file except in compliance with the License.
 * A copy of the License can be found in the LICENSE.md file distributed
 * together with this file.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { OAuth2Server } = require('..');

/* eslint no-console: off */

const defaultOptions = {
  host: undefined,
  port: 8080,
  keys: [],
  saveJWK: false,
  savePEM: false,
};

module.exports = cli(...process.argv.slice(2));

function cli(...args) {
  let options;

  try {
    options = parseCliArgs(args);
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
    return Promise.reject(err);
  }

  if (!options) {
    process.exitCode = 0;
    return Promise.resolve(null);
  }

  return startServer(options);
}

function parseCliArgs(args) {
  const opts = { ...defaultOptions };

  while (args.length > 0) {
    const arg = args.shift();

    switch (arg) {
      case '-h':
      case '--help':
        showHelp();
        return null;
      case '-a':
        opts.host = args.shift();
        break;
      case '-p':
        opts.port = parsePort(args.shift());
        break;
      case '--jwk':
        opts.keys.push(parseJWK(args.shift()));
        break;
      case '--pem':
        opts.keys.push(parsePEM(args.shift()));
        break;
      case '--save-jwk':
        opts.saveJWK = true;
        break;
      case '--save-pem':
        opts.savePEM = true;
        break;
      default:
        throw new Error(`Unrecognized option '${arg}'.`);
    }
  }

  return opts;
}

function showHelp() {
  const scriptName = path.basename(__filename, '.js');
  console.log(`Usage: ${scriptName} [options]
       ${scriptName} -a localhost -p 8080

Options:
  -h, --help        Shows this help information.
  -a <address>      Address on which the server will listen for connections.
                    If omitted, the server will accept connections on [::]
                    if IPv6 is available, or 0.0.0.0 otherwise.
  -p <port>         TCP port on which the server will listen for connections.
                    If omitted, 8080 will be used.
                    If 0 is provided, the operating system will assign
                    an arbitrary unused port.
  --jwk <filename>  Adds a JSON-formatted key to the server's keystore.
                    Can be specified many times.
  --pem <filename>  Adds a PEM-encoded key to the server's keystore.
                    Can be specified many times.
  --save-jwk        Saves all the keys in the keystore as "{kid}.json".
  --save-pem        Saves all the keys in the keystore as "{kid}.pem".

If no keys are added via the --jwk or --pem options, a new random RSA key
will be generated. This key can then be saved to disk with the --save-jwk
or --save-pem options for later reuse.`);
}

function parsePort(portStr) {
  const port = parseInt(portStr, 10);

  if (Number.isNaN(port) || port < 0 || port > 65535) {
    throw new Error('Invalid port number.');
  }

  return port;
}

function parseJWK(filename) {
  const jwkStr = fs.readFileSync(filename, 'utf8');
  return JSON.parse(jwkStr);
}

function parsePEM(filename) {
  return {
    kid: path.parse(filename).name,
    pem: fs.readFileSync(filename, 'utf8'),
  };
}

function saveJWK(keys) {
  keys.forEach((key) => {
    const filename = `${key.kid}.json`;
    fs.writeFileSync(filename, JSON.stringify(key.toJSON(true), null, 2));
    console.log(`JSON web key written to file "${filename}".`);
  });
}

function savePEM(keys) {
  keys.forEach((key) => {
    const filename = `${key.kid}.pem`;
    fs.writeFileSync(filename, key.toPEM(true));
    console.log(`PEM-encoded key written to file "${filename}".`);
  });
}

async function startServer(opts) {
  const server = new OAuth2Server();

  await Promise.all(opts.keys.map(async (key) => {
    let jwk;
    if (key.pem) {
      jwk = await server.issuer.keys.addPEM(key.pem, key.kid);
    } else {
      jwk = await server.issuer.keys.add(key);
    }

    console.log(`Added key with kid "${jwk.kid}"`);
  }));

  if (opts.keys.length === 0) {
    const jwk = await server.issuer.keys.generateRSA(1024);
    opts.keys.push(jwk);

    console.log(`Generated new RSA key with kid "${jwk.kid}"`);
  }

  if (opts.saveJWK) {
    saveJWK(opts.keys);
  }

  if (opts.savePEM) {
    savePEM(opts.keys);
  }

  await server.start(opts.port, opts.host);

  const addr = server.address();
  const hostname = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;

  console.log(`OAuth 2 server listening on http://${hostname}:${addr.port}`);
  console.log(`OAuth 2 issuer is ${server.issuer.url}`);

  process.once('SIGINT', async () => {
    await server.stop();
    console.log('OAuth 2 server has been stopped.');
  });

  return server;
}
