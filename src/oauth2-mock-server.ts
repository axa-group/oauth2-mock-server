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

import { readFile, writeFileSync } from 'fs';
import { promisify } from 'util';
import { JWK } from 'node-jose';
import path from 'path';

import { OAuth2Server } from './index';
import { assertIsString, shift } from './lib/helpers';
import type { Options } from './lib/types';

const readFileAsync = promisify(readFile);

/* eslint no-console: off */

const defaultOptions: Options = {
  port: 8080,
  keys: [],
  saveJWK: false,
  savePEM: false,
};

module.exports = cli(process.argv.slice(2));

async function cli(args: string[]): Promise<OAuth2Server | null> {
  let options;

  try {
    options = await parseCliArgs(args);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
    return Promise.reject(err);
  }

  if (!options) {
    process.exitCode = 0;
    return Promise.resolve(null);
  }

  return startServer(options);
}

async function parseCliArgs(args: string[]): Promise<Options | null> {
  const opts = { ...defaultOptions };

  while (args.length > 0) {
    const arg = shift(args);

    switch (arg) {
      case '-h':
      case '--help':
        showHelp();
        return null;
      case '-a':
        opts.host = shift(args);
        break;
      case '-p':
        opts.port = parsePort(shift(args));
        break;
      case '--jwk':
        opts.keys.push(await parseJWK(shift(args)));
        break;
      case '--pem':
        opts.keys.push(await parsePEM(shift(args)));
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
  const scriptName = path.basename(__filename, '.ts');
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

function parsePort(portStr: string) {
  const port = parseInt(portStr, 10);

  if (Number.isNaN(port) || port < 0 || port > 65535) {
    throw new Error('Invalid port number.');
  }

  return port;
}

async function parseJWK(filename: string): Promise<JWK.Key> {
  const jwkStr = await readFileAsync(filename, 'utf8');
  return await JWK.asKey(jwkStr);
}

async function parsePEM(filename: string): Promise<JWK.Key> {
  const pem = await readFileAsync(filename, 'utf8');
  return await JWK.asKey(pem, 'pem', {
    kid: path.parse(filename).name,
  });
}

function saveJWK(keys: JWK.Key[]) {
  keys.forEach((key) => {
    const filename = `${key.kid}.json`;
    writeFileSync(filename, JSON.stringify(key.toJSON(true), null, 2));
    console.log(`JSON web key written to file "${filename}".`);
  });
}

function savePEM(keys: JWK.Key[]) {
  keys.forEach((key) => {
    const filename = `${key.kid}.pem`;
    writeFileSync(filename, key.toPEM(true));
    console.log(`PEM-encoded key written to file "${filename}".`);
  });
}

async function startServer(opts: Options) {
  const server = new OAuth2Server();

  await Promise.all(
    opts.keys.map(async (key) => {
      const jwk = await server.issuer.keys.add(key);

      console.log(`Added key with kid "${jwk.kid}"`);
    })
  );

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
  assertIsString(server.issuer.url, 'Empty host');
  console.log(`OAuth 2 issuer is ${server.issuer.url}`);

  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  process.once('SIGINT', async () => {
    await server.stop();
    console.log('OAuth 2 server has been stopped.');
  });

  return server;
}
