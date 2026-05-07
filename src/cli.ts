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

/** @module cli */

import { writeFile } from 'node:fs/promises';

import { assertIsString } from './lib/assertions';
import { readJsonFromFile, shift } from './lib/helpers';
import type { JWK, Options } from './lib/types';
import { OAuth2Server } from './lib/oauth2-server';

/* eslint no-console: off */

const scriptName = 'oauth2-mock-server';

const defaultOptions: Options = {
  port: 8080,
  keys: [],
  saveJWK: false,
  issuerUrlTrailingSlash: false,
};

/**
 * Runs the CLI with the given arguments and returns the started server, or
 * null when the help option is passed.
 * @param args - Command-line arguments to parse.
 * @returns The started server, or null if help was requested.
 */
export const cli = async (args: string[]): Promise<OAuth2Server | null> => {
  let options;

  try {
    options = parseCliArgs(args);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
    throw err;
  }

  if (options === null) {
    showHelp(scriptName);
    return null;
  }

  return await startServer(options);
};

const parseCliArgs = (args: string[]): Options | null => {
  const opts: Options = { ...defaultOptions, keys: [] };

  while (args.length > 0) {
    const arg = shift(args);

    switch (arg) {
      case '-h':
      case '--help':
        return null;
      case '-a':
        opts.host = shift(args);
        break;
      case '-p':
        opts.port = parsePort(shift(args));
        break;
      case '-c':
        opts.cert = shift(args);
        break;
      case '-k':
        opts.key = shift(args);
        break;
      case '--jwk':
        opts.keys.push(readJsonFromFile(shift(args)));
        break;
      case '--save-jwk':
        opts.saveJWK = true;
        break;
      case '--issuer-url-trailing-slash':
        opts.issuerUrlTrailingSlash = true;
        break;
      default:
        throw new Error(`Unrecognized option '${arg}'.`);
    }
  }

  return opts;
};

const showHelp = (scriptName: string): void => {
  console.log(`Usage: ${scriptName} [options]
       ${scriptName} -a localhost -p 8080

Options:
  -h, --help                   Shows this help information.
  -a <address>                 Address on which the server will listen for connections.
                               If omitted, the server will accept connections on [::]
                               if IPv6 is available, or 0.0.0.0 otherwise.
  -p <port>                    TCP port on which the server will listen for connections.
                               If omitted, 8080 will be used.
                               If 0 is provided, the operating system will assign
                               an arbitrary unused port.
  --issuer-url-trailing-slash  Adds a trailing slash to the issuer url.
  -c <cert>                    Optional file path to an SSL cert. Both cert and key need
                               to be supplied to enable SSL.
  -k <key>                     Optional file path to an SSL key. Both key and cert need
                               to be supplied to enable SSL.
  --jwk <filename>             Adds a JSON-formatted key to the server's keystore.
                               Can be specified many times.
  --save-jwk                   Saves all the keys in the keystore as "{kid}.json".

If no keys are added via the --jwk option, a new random RSA key
will be generated. This key can then be saved to disk with the --save-jwk
for later reuse.`);
};

const parsePort = (portStr: string): number => {
  const port = parseInt(portStr, 10);

  if (Number.isNaN(port) || port < 0 || port > 65535) {
    throw new Error('Invalid port number.');
  }

  return port;
};

const saveJWK = async (keys: JWK[]): Promise<void> => {
  for (const key of keys) {
    const filename = `${key.kid}.json`;
    await writeFile(filename, JSON.stringify(key, null, 2));
    console.log(`JSON web key written to file "${filename}".`);
  }
};

const startServer = async (opts: Options): Promise<OAuth2Server> => {
  const server = new OAuth2Server(opts.key, opts.cert, {
    shouldIssuerUrlBeSuffixedWithATralingSlash: opts.issuerUrlTrailingSlash,
  });

  await Promise.all(
    opts.keys.map(async (key) => {
      const jwk = await server.issuer.keys.add(key);

      console.log(`Added key with kid "${jwk.kid}"`);
    }),
  );

  if (opts.keys.length === 0) {
    const jwk = await server.issuer.keys.generate('RS256');
    console.log(`Generated new RSA key with kid "${jwk.kid}"`);
  }

  if (opts.saveJWK) {
    await saveJWK(server.issuer.keys.toJSON(true));
  }

  await server.start(opts.port, opts.host);

  const addr = server.address();
  const hostname = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;

  console.log(
    `OAuth 2 server listening on http://${hostname}:${addr.port.toString()}`,
  );

  assertIsString(server.issuer.url, 'Empty host');
  console.log(`OAuth 2 issuer is ${server.issuer.url}`);

  process.once('SIGINT', () => {
    console.log('OAuth 2 server is stopping...');

    const handler = async (): Promise<void> => {
      await server.stop();
    };

    handler().catch((e: unknown) => {
      throw e;
    });

    console.log('OAuth 2 server has been stopped.');
  });

  return server;
};
