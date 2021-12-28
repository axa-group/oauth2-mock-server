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

/**
 * HTTP Server library
 *
 * @module lib/http-server
 */

import { Server, RequestListener, createServer } from 'http';
import { createServer as createHttpsServer } from 'https';
import { AddressInfo, isIP } from 'net';
import { URL } from 'url';

import { assertIsAddressInfo } from './helpers';
import { HttpServerOptions } from './types';

/**
 * Provides a restartable wrapper for http.CreateServer().
 */
export class HttpServer {
  #server: Server;
  #isSecured: boolean;

  /**
   * Creates a new instance of HttpServer.
   *
   * @param {RequestListener} requestListener The function that will handle the server's requests.
   * @param {HttpServerOptions} options Optional HttpServerOptions to start the server with https.
   */
  constructor(requestListener: RequestListener, options?: HttpServerOptions) {
    this.#isSecured = false;

    if (options?.key && options?.cert) {
      this.#server = createHttpsServer(options, requestListener);
      this.#isSecured = true;
    } else {
      this.#server = createServer(requestListener);
    }
  }

  /**
   * Returns a value indicating whether or not the server is listening for connections.
   *
   * @type {boolean}
   */
  get listening(): boolean {
    return this.#server.listening;
  }

  /**
   * Returns the bound address, family name and port where the server is listening,
   * or null if the server has not been started.
   *
   * @returns {AddressInfo} The server bound address information.
   */
  address(): AddressInfo {
    if (!this.listening) {
      throw new Error('Server is not started.');
    }

    const address = this.#server.address();

    assertIsAddressInfo(address);

    return address;
  }

  /**
   * Starts the server.
   *
   * @param {number} [port] Port number. If omitted, it will be assigned by the operating system.
   * @param {string} [host] Host name.
   * @returns {Promise<void>} A promise that resolves when the server has been started.
   */
  async start(port?: number, host?: string): Promise<Server> {
    if (this.listening) {
      throw new Error('Server has already been started.');
    }

    return new Promise((resolve, reject) => {
      this.#server
        .listen(port, host)
        .on('listening', resolve)
        .on('error', reject);
    });
  }

  /**
   * Stops the server.
   *
   * @returns {Promise} Resolves when the server has been stopped.
   */
  async stop(): Promise<void> {
    if (!this.listening) {
      throw new Error('Server is not started.');
    }

    return new Promise((resolve, reject) => {
      this.#server.close((err) => {
        if (err) {
          return reject(err);
        }

        return resolve();
      });
    });
  }

  protected buildIssuerUrl(host: string | undefined, port: number): string {
    const url = new URL(
      `${this.#isSecured ? 'https' : 'http'}://localhost:${port}`
    );

    if (host && !coversLocalhost(host)) {
      url.hostname = host.includes(':') ? `[${host}]` : host;
    }

    return url.origin;
  }
}

const coversLocalhost = (address: string) => {
  switch (isIP(address)) {
    case 4:
      return address === '0.0.0.0' || address.startsWith('127.');
    case 6:
      return address === '::' || address === '::1';
    default:
      return false;
  }
};
