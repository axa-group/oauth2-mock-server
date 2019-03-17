/**
 * Copyright (c) AXA Partners
 *
 * Licensed under the AXA Partners License (the "License"); you
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
 * @module lib/http-server
 */

'use strict';

const http = require('http');

const server = Symbol('server');

/**
 * Provides a restartable wrapper for http.CreateServer().
 */
class HttpServer {
  /**
   * @callback requestHandler
   * @param {http.IncomingMessage} request The incoming message.
   * @param {http.ServerResponse} response The server response.
   */

  /**
   * Creates a new instance of HttpServer.
   * @param {requestHandler} requestListener The function that will handle the server's requests.
   */
  constructor(requestListener) {
    this[server] = http.createServer(requestListener);
  }

  /**
   * Returns a value indicating whether or not the server is listening for connections.
   * @type {Boolean}
   */
  get listening() {
    return this[server].listening;
  }

  /**
   * Returns the bound address, family name and port where the server is listening,
   * or null if the server has not been started.
   * @returns {AddressInfo} The server bound address information.
   */
  address() {
    if (!this.listening) {
      throw new Error('Server is not started.');
    }

    return this[server].address();
  }

  /**
   * Starts the server.
   * @param {Number} [port] Port number. If omitted, it will be assigned by the operating system.
   * @param {String} [host] Host name.
   * @returns {Promise<void>} A promise that resolves when the server has been started.
   */
  async start(port, host) {
    if (this.listening) {
      throw new Error('Server has already been started.');
    }

    return new Promise((resolve, reject) => {
      this[server]
        .listen(port, host)
        .on('listening', resolve)
        .on('error', reject);
    });
  }

  /**
   * Stops the server.
   * @returns {Promise} Resolves when the server has been stopped.
   */
  async stop() {
    if (!this.listening) {
      throw new Error('Server is not started.');
    }

    return new Promise((resolve, reject) => {
      this[server].close((err) => {
        if (err) {
          return reject(err);
        }

        return resolve();
      });
    });
  }
}

module.exports = HttpServer;
