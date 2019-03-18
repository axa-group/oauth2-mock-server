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
 * OAuth2 HTTP Server library
 * @module lib/oauth2-server
 */

'use strict';

const { URL } = require('url');
const net = require('net');
const HttpServer = require('./http-server');
const OAuth2Issuer = require('./oauth2-issuer');
const OAuth2Service = require('./oauth2-service');

const issuer = Symbol('issuer');
const service = Symbol('service');

/**
 * Represents an OAuth2 HTTP server.
 */
class OAuth2Server extends HttpServer {
  /**
   * Creates a new instance of OAuth2Server.
   */
  constructor() {
    const iss = new OAuth2Issuer();
    const serv = new OAuth2Service(iss);

    super(serv.requestHandler);

    this[issuer] = iss;
    this[service] = serv;
  }

  /**
   * Returns the OAuth2Issuer instance used by the server.
   * @type {OAuth2Issuer}
   */
  get issuer() {
    return this[issuer];
  }

  /**
   * Returns the OAuth2Service instance used by the server.
   * @type {OAuth2Service}
   */
  get service() {
    return this[service];
  }

  /**
   * Returns a value indicating whether or not the server is listening for connections.
   * @type {Boolean}
   */
  get listening() {
    return super.listening;
  }

  /**
   * Returns the bound address, family name and port where the server is listening,
   * or null if the server has not been started.
   * @returns {AddressInfo} The server bound address information.
   */
  address() {
    return super.address();
  }

  /**
   * Starts the server.
   * @param {Number} [port] Port number. If omitted, it will be assigned by the operating system.
   * @param {String} [host] Host name.
   * @returns {Promise<void>} A promise that resolves when the server has been started.
   */
  async start(port, host) {
    await super.start(port, host);

    /* istanbul ignore else */
    if (!this.issuer.url) {
      this.issuer.url = buildIssuerUrl(host, this.address().port);
    }
  }

  /**
   * Stops the server.
   * @returns {Promise} Resolves when the server has been stopped.
   */
  async stop() {
    await super.stop();
    this[issuer].url = null;
  }
}

function buildIssuerUrl(host, port) {
  const url = new URL(`http://localhost:${port}`);

  if (host && !coversLocalhost(host)) {
    url.hostname = host.includes(':') ? `[${host}]` : host;
  }

  return url.origin;
}

function coversLocalhost(address) {
  switch (net.isIP(address)) {
    case 4:
      return address === '0.0.0.0' || address.startsWith('127.');
    case 6:
      return address === '::' || address === '::1';
    default:
      return false;
  }
}

module.exports = OAuth2Server;
