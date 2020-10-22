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
 * OAuth2 HTTP Server library
 *
 * @module lib/oauth2-server
 */

import { URL } from 'url';
import { isIP, AddressInfo } from 'net';
import { Server } from 'http';

import { HttpServer } from './http-server';
import { OAuth2Issuer } from './oauth2-issuer';
import { OAuth2Service } from './oauth2-service';
import { assertIsAddressInfo } from './helpers';

/**
 * Represents an OAuth2 HTTP server.
 */
export class OAuth2Server extends HttpServer {
  private _service: OAuth2Service;
  private _issuer: OAuth2Issuer;

  /**
   * Creates a new instance of OAuth2Server.
   */
  constructor() {
    const iss = new OAuth2Issuer();
    const serv = new OAuth2Service(iss);

    super(serv.requestHandler);

    this._issuer = iss;
    this._service = serv;
  }

  /**
   * Returns the OAuth2Issuer instance used by the server.
   *
   * @type {OAuth2Issuer}
   */
  get issuer(): OAuth2Issuer {
    return this._issuer;
  }

  /**
   * Returns the OAuth2Service instance used by the server.
   *
   * @type {OAuth2Service}
   */
  get service(): OAuth2Service {
    return this._service;
  }

  /**
   * Returns a value indicating whether or not the server is listening for connections.
   *
   * @type {boolean}
   */
  get listening(): boolean {
    return super.listening;
  }

  /**
   * Returns the bound address, family name and port where the server is listening,
   * or null if the server has not been started.
   *
   * @returns {AddressInfo} The server bound address information.
   */
  address(): AddressInfo {
    const address = super.address();

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
    const server = await super.start(port, host);

    /* istanbul ignore else */
    if (!this.issuer.url) {
      this.issuer.url = buildIssuerUrl(host, this.address().port);
    }

    return server;
  }

  /**
   * Stops the server.
   *
   * @returns {Promise} Resolves when the server has been stopped.
   */
  async stop(): Promise<void> {
    await super.stop();
    this._issuer.url = null;
  }
}

function buildIssuerUrl(host: string | undefined, port: number) {
  const url = new URL(`http://localhost:${port}`);

  if (host && !coversLocalhost(host)) {
    url.hostname = host.includes(':') ? `[${host}]` : host;
  }

  return url.origin;
}

function coversLocalhost(address: string) {
  switch (isIP(address)) {
    case 4:
      return address === '0.0.0.0' || address.startsWith('127.');
    case 6:
      return address === '::' || address === '::1';
    default:
      return false;
  }
}
