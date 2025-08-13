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
 * @module lib/oauth2-server
 */

import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';

import { HttpServer } from './http-server';
import { OAuth2Issuer } from './oauth2-issuer';
import { OAuth2Service } from './oauth2-service';
import { assertIsAddressInfo } from './helpers';
import type { HttpServerOptions, OAuth2Options } from './types';

/**
 * Represents an OAuth2 HTTP server.
 */
export class OAuth2Server extends HttpServer {
  private _service: OAuth2Service;
  private _issuer: OAuth2Issuer;

  /**
   * Creates a new instance of OAuth2Server.
   * @param key Optional key file path for ssl
   * @param cert Optional cert file path for ssl
   * @param oauth2Options Optional additional settings
   * @returns A new instance of OAuth2Server.
   */
  constructor(key?: string, cert?: string, oauth2Options?: OAuth2Options) {
    if ((key && !cert) || (!key && cert)) {
      throw new Error(
        'Both key and cert need to be supplied to start the server with https',
      );
    }

    const iss = new OAuth2Issuer(
      oauth2Options?.shouldIssuerUrlBeSuffixedWithATralingSlash,
    );
    const serv = new OAuth2Service(iss, oauth2Options?.endpoints);

    let options: HttpServerOptions | undefined = undefined;
    if (key && cert) {
      options = {
        key: readFileSync(key),
        cert: readFileSync(cert),
      };
    }

    super(serv.requestHandler, options);

    this._issuer = iss;
    this._service = serv;
  }

  /**
   * Returns the OAuth2Issuer instance used by the server.
   * @returns The OAuth2Issuer instance.
   */
  get issuer(): OAuth2Issuer {
    return this._issuer;
  }

  /**
   * Returns the OAuth2Service instance used by the server.
   * @returns The OAuth2Service instance.
   */
  get service(): OAuth2Service {
    return this._service;
  }

  /**
   * Returns a value indicating whether or not the server is listening for connections.
   * @returns A boolean value indicating whether the server is listening.
   */
  override get listening(): boolean {
    return super.listening;
  }

  /**
   * Returns the bound address, family name and port where the server is listening,
   * or null if the server has not been started.
   * @returns The server bound address information.
   */
  override address(): AddressInfo {
    const address = super.address();

    assertIsAddressInfo(address);

    return address;
  }

  /**
   * Starts the server.
   * @param port Port number. If omitted, it will be assigned by the operating system.
   * @param host Host name.
   * @returns A promise that resolves when the server has been started.
   */
  override async start(port?: number, host?: string): Promise<void> {
    await super.start(port, host);
    this.issuer.url ??= super.buildIssuerUrl(host, this.address().port);
  }

  /**
   * Stops the server.
   * @returns Resolves when the server has been stopped.
   */
  override async stop(): Promise<void> {
    await super.stop();
    this.issuer.url = undefined;
  }
}
