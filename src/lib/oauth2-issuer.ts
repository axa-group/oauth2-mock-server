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
 * OAuth2 Issuer library
 *
 * @module lib/oauth2-issuer
 */

import jwt from 'jsonwebtoken';
import { EventEmitter } from 'events';
import { JWK } from 'node-jose';

import { JWKStore } from './jwk-store';
import { assertIsAlgorithm, assertIsString } from './helpers';
import type { Header, MutableToken, Payload, ScopesOrTransform } from './types';
import { InternalEvents } from './types';

/**
 * Represents an OAuth 2 issuer.
 */
export class OAuth2Issuer extends EventEmitter {
  /**
   * Sets or returns the issuer URL.
   *
   * @type {string}
   */
  url: string | null;

  #keys: JWKStore;

  /**
   * Creates a new instance of HttpServer.
   */
  constructor() {
    super();
    this.url = null;

    this.#keys = new JWKStore();
  }

  /**
   * Returns the key store.
   *
   * @type {JWKStore}
   */
  get keys(): JWKStore {
    return this.#keys;
  }

  /**
   * Builds a JWT with the provided 'kid'.
   *
   * @param {boolean} signed A value that indicates whether or not to sign the JWT.
   * @param {string} [kid] The 'kid' of the key that will be used to sign the JWT.
   *     If omitted, the next key in the round-robin will be used.
   * @param {ScopesOrTransform} [scopesOrTransform] A scope, array of scopes,
   *     or JWT transformation callback.
   * @param {number} [expiresIn] Time in seconds for the JWT to expire. Default: 3600 seconds.
   * @returns {string} The produced JWT.
   * @fires OAuth2Issuer#beforeSigning
   */
  buildToken(
    signed: boolean,
    kid?: string,
    scopesOrTransform?: ScopesOrTransform,
    expiresIn = 3600
  ): string {
    const key = this.keys.get(kid);

    if (!key) {
      throw new Error('Cannot build token: Unknown key.');
    }

    const timestamp = Math.floor(Date.now() / 1000);

    const header: Header = {
      alg: arguments.length === 0 || signed ? getKeyAlg(key) : 'none',
      kid: key.kid,
    };

    assertIsString(this.url, 'Unknown issuer url');

    const payload: Payload = {
      iss: this.url,
      iat: timestamp,
      exp: timestamp + expiresIn,
      nbf: timestamp - 10,
    };

    if (typeof scopesOrTransform === 'string') {
      payload.scope = scopesOrTransform;
    } else if (Array.isArray(scopesOrTransform)) {
      payload.scope = scopesOrTransform.join(' ');
    } else if (typeof scopesOrTransform === 'function') {
      scopesOrTransform(header, payload);
    }

    const token: MutableToken = {
      header,
      payload,
    };

    /**
     * Before signing event.
     *
     * @event OAuth2Issuer#beforeSigning
     * @param {MutableToken} token The JWT header and payload.
     */
    this.emit(InternalEvents.BeforeSigning, token);

    const options: jwt.SignOptions = {
      header: token.header,
    };

    return jwt.sign(token.payload, getSecret(key), options);
  }
}

function getKeyAlg(key: JWK.Key): jwt.Algorithm {
  if (key.alg) {
    assertIsAlgorithm(key.alg);
    return key.alg;
  }

  switch (key.kty) {
    case 'RSA':
      return 'RS256';
    case 'EC': {
      const length = key.length & 0xfff0;
      const alg = `ES${length}`;
      assertIsAlgorithm(alg);
      return alg;
    }
    default:
      return 'HS256';
  }
}

function getSecret(key: JWK.Key): string {
  switch (key.kty) {
    case 'RSA':
    case 'EC':
      return key.toPEM(true);
    default:
      return (key.toJSON(true) as { k: string }).k;
  }
}
