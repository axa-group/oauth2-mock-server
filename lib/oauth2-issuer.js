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
 * OAuth2 Issuer library
 * @module lib/oauth2-issuer
 */

'use strict';

const jwt = require('jsonwebtoken');
const { EventEmitter } = require('events');
const JWKStore = require('./jwk-store');

const keys = Symbol('keys');

/**
 * Represents an OAuth 2 issuer.
 */
class OAuth2Issuer extends EventEmitter {
  /**
   * Creates a new instance of HttpServer.
   */
  constructor() {
    super();
    /**
     * Sets or returns the issuer URL.
     * @type {String}
     */
    this.url = null;

    this[keys] = new JWKStore();
  }

  /**
   * Returns the key store.
   * @type {JWKStore}
   */
  get keys() {
    return this[keys];
  }

  /**
   * Builds a JWT with the provided 'kid'.
   * @param {Boolean} signed A value that indicates whether or not to sign the JWT.
   * @param {String} [kid] The 'kid' of the key that will be used to sign the JWT.
   *     If omitted, the next key in the round-robin will be used.
   * @param {(String|Array<String>|jwtTransform)} [scopesOrTransform] A scope, array of scopes,
   *     or JWT transformation callback.
   * @param {Number} [expiresIn] Time in seconds for the JWT to expire. Default: 3600 seconds.
   * @returns {String} The produced JWT.
   */
  buildToken(signed, kid, scopesOrTransform, expiresIn) {
    const key = this.keys.get(kid);

    if (!key) {
      throw new Error('Cannot build token: Unknown key.');
    }

    const timestamp = Math.floor(Date.now() / 1000);

    const header = {
      kid: key.kid,
    };

    const payload = {
      iss: this.url,
      iat: timestamp,
      exp: timestamp + (expiresIn || 3600),
      nbf: timestamp - 10,
    };

    if (typeof scopesOrTransform === 'string') {
      payload.scope = scopesOrTransform;
    } else if (Array.isArray(scopesOrTransform)) {
      payload.scope = scopesOrTransform.join(' ');
    } else if (typeof scopesOrTransform === 'function') {
      scopesOrTransform(header, payload);
    }

    const token = {
      header,
      payload,
    };
    this.emit('beforeSigning', token);
    const options = {
      algorithm: ((arguments.length === 0 || signed) ? getKeyAlg(key) : 'none'),
      header: token.header,
    };

    return jwt.sign(token.payload, getSecret(key), options);
  }
}

function getKeyAlg(key) {
  if (key.alg) {
    return key.alg;
  }

  switch (key.kty) {
    case 'RSA':
      return 'RS256';
    case 'EC':
      /* eslint-disable-next-line no-bitwise */
      return `ES${key.length & 0xFFF0}`;
    default:
      return 'HS256';
  }
}

function getSecret(key) {
  switch (key.kty) {
    case 'RSA':
    case 'EC':
      return key.toPEM(true);
    default:
      return key.toObject(true).k;
  }
}

module.exports = OAuth2Issuer;
