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
 * JWK Store library
 * @module lib/jwk-store
 */

'use strict';

const jose = require('node-jose');

const store = Symbol('store');
const keyRotator = Symbol('keyRotator');

/**
 * Simplified wrapper class for [node-jose]{@link https://github.com/cisco/node-jose}'s keystore.
 */
class JWKStore {
  /**
   * Creates a new instance of the keystore.
   */
  constructor() {
    this[store] = jose.JWK.createKeyStore();
    this[keyRotator] = new KeyRotator();
  }

  /**
   * Generates a new random RSA key and adds it into this keystore.
   * @param {Number} [size] The size in bits of the new key. Default: 2048.
   * @param {String} [kid] The key ID. If omitted, a new random 'kid' will be generated.
   * @param {String} [use] The intended use of the key (e.g. 'sig', 'enc'.) Default: 'sig'.
   * @returns {Promise<JsonWebKey>} The promise for the generated key.
   */
  async generateRSA(size, kid, use) {
    const key = await this[store].generate('RSA', size, { kid, use: use || 'sig' });
    this[keyRotator].add(key);
    return key;
  }

  /**
   * Adds a JWK key to this keystore.
   * @param {JsonWebKey} jwk The JWK key to add.
   * @returns {Promise<JsonWebKey>} The promise for the added key.
   */
  async add(jwk) {
    const jwkUse = { use: 'sig', ...jwk };

    const key = await this[store].add(jwkUse);
    this[keyRotator].add(key);
    return key;
  }

  /**
   * Adds a PEM-encoded RSA key to this keystore.
   * @param {String} pem The PEM-encoded key to add.
   * @param {String} [kid] The key ID. If omitted, a new random 'kid' will be generated.
   * @param {String} [use] The intended use of the key (e.g. 'sig', 'enc'.) Default: 'sig'.
   * @returns {Promise<JsonWebKey>} The promise for the added key.
   */
  async addPEM(pem, kid, use) {
    const key = await this[store].add(pem, 'pem', { kid, use: use || 'sig' });
    this[keyRotator].add(key);
    return key;
  }

  /**
   * Gets a key from the keystore in a round-robin fashion.
   * If a 'kid' is provided, only keys that match will be taken into account.
   * @param {String} [kid] The optional key identifier to match keys against.
   * @returns {JsonWebKey} The retrieved key.
   */
  get(kid) {
    return this[keyRotator].next(kid);
  }

  /**
   * Generates a JSON representation of this keystore, which conforms
   * to a JWK Set from {I-D.ietf-jose-json-web-key}.
   * @param {Boolean} [isPrivate = false] `true` if the private fields
   *        of stored keys are to be included.
   * @returns {Object} The JSON representation of this keystore.
   */
  toJSON(isPrivate) {
    return this[store].toJSON(isPrivate);
  }
}

function KeyRotator() {
  const keys = [];

  this.add = function add(key) {
    if (!keys.includes(key)) {
      keys.push(key);
    }
  };

  this.next = function next(kid) {
    const i = findNext(kid);

    if (i === -1) {
      return null;
    }

    return moveToTheEnd(i);
  };

  function findNext(kid) {
    if (keys.length === 0) {
      return -1;
    }

    if (!kid) {
      return 0;
    }

    return keys.findIndex((x) => x.kid === kid);
  }

  function moveToTheEnd(i) {
    const [key] = keys.splice(i, 1);
    keys.push(key);

    return key;
  }
}

module.exports = JWKStore;
