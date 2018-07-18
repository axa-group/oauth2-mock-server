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
**/

/**
 * JWK Store library
 * @module lib/jwk-store
 */

'use strict';

const jose = require('node-jose');

const _store = Symbol('store');
const _keyRotator = Symbol('keyRotator');

/**
 * Simplified wrapper class for [node-jose]{@link https://github.com/cisco/node-jose}'s keystore.
 */
class JWKStore {
  /**
   * Creates a new instance of the keystore.
   */
  constructor() {
    this[_store] = jose.JWK.createKeyStore();
    this[_keyRotator] = new KeyRotator();
  }

  /**
   * Generates a new random RSA key and adds it into this keystore.
   * @param {Number} [size] The size in bits of the new key. Default: 2048.
   * @param {String} [kid] The key ID. If omitted, a new random 'kid' will be generated.
   * @param {String} [use] The intended use of the key (e.g. 'sig', 'enc'.) Default: 'sig'.
   * @returns {Promise<JsonWebKey>} The promise for the generated key.
   */
  async generateRSA(size, kid, use) {
    let key = await this[_store].generate('RSA', size, { kid, use: use || 'sig' });
    this[_keyRotator].add(key);
    return key;
  }

  /**
   * Adds a JWK key to this keystore.
   * @param {JsonWebKey} jwk The JWK key to add.
   * @returns {Promise<JsonWebKey>} The promise for the added key.
   */
  async add(jwk) {
    let jwkUse = Object.assign({ use: 'sig' }, jwk);

    let key = await this[_store].add(jwkUse);
    this[_keyRotator].add(key);
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
    let key = await this[_store].add(pem, 'pem', { kid, use: use || 'sig' });
    this[_keyRotator].add(key);
    return key;
  }

  /**
   * Gets a key from the keystore in a round-robin fashion.
   * If a 'kid' is provided, only keys that match will be taken into account.
   * @param {String} [kid] The key identifier to match against. If omitted, no match will be attempted.
   * @returns {JsonWebKey} The retrieved key.
   */
  get(kid) {
    return this[_keyRotator].next(kid);
  }

  /**
   * Generates a JSON representation of this keystore, which conforms
   * to a JWK Set from {I-D.ietf-jose-json-web-key}.
   * @param {Boolean} [isPrivate = false] `true` if the private fields
   *        of stored keys are to be included.
   * @returns {Object} The JSON representation of this keystore.
   */
  toJSON(isPrivate) {
    return this[_store].toJSON(isPrivate);
  }
}

function KeyRotator() {
  // We take advantage of the fact that set elements are iterated in insertion order.
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Set#Description
  
  const keys = new Set();

  this.add = function(key) {
    keys.add(key);
  };

  this.next = function(kid) {
    let key = findNext(kid);

    if (key) {
      moveToTheEnd(key);
    }

    return key;
  };

  function findNext(kid) {
    for (let key of keys) {
      if (!kid || key.kid == kid) {
        return key;
      }
    }

    return null;
  }

  function moveToTheEnd(key) {
    if (keys.delete(key)) {
      keys.add(key);
    }
  }
}

module.exports = JWKStore;
