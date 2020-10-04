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
 *
 * @module lib/jwk-store
 */

import { JWK } from 'node-jose';

/**
 * Simplified wrapper class for [node-jose]{@link https://github.com/cisco/node-jose}'s keystore.
 */
export class JWKStore {
  #store: JWK.KeyStore;
  #keyRotator: KeyRotator;

  /**
   * Creates a new instance of the keystore.
   */
  constructor() {
    this.#store = JWK.createKeyStore();
    this.#keyRotator = new KeyRotator();
  }

  /**
   * Generates a new random RSA key and adds it into this keystore.
   *
   * @param {number} [size] The size in bits of the new key. Default: 2048.
   * @param {string} [kid] The key ID. If omitted, a new random 'kid' will be generated.
   * @param {string} [use] The intended use of the key (e.g. 'sig', 'enc'.) Default: 'sig'.
   * @returns {Promise<JWK.Key>} The promise for the generated key.
   */
  async generateRSA(
    size?: number,
    kid?: string,
    use = 'sig'
  ): Promise<JWK.Key> {
    const key = await this.#store.generate('RSA', size, { kid, use });
    this.#keyRotator.add(key);
    return key;
  }

  /**
   * Adds a JWK key to this keystore.
   *
   * @param {JWK.Key} jwk The JWK key to add.
   * @returns {Promise<JWK.Key>} The promise for the added key.
   */
  async add(jwk: JWK.Key): Promise<JWK.Key> {
    const jwkUse: JWK.Key = { ...jwk, use: 'sig' };

    const key = await this.#store.add(jwkUse);
    this.#keyRotator.add(key);
    return key;
  }

  /**
   * Adds a PEM-encoded RSA key to this keystore.
   *
   * @param {string} pem The PEM-encoded key to add.
   * @param {string} [kid] The key ID. If omitted, a new random 'kid' will be generated.
   * @param {string} [use] The intended use of the key (e.g. 'sig', 'enc'.) Default: 'sig'.
   * @returns {Promise<JWK.Key>} The promise for the added key.
   */
  async addPEM(pem: string, kid?: string, use = 'sig'): Promise<JWK.Key> {
    const key = await this.#store.add(pem, 'pem', { kid, use });
    this.#keyRotator.add(key);
    return key;
  }

  /**
   * Gets a key from the keystore in a round-robin fashion.
   * If a 'kid' is provided, only keys that match will be taken into account.
   *
   * @param {string} [kid] The optional key identifier to match keys against.
   * @returns {JWK.Key | null} The retrieved key.
   */
  get(kid?: string): JWK.Key | null {
    return this.#keyRotator.next(kid);
  }

  /**
   * Generates a JSON representation of this keystore, which conforms
   * to a JWK Set from {I-D.ietf-jose-json-web-key}.
   *
   * @param {boolean} [isPrivate = false] `true` if the private fields
   *        of stored keys are to be included.
   * @returns {Object} The JSON representation of this keystore.
   */
  toJSON(isPrivate?: boolean): Record<string, unknown> {
    return this.#store.toJSON(isPrivate) as Record<string, unknown>;
  }
}

class KeyRotator {
  #keys: JWK.Key[] = [];

  add(key: JWK.Key): void {
    if (!this.#keys.includes(key)) {
      this.#keys.push(key);
    }
  }

  next(kid?: string): JWK.Key | null {
    const i = this.findNext(kid);

    if (i === -1) {
      return null;
    }

    return this.moveToTheEnd(i);
  }

  private findNext(kid?: string): number {
    if (this.#keys.length === 0) {
      return -1;
    }

    if (!kid) {
      return 0;
    }

    return this.#keys.findIndex((x) => x.kid === kid);
  }

  private moveToTheEnd(i: number): JWK.Key {
    // cf. https://github.com/typescript-eslint/typescript-eslint/pull/1645
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const [key] = this.#keys.splice(i, 1);

    this.#keys.push(key);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return key;
  }
}
