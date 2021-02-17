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

import { randomBytes } from 'crypto';

import generateKeyPair, {
  GenerateKeyPairOptions,
} from 'jose/util/generate_key_pair';
import fromKeyLike from 'jose/jwk/from_key_like';
import { JWK } from 'jose/types';
// import { fromPEM } from './helpers';

const generateRandomKid = () => {
  return randomBytes(40).toString('hex');
};

const normalizeKey = (
  jwk: JWK,
  alg?: string,
  opts?: { kid?: string }
): void => {
  if (jwk.kid === undefined) {
    if (opts !== undefined && opts.kid !== undefined) {
      jwk.kid = opts.kid;
    } else {
      jwk.kid = generateRandomKid();
    }
  }

  if (jwk.alg === undefined) {
    if (alg === undefined) {
      throw new Error('Unspecified alg');
    }
    jwk.alg = alg;
  }
};

/**
 * Simple JWK store
 */
export class JWKStore {
  #keyRotator: KeyRotator;

  /**
   * Creates a new instance of the keystore.
   */
  constructor() {
    this.#keyRotator = new KeyRotator();
  }

  /**
   * Generates a new random RSA key and adds it into this keystore.
   *
   * @param {string} alg The selected algorithm
   * @param {object} [opts] The options
   * @param {string} [opts.kid] The key identifier to use
   * @param opts.crv
   * @returns {Promise<JWK>} The promise for the generated key.
   */
  async generate(
    alg: string,
    opts?: { kid?: string; crv?: string }
  ): Promise<JWK> {
    /*
    https://www.scottbrady91.com/JOSE/JWTs-Which-Signing-Algorithm-Should-I-Use
    https://connect2id.com/products/nimbus-jose-jwt/algorithm-selection-guide
    https://tools.ietf.org/html/rfc7518#section-3.5
    */
    // TODO: whitelist alg

    const generateOpts: GenerateKeyPairOptions =
      opts !== undefined && opts.crv !== undefined ? { crv: opts.crv } : {};

    const pair = await generateKeyPair(alg, generateOpts);
    const jwk = await fromKeyLike(pair.privateKey);

    normalizeKey(jwk, alg, opts);

    this.#keyRotator.add(jwk);
    return jwk;
  }

  /**
   * Adds a JWK key to this keystore.
   *
   * @param {JWK} jwk The JWK key to add.
   * @returns {Promise<JWK>} The promise for the added key.
   */
  add(jwk: JWK): Promise<JWK> {
    const jwkUse: JWK = { ...jwk };

    normalizeKey(jwkUse);

    // TODO: assess can be properly deserialized
    // - alg exist
    // - toKeyLike() returns a private key

    this.#keyRotator.add(jwkUse);
    return Promise.resolve(jwkUse);
  }

  /**
   * Gets a key from the keystore in a round-robin fashion.
   * If a 'kid' is provided, only keys that match will be taken into account.
   *
   * @param {string} [kid] The optional key identifier to match keys against.
   * @returns {JWK.Key | null} The retrieved key.
   */
  get(kid?: string): JWK | undefined {
    return this.#keyRotator.next(kid);
  }

  /**
   * Generates a JSON representation of this keystore, which conforms
   * to a JWK Set from {I-D.ietf-jose-json-web-key}.
   *
   * @param {boolean} [includePrivateFields = false] `true` if the private fields
   *        of stored keys are to be included.
   * @returns {Object} The JSON representation of this keystore.
   */
  toJSON(includePrivateFields = false): Record<string, unknown> {
    return this.#keyRotator.toJSON(includePrivateFields);
  }
}

class KeyRotator {
  #keys: JWK[] = [];

  add(key: JWK): void {
    const pos = this.findNext(key.kid);

    if (pos > -1) {
      this.#keys.splice(pos, 1);
    }

    this.#keys.push(key);
  }

  next(kid?: string): JWK | undefined {
    const i = this.findNext(kid);

    if (i === -1) {
      return undefined;
    }

    return this.moveToTheEnd(i);
  }

  toJSON(includePrivateFields: boolean): { keys: JWK[] } {
    const keys: JWK[] = [];

    // TODO: clean up extraction of public members depending of the key types
    // cf. https://github.com/cisco/node-jose/search?q=describe%28%22%23publicKey
    for (const key of this.#keys) {
      const jwk = includePrivateFields
        ? { ...key }
        : { kid: key.kid, kty: key.kty, e: key.e, use: key.use, n: key.n };
      keys.push(jwk);
    }

    return { keys };
  }

  private findNext(kid?: string): number {
    if (this.#keys.length === 0) {
      return -1;
    }

    if (kid === undefined) {
      return 0;
    }

    return this.#keys.findIndex((x) => x.kid === kid);
  }

  private moveToTheEnd(i: number): JWK {
    const [key] = this.#keys.splice(i, 1);

    this.#keys.push(key);

    return key;
  }
}
