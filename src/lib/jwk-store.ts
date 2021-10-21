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

import { KeyObject, randomBytes } from 'crypto';

import {
  exportJWK,
  importJWK,
  generateKeyPair,
  GenerateKeyPairOptions,
} from 'jose';

import { JWK } from './types';
import { JWKWithKid } from './types-internals';

const generateRandomKid = () => {
  return randomBytes(40).toString('hex');
};

type JwkTransformer = (jwk: JWK) => JWK;

const RsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  const x = { ...jwk };

  delete x.d;
  delete x.p;
  delete x.q;
  delete x.dp;
  delete x.dq;
  delete x.qi;

  return x;
};

const EcdsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  const x = { ...jwk };

  delete x.d;

  return x;
};

const EddsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  const x = { ...jwk };

  delete x.d;

  return x;
};

const privateToPublicTransformerMap: Record<string, JwkTransformer> = {
  // RSASSA-PKCS1-v1_5
  RS256: RsaPrivateFieldsRemover,
  RS384: RsaPrivateFieldsRemover,
  RS512: RsaPrivateFieldsRemover,

  // RSASSA-PSS
  PS256: RsaPrivateFieldsRemover,
  PS384: RsaPrivateFieldsRemover,
  PS512: RsaPrivateFieldsRemover,

  // ECDSA
  ES256: EcdsaPrivateFieldsRemover,
  ES256K: EcdsaPrivateFieldsRemover,
  ES384: EcdsaPrivateFieldsRemover,
  ES512: EcdsaPrivateFieldsRemover,

  // Edwards-curve DSA
  EdDSA: EddsaPrivateFieldsRemover,
};

const supportedAlgs = Object.keys(privateToPublicTransformerMap);

function normalizeKeyKid(
  jwk: Record<string, unknown>,
  opts?: { kid?: string }
): asserts jwk is JWKWithKid {
  if (jwk.kid !== undefined) {
    return;
  }

  if (opts !== undefined && opts.kid !== undefined) {
    jwk.kid = opts.kid;
  } else {
    jwk.kid = generateRandomKid();
  }
}

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
   * Generates a new random key and adds it into this keystore.
   *
   * @param {string} alg The selected algorithm.
   * @param {object} [opts] The options.
   * @param {string} [opts.kid] The key identifier to use.
   * @param {string} [opts.crv] The OKP "crv" to be used for "EdDSA" algorithm.
   * @returns {Promise<JWK>} The promise for the generated key.
   */
  async generate(
    alg: string,
    opts?: { kid?: string; crv?: string }
  ): Promise<JWK> {
    const generateOpts: GenerateKeyPairOptions =
      opts !== undefined && opts.crv !== undefined ? { crv: opts.crv } : {};

    const pair = await generateKeyPair(alg, generateOpts);
    const joseJwk = await exportJWK(pair.privateKey);

    normalizeKeyKid(joseJwk, opts);
    joseJwk.alg = alg;

    const jwk = joseJwk as JWK;
    this.#keyRotator.add(jwk);
    return jwk;
  }

  /**
   * Adds a JWK key to this keystore.
   *
   * @param {object} maybeJwk The JWK key to add.
   * @returns {Promise<JWK>} The promise for the added key.
   */
  async add(maybeJwk: Record<string, unknown>): Promise<JWK> {
    const tempJwk = { ...maybeJwk };

    normalizeKeyKid(tempJwk);

    if (tempJwk.alg === undefined) {
      throw new Error('Unspecified JWK "alg" property');
    }

    if (!supportedAlgs.includes(tempJwk.alg)) {
      throw new Error(`Unsupported JWK "alg" value ("${tempJwk.alg}")`);
    }

    const jwk = tempJwk as JWK;

    const privateKey = await importJWK(jwk);

    if (!(privateKey instanceof KeyObject) || privateKey.type !== 'private') {
      throw new Error(
        `Invalid JWK type. No "private" key related data has been found.`
      );
    }

    this.#keyRotator.add(jwk);

    return jwk;
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
   * @returns {JWK[]} The JSON representation of this keystore.
   */
  toJSON(includePrivateFields = false): JWK[] {
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

  toJSON(includePrivateFields: boolean): JWK[] {
    const keys: JWK[] = [];

    for (const key of this.#keys) {
      if (includePrivateFields) {
        keys.push({ ...key });
        continue;
      }

      const cleaner = privateToPublicTransformerMap[key.alg];
      keys.push(cleaner(key));
    }

    return keys;
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
