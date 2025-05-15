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

import { randomBytes } from 'node:crypto';
import { AssertionError } from 'node:assert';

import type { GenerateKeyPairOptions } from 'jose';
import { exportJWK, importJWK, generateKeyPair } from 'jose';

import type { JWK } from './types';
import type { JWKWithKid } from './types-internals';
import {
  assertIsPlainObject,
  privateToPublicKeyTransformer,
  supportedAlgs,
} from './helpers';

const generateRandomKid = () => {
  return randomBytes(40).toString('hex');
};

function normalizeKeyKid(
  jwk: unknown,
  opts?: { kid?: string },
): asserts jwk is JWKWithKid {
  assertIsPlainObject(jwk, 'Invalid jwk format');

  if (jwk['kid'] !== undefined) {
    return;
  }

  if (opts?.kid !== undefined) {
    jwk['kid'] = opts.kid;
  } else {
    jwk['kid'] = generateRandomKid();
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
   * @param alg The selected algorithm.
   * @param opts The options.
   * @param opts.kid The key identifier to use.
   * @param opts.crv The OKP "crv" to be used for "EdDSA" algorithm.
   * @returns The promise for the generated key.
   */
  async generate(
    alg: string,
    opts?: { kid?: string; crv?: string },
  ): Promise<JWK> {
    const generateOpts: GenerateKeyPairOptions =
      opts?.crv !== undefined ? { crv: opts.crv } : {};

    generateOpts.extractable = true;

    if (
      alg === 'EdDSA' &&
      generateOpts.crv !== undefined &&
      generateOpts.crv !== 'Ed25519'
    ) {
      throw new Error(
        'Invalid or unsupported crv option provided, supported values are: Ed25519',
      );
    }

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
   * @param maybeJwk The JWK key to add.
   * @returns The promise for the added key.
   */
  async add(maybeJwk: Record<string, unknown>): Promise<JWK> {
    const tempJwk = { ...maybeJwk };

    normalizeKeyKid(tempJwk);

    if (!('alg' in tempJwk)) {
      throw new Error('Unspecified JWK "alg" property');
    }

    if (!supportedAlgs.includes(tempJwk.alg)) {
      throw new Error(`Unsupported JWK "alg" value ("${tempJwk.alg}")`);
    }

    const jwk = tempJwk as JWK;

    const privateKey = await importJWK(jwk, jwk.alg, { extractable: false });

    if (privateKey instanceof Uint8Array || privateKey.type !== 'private') {
      throw new Error(
        `Invalid JWK type. No "private" key related data has been found.`,
      );
    }

    this.#keyRotator.add(jwk);

    return jwk;
  }

  /**
   * Gets a key from the keystore in a round-robin fashion.
   * If a 'kid' is provided, only keys that match will be taken into account.
   * @param kid The optional key identifier to match keys against.
   * @returns The retrieved key.
   */
  get(kid?: string): JWK | undefined {
    return this.#keyRotator.next(kid);
  }

  /**
   * Generates a JSON representation of this keystore, which conforms
   * to a JWK Set from {I-D.ietf-jose-json-web-key}.
   * @param [includePrivateFields] `true` if the private fields
   *        of stored keys are to be included.
   * @returns The JSON representation of this keystore.
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

      keys.push(privateToPublicKeyTransformer(key));
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

    if (key === undefined) {
      throw new AssertionError({
        message: 'Unexpected error. key is supposed to exist',
      });
    }

    this.#keys.push(key);

    return key;
  }
}
