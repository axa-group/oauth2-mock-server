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

/* eslint-disable jsdoc/require-jsdoc */

import { AssertionError } from 'assert';
import { createPrivateKey, KeyExportOptions, KeyObject } from 'crypto';
import type { AddressInfo } from 'net';

import fromKeyLike from 'jose/jwk/from_key_like';
import parseJwk from 'jose/jwk/parse';
import { JWK } from 'jose/types';
import isPlainObject from 'lodash.isplainobject';

import type { TokenRequest } from './types';

export function assertIsString(
  input: unknown,
  errorMessage: string
): asserts input is string {
  if (typeof input !== 'string') {
    throw new AssertionError({ message: errorMessage });
  }
}

export function assertIsAddressInfo(
  input: string | null | AddressInfo
): asserts input is AddressInfo {
  if (input === null || typeof input === 'string') {
    throw new AssertionError({ message: 'Unexpected address type' });
  }
}

export function assertIsPlainObject(
  obj: unknown,
  errMessage: string
): asserts obj is Record<string, unknown> {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  if (!isPlainObject(obj)) {
    throw new AssertionError({ message: errMessage });
  }
}

export function assertIsValidTokenRequest(
  body: unknown
): asserts body is TokenRequest {
  assertIsPlainObject(body, 'Invalid token request body');

  if ('scope' in body) {
    assertIsString(body.scope, "Invalid 'scope' type");
  }

  assertIsString(body.grant_type, "Invalid 'grant_type' type");

  if ('code' in body) {
    assertIsString(body.code, "Invalid 'code' type");
  }
}

export function shift(arr: (string | undefined)[]): string {
  if (arr.length === 0) {
    throw new AssertionError({ message: 'Empty array' });
  }

  const val = arr.shift();

  if (val === undefined) {
    throw new AssertionError({ message: 'Empty value' });
  }

  return val;
}

export function assertKidIsDefined(kid: unknown): asserts kid is string {
  return assertIsString(kid, "Unexpected undefined 'kid'");
}

export const fromPEM = async (pem: string): Promise<JWK> => {
  const key = createPrivateKey({ key: pem, format: 'pem' });
  return await fromKeyLike(key);
};

export const toPEM = async (jwk: JWK): Promise<string> => {
  const key = await parseJwk(jwk);

  if (!(key instanceof KeyObject)) {
    throw new Error('Unexpected key type');
  }

  let opts: KeyExportOptions<'pem'>;
  switch (jwk.kty) {
    case 'RSA':
      opts = { format: 'pem', type: 'pkcs1' };
      break;
    case 'EC':
      opts = { format: 'pem', type: 'pkcs8' };
      break;
    default:
      throw new Error('Unsupported key type');
  }

  const out = key.export(opts);

  assertIsString(out, 'Unexpected export type');

  return out;
};
