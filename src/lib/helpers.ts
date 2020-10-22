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
import type jwt from 'jsonwebtoken';
import isPlainObject from 'lodash.isplainobject';
import type { AddressInfo } from 'net';

import type { TokenRequest } from './types';

export function assertIsString(
  input: unknown,
  errorMessage: string
): asserts input is string {
  if (typeof input !== 'string') {
    throw new AssertionError({ message: errorMessage });
  }
}

export const supportedAlgs = [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
  'none',
];

export function assertIsAlgorithm(
  input: string
): asserts input is jwt.Algorithm {
  if (!supportedAlgs.includes(input)) {
    throw new AssertionError({ message: `Unssuported algorithm '${input}'` });
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
