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

/** @module lib/assertions */

/* eslint-disable func-style */
/* eslint-disable jsdoc/require-jsdoc */

import { AssertionError } from 'node:assert';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';

import isPlainObject from 'is-plain-obj';

import type { TokenRequest } from './types';
import type { JWKWithKid } from './types-internals';

export function assertIsString(
  input: unknown,
  errorMessage: string,
): asserts input is string {
  if (typeof input !== 'string') {
    throw new AssertionError({ message: errorMessage });
  }
}

export function assertIsStringOrUndefined(
  input: unknown,
  errorMessage: string,
): asserts input is string | undefined {
  if (typeof input !== 'string' && input !== undefined) {
    throw new AssertionError({ message: errorMessage });
  }
}

export function assertIsAddressInfo(
  input: string | null | AddressInfo,
): asserts input is AddressInfo {
  if (input === null || typeof input === 'string') {
    throw new AssertionError({ message: 'Unexpected address type' });
  }
}

export function assertIsPlainObject(
  obj: unknown,
  errMessage: string,
): asserts obj is Record<string, unknown> {
  if (!isPlainObject(obj)) {
    throw new AssertionError({ message: errMessage });
  }
}

const validateAudField = (aud: unknown): void => {
  if (!Array.isArray(aud)) {
    assertIsString(aud, "Invalid 'aud' type");
    return;
  }

  aud.forEach((a) => {
    assertIsString(a, "Invalid 'aud' type");
  });
};

export function assertIsValidTokenRequest(
  body: unknown,
): asserts body is TokenRequest {
  assertIsPlainObject(body, 'Invalid token request body');

  assertIsString(body['grant_type'], "Invalid 'grant_type' type");

  if ('scope' in body) {
    assertIsString(body['scope'], "Invalid 'scope' type");
  }

  if ('code' in body) {
    assertIsString(body['code'], "Invalid 'code' type");
  }

  if ('aud' in body) {
    validateAudField(body['aud']);
  }
}

const generateRandomKid = () => {
  return randomBytes(40).toString('hex');
};

export function assertIsJwtWithKid(
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
