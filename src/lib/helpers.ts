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
import type { AddressInfo } from 'net';
import { readFileSync } from 'fs';

import isPlainObject from 'is-plain-obj';

import type { TokenRequest } from './types';

export const defaultTokenTtl = 3600;

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

export function assertIsValidTokenRequest(
  body: unknown,
): asserts body is TokenRequest {
  assertIsPlainObject(body, 'Invalid token request body');

  if ('scope' in body) {
    assertIsString(body['scope'], "Invalid 'scope' type");
  }

  assertIsString(body['grant_type'], "Invalid 'grant_type' type");

  if ('code' in body) {
    assertIsString(body['code'], "Invalid 'code' type");
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

export const readJsonFromFile = (filepath: string): Record<string, unknown> => {
  const content = readFileSync(filepath, 'utf8');

  const maybeJson = JSON.parse(content) as unknown;

  assertIsPlainObject(
    maybeJson,
    `File "${filepath}" doesn't contain a properly JSON serialized object.`,
  );

  return maybeJson;
};
