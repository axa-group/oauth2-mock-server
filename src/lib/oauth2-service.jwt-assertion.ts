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

/** @module lib/oauth2-service.jwt-assertion */

import { Buffer } from 'node:buffer';
import { AssertionError } from 'node:assert';

import { assertIsPlainObject, assertIsString } from './assertions';

export const jwtBearerGrantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

export interface JwtBearerAssertionPayload {
  sub: string;
  [key: string]: unknown;
}

/**
 * Parses the payload part of a JWT Bearer assertion.
 * The JWT signature is intentionally ignored because this mock server does not
 * cryptographically validate incoming assertions.
 * @param assertion The incoming JWT assertion.
 * @returns The decoded payload object.
 */
export function parseJwtBearerAssertionPayload(
  assertion: string,
): JwtBearerAssertionPayload {
  const encodedPayload = assertion.split('.').at(1);

  if (encodedPayload === undefined) {
    throw new AssertionError({
      message: "Invalid 'assertion' format: expected at least header.payload",
    });
  }

  const decodedPayload = Buffer.from(encodedPayload, 'base64url').toString(
    'utf8',
  );

  let payload: unknown;
  try {
    payload = JSON.parse(decodedPayload) as unknown;
  } catch {
    throw new AssertionError({
      message: "Invalid 'assertion' payload: malformed JSON",
    });
  }

  assertIsPlainObject(
    payload,
    "Invalid 'assertion' payload: expected an object",
  );

  assertIsString(
    payload['sub'],
    "Invalid 'assertion' payload: 'sub' claim is expected to be a string",
  );

  return payload as JwtBearerAssertionPayload;
}
