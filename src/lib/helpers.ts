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

import { AssertionError } from 'node:assert';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

import isPlainObject from 'is-plain-obj';

import type { CodeChallenge, JWK, PKCEAlgorithm, TokenRequest } from './types';

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

export async function pkceVerifierMatchesChallenge(
  verifier: string,
  challenge: CodeChallenge,
) {
  const generatedChallenge = await createPKCECodeChallenge(
    verifier,
    challenge.method,
  );
  return generatedChallenge === challenge.challenge;
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

  if ('aud' in body) {
    const aud = body['aud'];
    if (Array.isArray(aud)) {
      aud.forEach((a) => {
        assertIsString(a, "Invalid 'aud' type");
      });
    } else {
      assertIsString(aud, "Invalid 'aud' type");
    }
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

export const isValidPkceCodeVerifier = (verifier: string) => {
  const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;
  return PKCE_CHALLENGE_REGEX.test(verifier);
};

export const createPKCEVerifier = () => {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(randomBytes).toString('base64url');
};

export const supportedPkceAlgorithms = ['plain', 'S256'] as const;

export const createPKCECodeChallenge = async (
  verifier: string = createPKCEVerifier(),
  algorithm: PKCEAlgorithm = 'plain',
) => {
  let challenge: string;

  switch (algorithm) {
    case 'plain': {
      challenge = verifier;
      break;
    }
    case 'S256': {
      const buffer = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(verifier),
      );
      challenge = Buffer.from(buffer).toString('base64url');
      break;
    }
    default:
      throw new Error(`Unsupported PKCE method ("${algorithm as string}")`);
  }
  return challenge;
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
  ES384: EcdsaPrivateFieldsRemover,
  ES512: EcdsaPrivateFieldsRemover,

  // Edwards-curve DSA
  EdDSA: EddsaPrivateFieldsRemover,
};

export const supportedAlgs = Object.keys(privateToPublicTransformerMap);

export const privateToPublicKeyTransformer = (privateKey: JWK): JWK => {
  const transformer = privateToPublicTransformerMap[privateKey.alg];

  if (transformer === undefined) {
    throw new Error(`Unsupported algo '${privateKey.alg}'`);
  }

  return transformer(privateKey);
};
