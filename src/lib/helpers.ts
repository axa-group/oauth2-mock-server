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

import { AssertionError } from 'node:assert';
import { readFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

import type { CodeChallenge, JWK, PKCEAlgorithm } from './types';
import { assertIsPlainObject } from './assertions';

export const defaultTokenTtl = 3600;

/**
 * Checks whether a code_verifier produces the expected code_challenge.
 * @param verifier The code_verifier provided by the client.
 * @param challenge The stored code_challenge to verify against.
 * @returns `true` if the verifier produces the expected challenge, `false` otherwise.
 */
export async function pkceVerifierMatchesChallenge(
  verifier: string,
  challenge: CodeChallenge,
): Promise<boolean> {
  const generatedChallenge = await createPKCECodeChallenge(
    verifier,
    challenge.method,
  );
  return generatedChallenge === challenge.challenge;
}

/**
 * Shifts a value from the given array, throwing an error
 * if the array is empty or the value is undefined.
 * @param arr - The array to shift a value from.
 * @returns The shifted value.
 */
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

/**
 * Reads a JSON file and parses its content.
 * @param filepath - The path to the JSON file.
 * @returns The parsed JSON object.
 */
export function readJsonFromFile(filepath: string): Record<string, unknown> {
  const content = readFileSync(filepath, 'utf8');

  const maybeJson = JSON.parse(content) as unknown;

  assertIsPlainObject(
    maybeJson,
    `File "${filepath}" doesn't contain a properly JSON serialized object.`,
  );

  return maybeJson;
}

/**
 * Validates whether a string conforms to the PKCE code_verifier format defined in RFC 7636.
 * @param verifier The code_verifier string to validate.
 * @returns `true` if the verifier is valid, `false` otherwise.
 */
export function isValidPkceCodeVerifier(verifier: string): boolean {
  const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;
  return PKCE_CHALLENGE_REGEX.test(verifier);
}

/**
 * Generates a cryptographically random PKCE code_verifier.
 * @returns A base64url-encoded random string suitable for use as a code_verifier.
 */
export function createPKCEVerifier(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(randomBytes).toString('base64url');
}

export const supportedPkceAlgorithms = ['plain', 'S256'] as const;

/**
 * Derives a PKCE code_challenge from a code_verifier and algorithm.
 * @param verifier The code_verifier to derive the challenge from. Defaults to a newly generated verifier.
 * @param algorithm The PKCE algorithm to use. Defaults to `'plain'`.
 * @returns The derived code_challenge string.
 */
export async function createPKCECodeChallenge(
  verifier: string = createPKCEVerifier(),
  algorithm: PKCEAlgorithm = 'plain',
): Promise<string> {
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
}

type JwkTransformer = (jwk: JWK) => JWK;

// eslint-disable-next-line func-style
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

// eslint-disable-next-line func-style
const EcdsaPrivateFieldsRemover: JwkTransformer = (jwk) => {
  const x = { ...jwk };

  delete x.d;

  return x;
};

// eslint-disable-next-line func-style
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

export const supportedAlgs: string[] = Object.keys(
  privateToPublicTransformerMap,
);

/**
 * Transforms a private JSON web key into a public one by removing the private fields.
 * @param privateKey The private JSON web key to transform.
 * @returns The public JSON web key.
 */
// eslint-disable-next-line func-style
export const privateToPublicKeyTransformer: JwkTransformer = (privateKey) => {
  const transformer = privateToPublicTransformerMap[privateKey.alg];

  if (transformer === undefined) {
    throw new Error(`Unsupported algo '${privateKey.alg}'`);
  }

  return transformer(privateKey);
};
