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

import { Buffer } from 'node:buffer';
import { webcrypto as crypto } from 'node:crypto';

import type { CodeChallenge, PKCEAlgorithm } from './types';

/**
 * Validates whether a string conforms to the PKCE code_verifier format defined in RFC 7636.
 * @param verifier The code_verifier string to validate.
 * @returns `true` if the verifier is valid, `false` otherwise.
 */
export const isValidPkceCodeVerifier = (verifier: string): boolean => {
  const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;
  return PKCE_CHALLENGE_REGEX.test(verifier);
};

/**
 * Generates a cryptographically random PKCE code_verifier.
 * @returns A base64url-encoded random string suitable for use as a code_verifier.
 */
export const createPKCEVerifier = (): string => {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(randomBytes).toString('base64url');
};

/**
 * Derives a PKCE code_challenge from a code_verifier and algorithm.
 * @param verifier The code_verifier to derive the challenge from. Defaults to a newly generated verifier.
 * @param algorithm The PKCE algorithm to use. Defaults to `'plain'`.
 * @returns The derived code_challenge string.
 */
export const createPKCECodeChallenge = async (
  verifier: string = createPKCEVerifier(),
  algorithm: PKCEAlgorithm = 'plain',
): Promise<string> => {
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

/**
 * Checks whether a code_verifier produces the expected code_challenge.
 * @param verifier The code_verifier provided by the client.
 * @param challenge The stored code_challenge to verify against.
 * @returns `true` if the verifier produces the expected challenge, `false` otherwise.
 */
export const pkceVerifierMatchesChallenge = async (
  verifier: string,
  challenge: CodeChallenge,
): Promise<boolean> => {
  const generatedChallenge = await createPKCECodeChallenge(
    verifier,
    challenge.method,
  );
  return generatedChallenge === challenge.challenge;
};
