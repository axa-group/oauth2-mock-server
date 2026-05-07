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
import type { IncomingMessage, ServerResponse } from 'node:http';
import { AssertionError } from 'node:assert';
import { readFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

import isPlainObject from 'is-plain-obj';

import type { CodeChallenge, JWK, PKCEAlgorithm } from './types';
import { assertIsPlainObject } from './assertions';

export const defaultTokenTtl = 3600;

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

export const shift = (arr: (string | undefined)[]): string => {
  if (arr.length === 0) {
    throw new AssertionError({ message: 'Empty array' });
  }

  const val = arr.shift();

  if (val === undefined) {
    throw new AssertionError({ message: 'Empty value' });
  }

  return val;
};

export const readJsonFromFile = (filepath: string): Record<string, unknown> => {
  const content = readFileSync(filepath, 'utf8');

  const maybeJson = JSON.parse(content) as unknown;

  assertIsPlainObject(
    maybeJson,
    `File "${filepath}" doesn't contain a properly JSON serialized object.`,
  );

  return maybeJson;
};

export const isValidPkceCodeVerifier = (verifier: string): boolean => {
  const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;
  return PKCE_CHALLENGE_REGEX.test(verifier);
};

export const createPKCEVerifier = (): string => {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(randomBytes).toString('base64url');
};

export const supportedPkceAlgorithms = ['plain', 'S256'] as const;

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

export const supportedAlgs: string[] = Object.keys(
  privateToPublicTransformerMap,
);

export const privateToPublicKeyTransformer = (privateKey: JWK): JWK => {
  const transformer = privateToPublicTransformerMap[privateKey.alg];

  if (transformer === undefined) {
    throw new Error(`Unsupported algo '${privateKey.alg}'`);
  }

  return transformer(privateKey);
};

export const readRawBody = (req: IncomingMessage): Promise<string> => {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });
    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', reject);
  });
};

const urlSearchParamsToRecord = (
  params: URLSearchParams,
): Record<string, string | string[] | undefined> => {
  if (params.size === 0) {
    return {};
  }

  const result: Record<string, string | string[]> = {};

  for (const [key, value] of params) {
    const existing = result[key];
    if (existing === undefined) {
      result[key] = value;
      continue;
    }

    if (Array.isArray(existing)) {
      existing.push(value);
      continue;
    }

    result[key] = [existing, value];
  }

  return result;
};

const parseUrlEncodedBody = (
  raw: string,
): Record<string, string | string[] | undefined> => {
  return urlSearchParamsToRecord(new URLSearchParams(raw));
};

const parseJsonBody = (raw: string): Record<string, unknown> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new AssertionError({
      message: 'Malformed JSON payload',
    });
  }

  if (!isPlainObject(parsed) && !Array.isArray(parsed)) {
    throw new AssertionError({
      message: 'Invalid JSON body: expected an object or array',
    });
  }

  return parsed as Record<string, unknown>;
};

export const parseBody = async (
  req: IncomingMessage,
): Promise<Record<string, unknown> | undefined> => {
  const contentType = req.headers['content-type'] ?? '';
  const raw = await readRawBody(req);

  if (contentType.includes('application/x-www-form-urlencoded')) {
    return parseUrlEncodedBody(raw);
  }

  if (contentType.includes('application/json')) {
    return parseJsonBody(raw);
  }

  return undefined;
};

export const parseQuery = (
  req: IncomingMessage,
): Record<string, string | string[] | undefined> => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  return urlSearchParamsToRecord(url.searchParams);
};

export const applyCorsHeaders = (res: ServerResponse): void => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

export const sendJson = (
  res: ServerResponse,
  body: unknown,
  status = 200,
): void => {
  ensureWriteable(res);

  const content = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(content));
  res.end(content);
};

export const sendRedirect = (res: ServerResponse, url: string): void => {
  ensureWriteable(res);

  res.statusCode = 302;
  res.setHeader('Location', url);
  res.end();
};

export const sendEmpty = (res: ServerResponse, status = 200): void => {
  ensureWriteable(res);

  res.statusCode = status;
  res.end();
};

export const normalizePath = (path: string): string => {
  const pathname = new URL(path, 'http://localhost').pathname;
  return pathname.length > 1 && pathname.endsWith('/')
    ? pathname.slice(0, -1)
    : pathname;
};

const ensureWriteable = (res: ServerResponse) => {
  if (!res.writableEnded) {
    return;
  }

  throw new Error('Invalid response state: response already sent');
};
