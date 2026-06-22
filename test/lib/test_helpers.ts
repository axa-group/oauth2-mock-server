import { Readable } from 'node:stream';
import type { IncomingMessage } from 'node:http';

import type { JWTVerifyResult } from "jose";
import { importJWK, jwtVerify } from "jose";
import { expect } from 'vitest';
import type request from 'supertest';

import type { OAuth2Issuer } from "../../src/lib/oauth2-issuer";
import { privateToPublicKeyTransformer } from "../../src/lib/jwk-store.keys";

export async function verifyTokenWithKey(
  issuer: OAuth2Issuer,
  token: string,
  kid: string
): Promise<JWTVerifyResult> {
  const key = issuer.keys.get(kid);

  if (key === undefined) {
    throw new Error("Key is undefined");
  }

  const publicKey = await importJWK(privateToPublicKeyTransformer(key));

  const verified = await jwtVerify(token, publicKey);
  return verified;
}

export function createMockRequest({
  body = '', contentType, url = '/',
}: {
  body?: string;
  contentType?: string;
  url?: string;
} = {}): IncomingMessage {
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  const readable = new Readable({ read() { } });
  readable.push(body);
  readable.push(null);
  const req = readable as unknown as IncomingMessage;
  req.headers = contentType ? { 'content-type': contentType } : {};
  req.url = url;
  return req;
}

export function assert400ProblemDetails(res: request.Response, detail: string) {
  expect(res.statusCode).toBe(400);

  expect(res.body).toMatchObject({
    type: 'https://tools.ietf.org/html/rfc9110#section-15.5.1',
    title: 'Bad Request',
    detail: detail,
  });

  expect(res.headers['content-type']).toMatch(/application\/problem\+json/);
}

export function createJwtAssertion(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');

  // Signature ommitted on purpose since this mock server explicitly ignores it
  return `${header}.${body}`;
}
