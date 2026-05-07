import { Readable } from 'node:stream';
import type { IncomingMessage } from 'node:http';

import type {JWTVerifyResult } from "jose";
import { importJWK, jwtVerify } from "jose";

import type { OAuth2Issuer } from "../../src/lib/oauth2-issuer";
import { privateToPublicKeyTransformer } from "../../src/lib/helpers";

export const verifyTokenWithKey = async (issuer: OAuth2Issuer, token: string, kid: string): Promise<JWTVerifyResult> => {
  const key = issuer.keys.get(kid);

  if (key === undefined) {
    throw new Error('Key is undefined');
  }

  const publicKey = await importJWK(privateToPublicKeyTransformer(key));

  const verified = await jwtVerify(token, publicKey);
  return verified;
};

export const createMockRequest = ({
  body = '',
  contentType,
  url = '/',
}: {
  body?: string;
  contentType?: string;
  url?: string;
} = {}): IncomingMessage => {
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  const readable = new Readable({ read() {} });
  readable.push(body);
  readable.push(null);
  const req = readable as unknown as IncomingMessage;
  req.headers = contentType ? { 'content-type': contentType } : {};
  req.url = url;
  return req;
};
