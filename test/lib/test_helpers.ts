import { AssertionError } from "assert";

import type {JWTVerifyResult } from "jose";
import { importJWK, jwtVerify } from "jose";

import type { OAuth2Issuer } from "../../src/lib/oauth2-issuer";

export const verifyTokenWithKey = async (issuer: OAuth2Issuer, token: string, kid: string): Promise<JWTVerifyResult> => {
  const key = issuer.keys.get(kid);

  if (key === undefined) {
    throw new AssertionError({ message: 'Key is undefined' });
  }

  const privateKey = await importJWK(key);

  const verified = await jwtVerify(token, privateKey);
  return verified;
};
