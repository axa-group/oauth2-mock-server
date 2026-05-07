import type { JWTVerifyResult } from "jose";
import { importJWK, jwtVerify } from "jose";

import type { OAuth2Issuer } from "../../src/lib/oauth2-issuer";
import { privateToPublicKeyTransformer } from "../../src/lib/helpers";

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
