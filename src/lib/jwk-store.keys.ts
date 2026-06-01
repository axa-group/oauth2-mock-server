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

import type { JWK } from './types';

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
  Ed25519: EddsaPrivateFieldsRemover,
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
