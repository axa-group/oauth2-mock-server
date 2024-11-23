import type { JWK as JoseJWK } from 'jose';

export interface JWKWithKid extends JoseJWK {
  kid: string;
  alg: string;
  [propName: string]: unknown;
}

export enum InternalEvents {
  BeforeSigning = 'beforeSigning',
}
