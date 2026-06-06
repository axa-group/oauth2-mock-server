import type { JWK as JoseJWK } from 'jose';

export interface JWKWithKid extends JoseJWK {
  kid: string;
  alg: string;
  [propName: string]: unknown;
}

export enum InternalEvents {
  BeforeSigning = 'beforeSigning',
}

export const supportedPkceAlgorithms = ['plain', 'S256'] as const;

export interface ProblemDetails {
  type: string;
  title: string;
  detail: string;
}
