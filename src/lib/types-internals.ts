import { JWK as JoseJWK } from 'jose';

export interface JWKWithKid extends JoseJWK {
  kid: string;
}

export enum InternalEvents {
  BeforeSigning = 'beforeSigning',
}
