import type { IncomingMessage, ServerResponse } from 'node:http';

import type { JWK as JoseJWK } from 'jose';

export interface JWKWithKid extends JoseJWK {
  kid: string;
  alg: string;
  [propName: string]: unknown;
}

export enum InternalEvents {
  BeforeSigning = 'beforeSigning',
}

export interface AugmentedRequest extends IncomingMessage {
  body: Record<string, unknown> | undefined;
  query: Record<string, string | string[] | undefined> | undefined;
}

export type RouteHandler = (
  req: AugmentedRequest,
  res: ServerResponse,
) => Promise<void> | void;
