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

export const supportedPkceAlgorithms = ['plain', 'S256'] as const;

export const supportedHttpMethods = ['GET', 'POST'] as const;
export type HttpMethod = (typeof supportedHttpMethods)[number];

export interface AugmentedRequest extends IncomingMessage {
  body: Record<string, unknown> | undefined;
  query: Record<string, string | string[] | undefined>;
}

export type RouteHandler = (
  req: AugmentedRequest,
  res: ServerResponse,
) => Promise<void> | void;
