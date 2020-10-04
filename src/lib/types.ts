import type { JWK } from 'node-jose';

export interface TokenRequest {
  scope?: string;
  grant_type: string;
  username?: unknown;
  client_id?: unknown;
  code?: string;
}

export interface Options {
  host?: string;
  port: number;
  keys: JWK.Key[];
  saveJWK: boolean;
  savePEM: boolean;
}

export interface MutableToken {
  header: Header;
  payload: Payload;
}

export interface Header {
  kid: string;
  [key: string]: unknown;
}

export interface Payload {
  iss: string;
  iat: number;
  exp: number;
  nbf: number;
  [key: string]: unknown;
}

export interface MutableResponse {
  body: Record<string, unknown> | null;
  statusCode: number;
}

export type ScopesOrTransform = string | string[] | JwtTransform;

export interface JwtTransform {
  (header: Header, payload: Payload): void;
}
