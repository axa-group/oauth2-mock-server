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

import { Buffer } from 'node:buffer';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { URL } from 'node:url';
import { AssertionError } from 'node:assert';

import isPlainObject from 'is-plain-obj';

import { assertIsString } from './assertions';
import type { OAuth2Endpoints } from './types';
import type { AugmentedRequest, RouteHandler } from './types-internals';

const readRawBody = (req: IncomingMessage): Promise<string> => {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });
    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', reject);
  });
};

const urlSearchParamsToRecord = (
  params: URLSearchParams,
): Record<string, string | string[] | undefined> => {
  if (params.size === 0) {
    return {};
  }

  const result: Record<string, string | string[]> = {};

  for (const [key, value] of params) {
    const existing = result[key];
    if (existing === undefined) {
      result[key] = value;
      continue;
    }

    if (Array.isArray(existing)) {
      existing.push(value);
      continue;
    }

    result[key] = [existing, value];
  }

  return result;
};

const parseUrlEncodedBody = (
  raw: string,
): Record<string, string | string[] | undefined> => {
  return urlSearchParamsToRecord(new URLSearchParams(raw));
};

const parseJsonBody = (raw: string): Record<string, unknown> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new AssertionError({
      message: 'Malformed JSON payload',
    });
  }

  if (!isPlainObject(parsed) && !Array.isArray(parsed)) {
    throw new AssertionError({
      message: 'Invalid JSON body: expected an object or array',
    });
  }

  return parsed as Record<string, unknown>;
};

/**
 * Parses the body of an incoming HTTP request.
 * Supports `application/x-www-form-urlencoded` and `application/json` content types.
 * Returns `undefined` when the content type is absent or not recognised.
 * @param req The incoming HTTP request.
 * @returns The parsed body, or `undefined` if the content type is not supported.
 */
export const parseBody = async (
  req: IncomingMessage,
): Promise<Record<string, unknown> | undefined> => {
  const contentType = req.headers['content-type'] ?? '';
  const raw = await readRawBody(req);

  if (contentType.includes('application/x-www-form-urlencoded')) {
    return parseUrlEncodedBody(raw);
  }

  if (contentType.includes('application/json')) {
    return parseJsonBody(raw);
  }

  return undefined;
};

/**
 * Parses query string parameters from an incoming HTTP request URL.
 * Keys that appear multiple times are collected into an array.
 * @param req The incoming HTTP request.
 * @returns A record mapping each query parameter name to its value(s).
 */
export const parseQuery = (
  req: IncomingMessage,
): Record<string, string | string[] | undefined> => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  return urlSearchParamsToRecord(url.searchParams);
};

const applyCorsHeaders = (res: ServerResponse): void => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

const ensureWriteable = (res: ServerResponse): void => {
  if (!res.writableEnded) {
    return;
  }

  throw new Error('Invalid response state: response already sent');
};

/**
 * Sends a JSON response.
 * @param res The server response object.
 * @param body The value to serialise as JSON.
 * @param status The HTTP status code. Defaults to `200`.
 */
export const sendJson = (
  res: ServerResponse,
  body: unknown,
  status = 200,
): void => {
  ensureWriteable(res);

  const content = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(content));
  res.end(content);
};

/**
 * Sends a 302 redirect response.
 * @param res The server response object.
 * @param url The URL to redirect to.
 */
export const sendRedirect = (res: ServerResponse, url: string): void => {
  ensureWriteable(res);

  res.statusCode = 302;
  res.setHeader('Location', url);
  res.end();
};

/**
 * Sends an empty response with no body.
 * @param res The server response object.
 * @param status The HTTP status code. Defaults to `200`.
 */
export const sendEmpty = (res: ServerResponse, status = 200): void => {
  ensureWriteable(res);

  res.statusCode = status;
  res.end();
};

/**
 * Normalises a URL path by stripping a trailing slash, unless the path is the root `/`.
 * @param path The URL path to normalise.
 * @returns The normalised path.
 */
export const normalizePath = (path: string): string => {
  const pathname = new URL(path, 'http://localhost').pathname;
  return pathname.length > 1 && pathname.endsWith('/')
    ? pathname.slice(0, -1)
    : pathname;
};

/**
 * Converts an unknown error into a structured JSON error response.
 * `AssertionError` instances produce a 400 `invalid_request`; all other errors produce 500.
 * @param err The error to handle.
 * @param res The server response object.
 */
export const errorHandler = (err: unknown, res: ServerResponse): void => {
  let status = 400;
  const errorBody: Record<string, unknown> = {};

  if (err instanceof AssertionError) {
    errorBody['error'] = 'invalid_request';
    errorBody['error_description'] = err.message;
  } else {
    console.error('Unexpected error:', err);

    status = 500;
    errorBody['error'] =
      'Most certainly a bug in the library code. ' +
      'Check the logs for more details and report this to the maintainers.';
  }

  sendJson(res, errorBody, status);
};

/**
 * Dispatches an incoming request to the matching route handler.
 * Applies CORS headers, handles OPTIONS pre-flight, normalises the path,
 * and returns 404 when no route matches.
 * @param routes A map of `"METHOD:path"` keys to route handler functions.
 * @param req The incoming HTTP request.
 * @param res The server response object.
 */
export const dispatch = async (
  routes: Map<string, RouteHandler>,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> => {
  applyCorsHeaders(res);

  assertIsString(req.method, 'Invalid HTTP method');

  if (req.method === 'OPTIONS') {
    sendEmpty(res, 204);
    return;
  }

  // Mimics Express default lenient routing behavior (trailing slashes are ignored)
  const pathname = normalizePath(req.url ?? '/');

  const handler = routes.get(`${req.method}:${pathname}`);

  if (handler === undefined) {
    sendEmpty(res, 404);
    return;
  }

  await handler(req as AugmentedRequest, res);
};

/**
 * Validates that all provided endpoint paths start with a forward slash.
 * Throws an `AssertionError` listing every invalid entry if any are found.
 * @param endpoints The partial endpoint overrides to validate.
 */
export const assertEndpointsStartWithAForwardSlash = (
  endpoints: Partial<OAuth2Endpoints> | undefined,
): void => {
  if (endpoints === undefined) {
    return;
  }

  const invalidEndpoints = Object.entries(endpoints)
    .filter(([, path]) => !path.startsWith('/'))
    .map(([name, path]) => `"${name}": "${path}"`);

  if (invalidEndpoints.length > 0) {
    throw new AssertionError({
      message: `All endpoint paths must start with a forward slash. Invalid endpoints: ${invalidEndpoints.join(
        ', ',
      )}`,
    });
  }
};

/**
 * Concatenates a base URL and a path, stripping a trailing slash from the base if present.
 * @param base The base URL string.
 * @param path The path segment to append.
 * @returns The combined URL string.
 */
export const urlCombine = (base: string, path: string): string => {
  if (!base.endsWith('/')) {
    return `${base}${path}`;
  }

  return `${base.slice(0, -1)}${path}`;
};
