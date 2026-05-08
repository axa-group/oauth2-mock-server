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

import { URL } from 'node:url';
import { AssertionError } from 'node:assert';

import type { OAuth2Endpoints } from './types';
import type {} from './types-internals';

/**
 * Normalises a URL path by stripping a trailing slash, unless the path is the root `/`.
 * @param path The URL path to normalise.
 * @returns The normalised path.
 */
export function normalizePath(path: string): string {
  const pathname = new URL(path, 'http://localhost').pathname;
  return pathname.length > 1 && pathname.endsWith('/')
    ? pathname.slice(0, -1)
    : pathname;
}

/**
 * Validates that all provided endpoint paths start with a forward slash.
 * Throws an `AssertionError` listing every invalid entry if any are found.
 * @param endpoints The partial endpoint overrides to validate.
 */
export function assertEndpointsStartWithAForwardSlash(
  endpoints: Partial<OAuth2Endpoints> | undefined,
): void {
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
}

/**
 * Concatenates a base URL and a path, stripping a trailing slash from the base if present.
 * @param base The base URL string.
 * @param path The path segment to append.
 * @returns The combined URL string.
 */
export function urlCombine(base: string, path: string): string {
  if (!base.endsWith('/')) {
    return `${base}${path}`;
  }

  return `${base.slice(0, -1)}${path}`;
}
