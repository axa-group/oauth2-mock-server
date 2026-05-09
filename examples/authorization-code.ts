/**
 * Authorization code grant with PKCE: browser and native app flows.
 *
 * Use this pattern when testing code that implements the authorization code
 * flow — a backend callback handler, an OAuth client library integration, or
 * an end-to-end flow that includes a browser redirect through the IdP.
 * PKCE (RFC 7636) is strongly recommended for all authorization code flows.
 *
 * Run with: npx tsx examples/authorization-code.ts
 */

import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';

import { OAuth2Server } from 'oauth2-mock-server';

// PKCE helpers — in a real application these would typically come from an
// OAuth client library rather than being hand-rolled.

const createVerifier = (): string => randomBytes(32).toString('base64url');

const createChallenge = (verifier: string): string =>
  createHash('sha256').update(verifier).digest('base64url');

// Make an HTTP GET without following redirects and return the Location header.
// We use node:http directly so we can capture the 302 Location before the
// redirect is followed — fetch's redirect:'manual' returns an opaque response
// in Node.js that hides the headers.
const getRedirectLocation = (url: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const req = httpRequest(url, (res) => {
      const location = res.headers.location;
      if (typeof location !== 'string') {
        reject(
          new Error(`Expected a Location header in the redirect response`),
        );
        return;
      }
      resolve(location);
      res.resume(); // discard body to free the socket
    });
    req.on('error', reject);
    req.end();
  });

// ─── Mock server (your test setup) ───────────────────────────────────────────
// This part belongs in beforeAll() / a startup script.
// The server handles /authorize redirects and /token exchanges automatically —
// no custom hooks are needed for a standard authorization code flow.

const startMockServer = async (): Promise<OAuth2Server> => {
  const server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0, 'localhost');
  console.log('Mock server started. Issuer URL:', server.issuer.url);
  return server;
};

// ─── Application under test (simulated client) ───────────────────────────────
// This represents what an OAuth2 client (browser app or native app) does:
//   1. Navigate to /authorize — the IdP redirects back with a code.
//   2. Exchange the code + code_verifier at /token for an access token.
// In your actual tests, replace this with the OAuth client under test.

const simulateBrowserFlow = async (issuerUrl: string): Promise<void> => {
  const verifier = createVerifier();
  const challenge = createChallenge(verifier);
  const redirectUri = 'http://localhost/callback';

  // Step 1 — Navigate to the authorization endpoint.
  // The mock server immediately redirects to redirect_uri with a code.
  const authorizeUrl = new URL('/authorize', issuerUrl);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', 'test-client');
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('scope', 'openid');
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  authorizeUrl.searchParams.set('state', 'test-state');

  const location = await getRedirectLocation(authorizeUrl.href);
  console.log('Authorization redirect received.');

  // Step 2 — Extract the authorization code from the callback URL.
  const callbackUrl = new URL(location);
  const code = callbackUrl.searchParams.get('code');

  if (code === null) {
    throw new Error('No authorization code found in redirect URL');
  }

  // Step 3 — Exchange the code for tokens (what the backend does after
  // receiving the callback request from the browser).
  const tokenResponse = await fetch(new URL('/token', issuerUrl).href, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: 'test-client',
      code_verifier: verifier,
    }).toString(),
  });

  if (!tokenResponse.ok) {
    const body = await tokenResponse.text();
    throw new Error(
      `Token exchange failed: ${tokenResponse.status.toString()} ${body}`,
    );
  }

  const data = (await tokenResponse.json()) as Record<string, unknown>;
  const accessToken = data['access_token'];

  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new Error('Expected a non-empty access_token in the token response');
  }

  console.log('Access token received via authorization code + PKCE flow.');
};

// ─────────────────────────────────────────────────────────────────────────────

const run = async (): Promise<void> => {
  const server = await startMockServer();

  try {
    const issuerUrl = server.issuer.url;
    if (issuerUrl === undefined) {
      throw new Error('Issuer URL is not set after server start');
    }
    await simulateBrowserFlow(issuerUrl);
  } finally {
    await server.stop();
    console.log('Mock server stopped.');
  }
};

void run().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
