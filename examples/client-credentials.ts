/**
 * Client credentials grant: machine-to-machine token request.
 *
 * Use this pattern when testing a backend service that authenticates itself
 * to another service using its own credentials — no user is involved. This
 * is the standard OAuth2 flow for service-to-service communication.
 *
 * Run with: npx tsx examples/client-credentials.ts
 */

import { OAuth2Server } from 'oauth2-mock-server';

// ─── Mock server (your test setup) ───────────────────────────────────────────
// This part belongs in beforeAll() / a startup script.
// The server replaces your real IdP for the duration of the test run.

const startMockServer = async (): Promise<OAuth2Server> => {
  const server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0, 'localhost');
  console.log('Mock server started. Issuer URL:', server.issuer.url);
  return server;
};

// ─── Application under test (simulated client) ───────────────────────────────
// This represents what your backend service does to obtain an access token.
// In your actual tests, replace this with the service under test making its
// real token request to the configured issuer URL.

const simulateBackendCall = async (issuerUrl: string): Promise<void> => {
  const tokenUrl = new URL('/token', issuerUrl).href;

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'openid',
    }).toString(),
  });

  if (!response.ok) {
    throw new Error(
      `Token request failed with status ${response.status.toString()}`,
    );
  }

  const data = (await response.json()) as Record<string, unknown>;
  const accessToken = data['access_token'];

  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new Error('Expected a non-empty access_token in the response');
  }

  console.log('Access token received. Token type:', data['token_type']);
};

// ─────────────────────────────────────────────────────────────────────────────

const run = async (): Promise<void> => {
  const server = await startMockServer();

  try {
    const issuerUrl = server.issuer.url;
    if (issuerUrl === undefined) {
      throw new Error('Issuer URL is not set after server start');
    }
    await simulateBackendCall(issuerUrl);
  } finally {
    await server.stop();
    console.log('Mock server stopped.');
  }
};

void run().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
