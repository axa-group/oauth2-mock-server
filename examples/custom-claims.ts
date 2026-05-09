/**
 * Custom claims: injecting user identity into tokens.
 *
 * Use this pattern when your application reads identity claims from the JWT
 * (sub, email, name, roles, etc.) and you need per-test control over those
 * values — for example to test that your app correctly identifies the
 * authenticated user, or to test access rules for different user profiles.
 *
 * Run with: npx tsx examples/custom-claims.ts
 */

import { OAuth2Server, Events } from 'oauth2-mock-server';
import type { MutableToken } from 'oauth2-mock-server';

// ─── Mock server (your test setup) ───────────────────────────────────────────
// This part belongs in beforeAll() / a startup script.
// Register the hook here to shape every token the server produces.
// Use server.service.once() instead of .on() to apply the hook to a single
// request only — useful when different tests need different claim sets.

const startMockServer = async (): Promise<OAuth2Server> => {
  const server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0, 'localhost');

  // Inject user identity claims into every token this server issues.
  // In a real test suite you would typically use .once() here and register
  // a different set of claims per test.
  server.service.on(Events.BeforeTokenSigning, (token: MutableToken) => {
    token.payload['sub'] = 'user-123';
    token.payload['email'] = 'user@example.com';
    token.payload['name'] = 'Test User';
  });

  console.log('Mock server started. Issuer URL:', server.issuer.url);
  return server;
};

// ─── Application under test (simulated client) ───────────────────────────────
// This represents what your application does after receiving a token — here
// we decode the JWT payload and assert that the expected claims are present.
// In your actual tests, replace this with the application code that reads
// claims (e.g. an auth middleware, a user-info resolver, a permission check).

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

  // Decode the JWT payload (the middle base64url segment) without verifying
  // the signature — verification is not the point of this example.
  const payloadSegment = accessToken.split('.')[1];
  if (payloadSegment === undefined) {
    throw new Error('Malformed JWT: missing payload segment');
  }
  const payload = JSON.parse(
    Buffer.from(payloadSegment, 'base64url').toString('utf8'),
  ) as Record<string, unknown>;

  // Assert the injected claims arrived in the token.
  if (payload['sub'] !== 'user-123') {
    throw new Error(`Expected sub=user-123, got: ${String(payload['sub'])}`);
  }
  if (payload['email'] !== 'user@example.com') {
    throw new Error(
      `Expected email=user@example.com, got: ${String(payload['email'])}`,
    );
  }
  if (payload['name'] !== 'Test User') {
    throw new Error(`Expected name=Test User, got: ${String(payload['name'])}`);
  }

  console.log(
    'Claims verified — sub:',
    payload['sub'],
    '| email:',
    payload['email'],
  );
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
