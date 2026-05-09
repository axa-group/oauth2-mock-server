/**
 * Quickstart: building a signed token directly.
 *
 * Use this pattern when the code under test consumes a pre-built JWT — for
 * example a middleware that validates a token or reads claims from it — and
 * you do not need to go through an HTTP grant flow to obtain it.
 *
 * Run with: npx tsx examples/quickstart.ts
 */

import { OAuth2Server } from 'oauth2-mock-server';

// ─── Mock server (your test setup) ───────────────────────────────────────────
// This part belongs in beforeAll() / a startup script.
// The server replaces your real IdP. It signs JWTs with a freshly generated
// key whose public counterpart is served at <issuerUrl>/jwks for verification.

const startMockServer = async (): Promise<OAuth2Server> => {
  const server = new OAuth2Server();

  // Generate a new RSA key. Tokens are signed with this key; the public
  // part is served at <issuerUrl>/jwks so consuming code can verify them.
  await server.issuer.keys.generate('RS256');

  // Port 0 lets the OS assign a free port automatically, avoiding conflicts.
  await server.start(0, 'localhost');

  console.log('Mock server started. Issuer URL:', server.issuer.url);
  return server;
};

// ─── Application under test (simulated client) ───────────────────────────────
// This represents what your application does when it needs a signed token.
// In your actual tests, replace this with the system under test that receives
// or validates a JWT produced by server.issuer.buildToken().

const buildTokenDirectly = async (server: OAuth2Server): Promise<void> => {
  const token = await server.issuer.buildToken();

  // A valid JWT has exactly three dot-separated base64url segments.
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(
      `Malformed JWT: expected 3 parts, got ${parts.length.toString()}`,
    );
  }

  console.log('Token built successfully. JWT length:', token.length);
};

// ─────────────────────────────────────────────────────────────────────────────

const run = async (): Promise<void> => {
  const server = await startMockServer();

  try {
    await buildTokenDirectly(server);
  } finally {
    await server.stop();
    console.log('Mock server stopped.');
  }
};

void run().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
