/**
 * E2E global setup: long-running server with provider-shaped endpoints.
 *
 * Use this pattern when you need the mock server to start once before your
 * entire test suite and shut down afterwards — the Playwright globalSetup /
 * globalTeardown pattern, Vitest globalSetup, or a standalone process for
 * non-JS test runners (Java, Python, .NET). Custom endpoint paths let the
 * mock look exactly like the real provider your application is configured for.
 *
 * Run with: npx tsx examples/e2e-setup.ts
 */

import { OAuth2Server } from 'oauth2-mock-server';

// ─── Mock server (your test setup) ───────────────────────────────────────────
// This part belongs in your globalSetup function (Playwright / Vitest) or in
// a standalone startup script. Custom endpoint paths let the mock mirror the
// URL scheme of the real provider so your application config needs no changes.

const startMockServer = async (): Promise<OAuth2Server> => {
  // Match the endpoint paths of your real provider here.
  // The example below mirrors Keycloak's /protocol/openid-connect paths
  // using a simpler /oauth prefix.
  const server = new OAuth2Server(undefined, undefined, {
    endpoints: {
      token: '/oauth/token',
      jwks: '/oauth/jwks',
      authorize: '/oauth/authorize',
      userinfo: '/oauth/userinfo',
      revoke: '/oauth/revoke',
      endSession: '/oauth/logout',
      introspect: '/oauth/introspect',
    },
  });

  await server.issuer.keys.generate('RS256');
  await server.start(0, 'localhost');

  const issuerUrl = server.issuer.url;
  if (issuerUrl === undefined) {
    throw new Error('Issuer URL is not set after server start');
  }

  // In a real globalSetup you would persist the issuer URL so test workers
  // can read it, for example:
  //   process.env.AUTH_ISSUER = issuerUrl;
  //   await fs.writeFile('test/.auth/server.json', JSON.stringify({ issuerUrl }));
  console.log('Mock server started.');
  console.log('  Issuer URL  :', issuerUrl);
  console.log('  Token URL   :', new URL('/oauth/token', issuerUrl).href);
  console.log('  JWKS URL    :', new URL('/oauth/jwks', issuerUrl).href);

  return server;
};

// ─── Application under test (simulated client) ───────────────────────────────
// This represents an application discovering the OIDC provider configuration.
// In a real setup, your application (or test worker) would fetch this URL to
// resolve token/jwks/authorize endpoints at startup rather than hardcoding them.

const discoverEndpoints = async (issuerUrl: string): Promise<void> => {
  const discoveryUrl = new URL('/.well-known/openid-configuration', issuerUrl)
    .href;

  const response = await fetch(discoveryUrl);

  if (!response.ok) {
    throw new Error(
      `Discovery request failed with status ${response.status.toString()}`,
    );
  }

  const config = (await response.json()) as Record<string, unknown>;

  console.log('OIDC discovery successful.');
  console.log('  token_endpoint  :', config['token_endpoint']);
  console.log('  jwks_uri        :', config['jwks_uri']);
};

// ─────────────────────────────────────────────────────────────────────────────

const run = async (): Promise<void> => {
  const server = await startMockServer();

  try {
    const issuerUrl = server.issuer.url;
    if (issuerUrl === undefined) {
      throw new Error('Issuer URL is not set after server start');
    }
    await discoverEndpoints(issuerUrl);
  } finally {
    // In a real globalTeardown this is where you stop the server.
    await server.stop();
    console.log('Mock server stopped.');
  }
};

void run().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
