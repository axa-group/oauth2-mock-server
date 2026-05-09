'use strict';

const { OAuth2Server } = require('oauth2-mock-server');

async function run() {
  const server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0, 'localhost');
  console.log('Server started:', server.issuer.url);

  try {
    const res = await fetch(new URL('/token', server.issuer.url).href, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'openid' }).toString(),
    });

    if (!res.ok) {
      throw new Error(`POST /token failed: ${res.status}`);
    }

    const data = await res.json();

    if (typeof data.access_token !== 'string' || data.access_token.length === 0) {
      throw new Error('Expected a non-empty access_token');
    }

    console.log('Token received.');
  } finally {
    await server.stop();
    console.log('Server stopped.');
  }

  console.log('CJS require: OK');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
