'use strict';

const request = require('supertest');
const OAuth2Server = require('../lib/oauth2-server');

describe('OAuth 2 Server', () => {
  it('should be able to start and stop the server', async () => {
    const server = new OAuth2Server();

    await expect(server.start()).resolves.not.toThrow();

    const host = `http://127.0.0.1:${server.address().port}`;
    await request(host).get('/').expect(404);

    await expect(server.stop()).resolves.not.toThrow();
  });

  it('should have an issuer URL that matches the server\'s endpoint', async () => {
    const server = new OAuth2Server();

    expect(server.issuer.url).toBeNull();

    await server.start(null, 'localhost');
    expect(server.issuer.url).toEqual(`http://localhost:${server.address().port}`);

    await expect(server.stop());
  });
});
