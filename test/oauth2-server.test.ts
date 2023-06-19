import { describe, it, expect } from 'vitest';
import request from 'supertest';

import { OAuth2Server } from '../src/lib/oauth2-server';

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

    expect(server.issuer.url).toBeUndefined();

    await server.start(undefined, 'localhost');
    expect(server.issuer.url).toBe(`http://localhost:${server.address().port}`);

    await expect(server.stop()).resolves.toBeUndefined();
  });

  it('should expose the oauth2 service', () => {
    const server = new OAuth2Server();

    expect(server.service).toBeDefined();
  });

  it("should throw if only one of cert/key is supplied", () => {
    expect(() => {
      new OAuth2Server("test/keys/localhost-key.pem");
    }).toThrow();

    expect(() => {
      new OAuth2Server(undefined, "test/keys/localhost-cert.pem");
    }).toThrow();
  });

  it('should not raise an UnhandledPromiseRejectionWarning when wrongly invoking the /token endpoint', async () => {
    const server = new OAuth2Server();

    await expect(server.start()).resolves.not.toThrow();

    const host = `http://127.0.0.1:${server.address().port}`;
    const res = await request(host)
      .post('/token')
      .set('Content-Type', 'multipart/form-data;');

    expect(res.text).toContain("[ERR_ASSERTION]: Invalid &#39;grant_type&#39; type");

    await expect(server.stop()).resolves.not.toThrow();
  });

  it('should override custom endpoint pathnames', async () => {
    const endpoints = { jwks: '/custom-jwks' };
    const server = new OAuth2Server(undefined, undefined, { endpoints });

    await expect(server.start()).resolves.not.toThrow();

    const host = `http://127.0.0.1:${server.address().port}`;
    await request(host)
      .get('/custom-jwks')
      .expect(200);

    await expect(server.stop()).resolves.not.toThrow();
  });
});
