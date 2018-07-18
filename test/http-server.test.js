'use strict';

const HttpServer = require('../lib/http-server');
const request = require('supertest');

describe('HTTP Server', () => {
  it('should be able to start and stop the server', async () => {
    let server = new HttpServer(dummyHandler);

    await expect(server.start()).resolves.not.toThrow();

    let host = `http://127.0.0.1:${server.address().port}`;
    let res = await request(host).get('/').expect(200);

    expect(res.body).toEqual({
      value: 'Dummy response'
    });

    await expect(server.stop()).resolves.not.toThrow();
  });

  it('should be listening only when the server is started', async () => {
    let server = new HttpServer(dummyHandler);
    expect(server.listening).toBe(false);

    await server.start();
    expect(server.listening).toBe(true);

    await server.stop();
    expect(server.listening).toBe(false);
  });

  it('should have an address only when the server is started', async () => {
    let server = new HttpServer(dummyHandler);
    expect(() => server.address()).toThrow('Server is not started.');

    await server.start();
    expect(server.address()).toMatchObject({
      address: expect.any(String),
      family: expect.stringMatching(/IPv4|IPv6/),
      port: expect.any(Number)
    });

    await server.stop();
    expect(() => server.address()).toThrow('Server is not started.');
  });

  it('should not be able to start the server when it\'s already started', async () => {
    let server = new HttpServer(dummyHandler);

    await server.start();

    await expect(server.start()).rejects.toThrow('Server has already been started.');

    await server.stop();
  });

  it('should not be able to stop the server when it\'s already stopped', async () => {
    let server = new HttpServer(dummyHandler);

    await expect(server.stop()).rejects.toThrow('Server is not started.');
  });
});

function dummyHandler(req, res) {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end('{ "value": "Dummy response" }');
}
