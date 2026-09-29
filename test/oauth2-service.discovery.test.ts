import { IncomingMessage } from 'node:http';

import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';

import { Events, OAuth2Issuer, OAuth2Service } from '../src';
import type { MutableResponse } from '../src';

describe('OpenID configuration event', () => {
  it('exports the discovery event name', () => {
    expect(Events.BeforeWellKnownOpenIdConfiguration).toBe(
      'beforeWellKnownOpenIdConfiguration',
    );
  });
});

describe.each([
  {
    name: 'default endpoints',
    issuerUrl: 'http://internal-provider:8080',
    discoveryPath: '/.well-known/openid-configuration',
    endpoints: undefined,
  },
  {
    name: 'custom endpoints and a trailing issuer slash',
    issuerUrl: 'http://internal-provider:8080/',
    discoveryPath: '/custom-discovery',
    endpoints: {
      wellKnownDocument: '/custom-discovery',
      authorize: '/custom-authorize',
      token: '/custom-token',
      jwks: '/custom-jwks',
    },
  },
])('OpenID configuration event with $name', (configuration) => {
  let service: OAuth2Service;

  beforeEach(() => {
    const issuer = new OAuth2Issuer();
    issuer.url = configuration.issuerUrl;
    service = new OAuth2Service(issuer, configuration.endpoints);
  });

  it('allows a persistent authorization endpoint override without changing other metadata', async () => {
    const original = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    let incomingRequest: IncomingMessage | undefined;

    service.on(
      'beforeWellKnownOpenIdConfiguration',
      (response: MutableResponse, req: IncomingMessage) => {
        incomingRequest = req;
        Object.assign(response.body, {
          authorization_endpoint: 'http://localhost:8080/browser-authorize',
        });
      },
    );

    const changed = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .set('X-Scenario', 'browser-host')
      .expect(200);

    expect(incomingRequest).toBeInstanceOf(IncomingMessage);
    expect(incomingRequest?.url).toBe(configuration.discoveryPath);
    expect(incomingRequest?.headers['x-scenario']).toBe('browser-host');
    expect(changed.body).toEqual({
      ...original.body,
      authorization_endpoint: 'http://localhost:8080/browser-authorize',
    });
    expect(service.issuer.url).toBe(configuration.issuerUrl);

    const next = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    expect(next.body).toEqual(changed.body);
  });

  it('allows a one-time body and status override without changing later responses', async () => {
    const original = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);

    service.once(
      'beforeWellKnownOpenIdConfiguration',
      (response: MutableResponse) => {
        response.body = { error: 'temporarily_unavailable' };
        response.statusCode = 503;
      },
    );

    const changed = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(503);
    expect(changed.body).toEqual({ error: 'temporarily_unavailable' });

    const next = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    expect(next.body).toEqual(original.body);
  });

  it('allows an empty response body', async () => {
    service.once(
      'beforeWellKnownOpenIdConfiguration',
      (response: MutableResponse) => {
        response.body = '';
        response.statusCode = 204;
      },
    );

    const changed = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(204);
    expect(changed.text).toBe('');
  });

  it('keeps nested metadata mutations local to the intercepted response', async () => {
    const original = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    const otherService = new OAuth2Service(
      service.issuer,
      configuration.endpoints,
    );

    service.once(
      'beforeWellKnownOpenIdConfiguration',
      (response: MutableResponse) => {
        const body = response.body as Record<string, unknown>;
        const methods = body['code_challenge_methods_supported'] as string[];
        methods.push('custom-test-method');
      },
    );

    const changed = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    expect(changed.body.code_challenge_methods_supported).toEqual([
      'plain',
      'S256',
      'custom-test-method',
    ]);

    const next = await request(service.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    const other = await request(otherService.requestHandler)
      .get(configuration.discoveryPath)
      .expect(200);
    expect(next.body).toEqual(original.body);
    expect(other.body).toEqual(original.body);
  });
});
