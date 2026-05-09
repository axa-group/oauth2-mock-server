# Integration Guide

This guide covers how to use `oauth2-mock-server` in three common scenarios:

1. [JS/TS test suite](#jsts-test-suite) — embed the server in Vitest, Jest, or Mocha
2. [Non-JS projects](#non-js-projects) — run the server via CLI for Java, .NET, Python, etc.
3. [CI pipeline](#ci-pipeline) — cross-platform strategies for starting and stopping the server in CI

---

## JS/TS test suite

The recommended approach for JavaScript and TypeScript projects is to start the server programmatically in a `beforeAll` hook and stop it in `afterAll`. This gives you dynamic port assignment (no port conflicts) and full access to the event hook API.

### Vitest

```ts
// auth-server.setup.ts
import { beforeAll, afterAll } from 'vitest';
import { OAuth2Server } from 'oauth2-mock-server';

let server: OAuth2Server;

beforeAll(async () => {
  server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0); // 0 = OS-assigned port
  process.env['OAUTH2_ISSUER_URL'] = server.issuer.url!;
});

afterAll(async () => {
  await server.stop();
});
```

Reference the setup file from `vitest.config.ts`:

```ts
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    setupFiles: ['./auth-server.setup.ts'],
  },
});
```

### Jest

```ts
// globalSetup.ts
import { OAuth2Server } from 'oauth2-mock-server';

let server: OAuth2Server;

export async function setup() {
  server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0);
  process.env['OAUTH2_ISSUER_URL'] = server.issuer.url!;
}

export async function teardown() {
  await server.stop();
}
```

```js
// jest.config.js
module.exports = {
  globalSetup: './globalSetup.ts',
};
```

### Mocha

```ts
// test/hooks.ts
import { OAuth2Server } from 'oauth2-mock-server';

let server: OAuth2Server;

before(async () => {
  server = new OAuth2Server();
  await server.issuer.keys.generate('RS256');
  await server.start(0);
  process.env['OAUTH2_ISSUER_URL'] = server.issuer.url!;
});

after(async () => {
  await server.stop();
});
```

### Customizing tokens per test

Use `server.service.once(...)` inside individual tests to override token claims or simulate errors for that single request:

```ts
import { Events } from 'oauth2-mock-server';

test('rejects expired tokens', async () => {
  server.service.once(Events.BeforeTokenSigning, (token) => {
    token.payload.exp = Math.floor(Date.now() / 1000) - 60; // already expired
  });

  // ... call your API and assert it returns 401
});
```

---

## Non-JS projects

For Java, .NET, Python, and other non-JS projects, run the server as a standalone CLI process. Node.js must be installed on the machine running the tests, but no `package.json` or npm project is needed.

### Basic setup

```sh
# Generate a key and save it for reuse
npx oauth2-mock-server --save-jwk -p 8080
# -> Writes <kid>.json to the current directory

# On subsequent runs, load the saved key
npx oauth2-mock-server --jwk <kid>.json -p 8080
```

The server prints its issuer URL on startup:

```
OAuth 2 server listening on http://[::]:8080
OAuth 2 issuer is http://localhost:8080
```

### Configuring your app to trust the mock issuer

Point your application's OAuth2/OIDC configuration at the mock server. Examples:

**.NET (Microsoft.AspNetCore.Authentication.JwtBearer)**

```csharp
// appsettings.Test.json
{
  "Authentication": {
    "Authority": "http://localhost:8080",
    "Audience": "my-api"
  }
}
```

**Spring Boot**

```yaml
# application-test.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080
```

**Python (authlib / python-jose)**

```python
OAUTH2_ISSUER = os.environ.get("OAUTH2_ISSUER_URL", "http://localhost:8080")
OAUTH2_JWKS_URI = f"{OAUTH2_ISSUER}/jwks"
```

> **Fixed port requirement:** the server must use a known fixed port so that your application's test configuration can reference it. Unlike the JS/TS approach, dynamic port assignment is not practical here without an orchestrator script (see [CI pipeline](#ci-pipeline)).

---

## CI pipeline

Two cross-platform approaches are available. Both work on Windows, Linux, and macOS.

### Option 1: `start-server-and-test` (zero scripting)

[`start-server-and-test`](https://www.npmjs.com/package/start-server-and-test) is a small npm tool that:

1. Starts a server command as a child process
2. Polls a URL until it returns HTTP 2xx (the server is ready)
3. Runs the test command
4. Kills the server when the tests finish (pass or fail), propagating the exit code

**Setup** — add it to your project once:

```sh
npm install --save-dev start-server-and-test
```

Or use it via `npx` without installing:

```sh
npx start-server-and-test \
  "npx oauth2-mock-server --jwk my-key.json -p 8080" \
  "http://localhost:8080/.well-known/openid-configuration" \
  "dotnet test"
```

In a `package.json` script:

```json
{
  "scripts": {
    "test:with-auth": "start-server-and-test \"npx oauth2-mock-server --jwk my-key.json -p 8080\" http://localhost:8080/.well-known/openid-configuration \"dotnet test\""
  }
}
```

> **Fixed port is required.** `start-server-and-test` polls a hard-coded URL, so the port cannot be dynamic. Choose a port unlikely to conflict on shared agents, or use a port range convention your CI platform supports.

> **Key reuse.** Generate a key once with `--save-jwk`, commit the resulting `<kid>.json` file, and load it on every CI run with `--jwk`. This avoids regenerating a key on every run and keeps the `kid` stable.

---

### Option 2: Node.js orchestrator script (dynamic port)

For cases where port conflicts are a concern, or when you need to pass the actual bound port to your tests, a small Node.js script gives full control. It starts the server programmatically, reads the actual port, and passes the issuer URL to the test process via an environment variable.

```js
// scripts/run-tests.mjs
import { spawn } from 'node:child_process';
import { OAuth2Server } from 'oauth2-mock-server';

const server = new OAuth2Server();
await server.issuer.keys.generate('RS256');
await server.start(0); // 0 = OS-assigned — no port conflicts

const issuerUrl = server.issuer.url;
console.log(`OAuth2 mock server started: ${issuerUrl}`);

const [command, ...args] = process.argv.slice(2);

const child = spawn(command, args, {
  stdio: 'inherit',
  env: { ...process.env, OAUTH2_ISSUER_URL: issuerUrl },
});

const exitCode = await new Promise((resolve) => child.on('close', resolve));

await server.stop();
process.exit(exitCode ?? 1);
```

Run it from CI:

```sh
# Linux / macOS
node scripts/run-tests.mjs dotnet test

# Windows (PowerShell)
node scripts/run-tests.mjs dotnet test
```

The script is identical on all platforms. Your test code reads `OAUTH2_ISSUER_URL` from the environment:

```csharp
// .NET — read the issuer URL from the environment
var issuerUrl = Environment.GetEnvironmentVariable("OAUTH2_ISSUER_URL")
                ?? "http://localhost:8080";
```

---

### Choosing between the two options

|                    | `start-server-and-test`              | Node.js orchestrator                 |
| ------------------ | ------------------------------------ | ------------------------------------ |
| Setup effort       | One `npx` call or one dev dependency | One `.mjs` script (~25 lines)        |
| Dynamic port       | No — fixed port required             | Yes                                  |
| Cross-platform     | Yes                                  | Yes                                  |
| Issuer URL handoff | Fixed in app config                  | Via environment variable             |
| Best for           | Simple pipelines, single fixed port  | Port-conflict-sensitive environments |

---

> **Platform-specific shell scripting** (bash `&`/`$!`, PowerShell `Start-Process`) is not covered here to avoid platform-specific maintenance burden. See the [bash manual](https://www.gnu.org/software/bash/manual/) and [PowerShell docs](https://learn.microsoft.com/powershell/) for equivalent approaches.
