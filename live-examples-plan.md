# Plan: Live runnable code examples

## TL;DR

Add a top-level `examples/` directory with 4 self-contained TypeScript scripts demonstrating the library's core use cases. Each is run directly with `tsx`, imports via a `'oauth2-mock-server'` path alias → `./src/index.ts`, self-verifies by throwing on failure, and runs as a separate `npm run examples` CI step.

## Phase 1 — Infrastructure

1. Add `tsx` as devDependency
2. Create `examples/tsconfig.json` — extends root tsconfig; adds `paths: { "oauth2-mock-server": ["../src/index.ts"] }`; `include` covers both `../src` and `.`
3. Update `tsconfig.eslint.json` — add `"examples/"` to `include`; add `"paths": { "oauth2-mock-server": ["./src/index.ts"] }` to `compilerOptions`
4. Update `eslint.config.js` — add `examples/**/*.ts` override: `jsdoc/require-jsdoc: off`, relax `no-non-null-assertion`, `no-console: off`
5. Add `"examples"` script to `package.json` — runs each file sequentially with `tsx`
6. Add CI step to `.github/workflows/main.yml` — `npm run examples` after "Lint and run tests"

## Phase 2 — Example files

All follow: copyright header · block comment · `run()` async function · `run().catch(...)` IIFE · inline assertions · `console.log` progress.

7. `examples/quickstart.ts` — create OAuth2Server, generate RS256 key, start on random port, call `buildToken()`, verify non-empty string, stop
8. `examples/client-credentials.ts` — start server, POST /token with `grant_type=client_credentials` via Node `fetch`, assert `access_token` present
9. `examples/custom-claims.ts` — register `beforeTokenSigning` that injects `{ custom_claim: 'hello' }`, POST /token, base64-decode JWT payload, assert claim present
10. `examples/pkce.ts` — generate PKCE verifier+challenge, GET /authorize with `redirect: 'manual'` to capture Location header, extract code, POST /token with `code_verifier`, assert `access_token` present

## Phase 3 — Documentation

11. Update `README.md` — add "Examples" section (after "Quickstart") listing the 4 examples with `npx tsx examples/<name>.ts` run commands and file links
12. Update `AGENTS.md`:
    - Module map: add `examples/` row describing the conventions (copyright header, `run()` pattern, package alias import, no Vitest dependency)
    - "Mandatory checks" section: change intro from "three steps" → "four steps"; insert new **step 3 — Examples** (`npm run examples`, must exit 0); renumber old step 3 Documentation → step 4; add a third bullet to the Documentation step: **`examples/`** — consider whether the change introduces a use case not already covered; add a new example when it demonstrates a meaningfully different way to use the library (new grant type, new hook, CLI workflow); if no new example is needed, confirm that explicitly

## Relevant files

- `package.json` — add `tsx` devDep, add `"examples"` script
- `tsconfig.eslint.json` — add `"examples/"` to include, add paths
- `eslint.config.js` — add `examples/**/*.ts` override (use `test/**/*.ts` block as template)
- `.github/workflows/main.yml` — add step after test step
- `examples/tsconfig.json` — new
- `examples/quickstart.ts` — new
- `examples/client-credentials.ts` — new
- `examples/custom-claims.ts` — new
- `examples/pkce.ts` — new
- `README.md` — add section
- `AGENTS.md` — update

## Decisions

- Node built-in `fetch` (Node 20+, no new deps)
- Examples excluded from Vitest coverage
- `examples/` NOT added to `files` in package.json (not shipped in tarball)
- `tsx` devDependency only

## Open questions

1. README linking: local file paths vs GitHub URLs (for npm rendering)?
2. CLI example as 5th file? `cli()` is exported from `src/cli.ts` but not public API.
