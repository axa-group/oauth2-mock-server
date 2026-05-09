# oauth2-mock-server — Market Usage Research

> Updated 2026-05-09 via `gh api --paginate "search/code?q=oauth2-mock-server+NOT+is:fork&per_page=30"` (384 results across 13 pages; GitHub API cap is 1,000 — no truncation).

## Step 1 Results — Library Usage by File

| Repo                                    |  Stars | File                                                                              | Usage                                                                                                  |
| --------------------------------------- | -----: | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| better-auth/better-auth | 28,200 | `packages/sso/src/oidc.test.ts` | imports `OAuth2Server`, Vitest SSO OIDC test |
| better-auth/better-auth | 28,200 | `packages/sso/src/saml.test.ts` | dynamic import of `OAuth2Server`, generates RS256 key |
| better-auth/better-auth | 28,200 | `packages/better-auth/src/social.test.ts` | imports `OAuth2Server`, Vitest social auth test |
| better-auth/better-auth | 28,200 | `packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts` | imports `OAuth2Server`, Vitest generic OAuth plugin test |
| blitz-js/blitz | 14,132 | `apps/toolkit-app-passportjs/src/pages/api/auth/[...auth].ts` | Passport.js auth API route referencing oauth2-mock-server |
| grafana/pyroscope | 11,400 | `og/scripts/oauth-mock/oauth-mock.js` (commit 7e69171, no longer on main) | programmatic server setup script — pre-found |
| mcp-use/mcp-use | 9,910 | `libraries/typescript/packages/inspector/tests/e2e/fixtures/oauth-mock-server.ts` | fixture file creating mock OAuth servers for multiple providers |
| mcp-use/mcp-use | 9,910 | `libraries/typescript/packages/inspector/tests/e2e/auth-flows.test.ts` | Playwright E2E test referencing oauth2-mock-server integration |
| gtsteffaniak/filebrowser | 6,992 | `_docker/src/oidc/frontend/mock-oidc-server.js` | CJS script starting mock OIDC server for frontend E2E tests |
| gtsteffaniak/filebrowser | 6,992 | `_docker/Dockerfile.playwright-base` | Dockerfile installing oauth2-mock-server for Playwright base image |
| trailbaseio/trailbase | ~5,000 | `crates/assets/js/client/tests/integration/auth_integration.test.ts` | imports `OAuth2Server`, Vitest integration test |
| thunderbird/thunderbolt | 4,529 | `e2e/global-setup.ts` | imports `OAuth2Server`, starts OIDC server for Playwright E2E |
| thunderbird/thunderbolt | 4,529 | `e2e/global-teardown.ts` | imports `OAuth2Server` type, tears down server |
| thunderbird/thunderbolt | 4,529 | `backend/src/auth/oidc-integration.test.ts` | imports `OAuth2Server`, Bun integration test |
| thunderbird/thunderbolt | 4,529 | `docs/development/testing.md` | documentation reference |
| thunderbird/thunderbolt | 4,529 | `backend/docs/oidc-local-dev.md` | documentation reference |
| garden-co/classic-jazz | ~2,500 | `packages/jazz-tools/src/better-auth/auth/tests/server.test.ts` | imports `OAuth2Server`, Vitest server test |
| tiddly-gittly/TidGi-Desktop | ~2,000 | `features/supports/mockOAuthServer.ts` | programmatic mock OAuth server support file |
| tiddly-gittly/TidGi-Desktop | ~2,000 | `src/constants/oauthConfig.ts` | config referencing oauth2-mock-server endpoints (port 8888) |
| tiddly-gittly/TidGi-Desktop | ~2,000 | `features/oauthLogin.feature` | Cucumber/BDD feature file referencing oauth2-mock-server behavior |
| namecheap/ilc | 770 | `registry/lde/oauth-server.ts` | imports `OAuth2Server`, generates RS256 key, starts server |
| liblaber/ai | 340 | — | ⚠ No usage file found — see verification table below |
| payload-auth/payload-auth | 307 | — | ⚠ No usage file found — see verification table below |
| apache/incubator-kie-tools | 289 | `packages/runtime-tools-management-console-webapp/package.json` | CLI usage only: `pnpm exec oauth2-mock-server -p …` in `start:idp-mock` script |
| mitre/heimdall2 | 249 | `test/support/server/oidc-server.js` | CJS `require('oauth2-mock-server')`, generates RS256 key, starts server |
| CaoMeiYouRen/caomei-auth | 215 | — | ⚠ No usage file found — see verification table below |
| neondatabase/neonctl | 109 | `src/test_utils/oauth_server.ts` | imports `OAuth2Server`, helper to start server on random port |
| neondatabase/neonctl | 109 | `src/commands/auth.test.ts` | imports `OAuth2Server` and `startOauthServer`, Vitest auth command test |
| pikkujs/pikku | 56 | `verifiers/secrets/src/credentials.ts` | comment referencing mock server on localhost:8080 |
| pikkujs/pikku | 56 | `packages/addon/pikku-console/src/tests/test-oauth.ts` | imports `OAuth2Server`, standalone test script |
| pikkujs/pikku | 56 | `packages/addon/pikku-console/src/tests/test-oauth2-client.ts` | imports `OAuth2Server`, tests full OAuth2 flow end-to-end |
| noxify/turbo-lucia-starter | 44 | `apps/mock-server/src/server.ts` | imports `OAuth2Server`, generates RS256 key, starts server |
| noxify/turbo-lucia-starter | 44 | `README.md` | documentation reference |
| canton-network/wallet-gateway | 34 | `mock-oauth2/src/index.ts` | imports `OAuth2Server`, programmatic mock OAuth2 server |
| JalinZhang/Security_Scan | 22 | `heimdall2-master/test/support/server/oidc-server.js` | CJS `require('oauth2-mock-server')`, vendored copy of heimdall2 test |
| nearform/fastify-jwt-jwks | 16 | `test-integration/oauth2-mocked-server.integration.test.js` | CJS `require('oauth2-mock-server')`, node:test integration test |
| digital-asset/decentralized-canton-sync | 16 | — | ⚠ Search tool error — see verification table below |
| PREreview/prereview.org | 14 | `integration/base.ts` | imports `OAuth2Server` and `MutableRedirectUri`, integration test base |
| PREreview/prereview.org | 14 | `integration/log-in.spec.ts` | imports `MutableRedirectUri` type, login integration spec |
| PREreview/prereview.org | 14 | `integration/publishing-a-prereview.spec.ts` | imports `MutableRedirectUri` type, publishing integration spec |
| mcp-use/inspector | 13 | — | ⚠ Dependency in `package.json` only; no code usage files found |
| jirutka/nginx-oidc-njs | 12 | `integration-tests/support/oauth-server.ts` | imports types from `oauth2-mock-server`, OAuth support helper |
| otto-etl/otto | 10 | — | ⚠ Dependency in `server/package.json` only; no code usage files found — see verification table below |
| ayarse/mock-efaas-server | 9 | `src/config.ts` | imports `OAuth2Server`, mock eFaaS OIDC server config |
| ayarse/mock-efaas-server | 9 | `src/index.ts` | imports `OAuth2Server`, starts mock eFaaS OAuth server |
| ayarse/mock-efaas-server | 9 | `src/oidc/utils.ts` | OIDC utility helpers for mock eFaaS server |
| atagon-GmbH/oAuth-mock | 8 | `index.js` | CJS `require('oauth2-mock-server')`, standalone OAuth mock wrapper |
| indice-co/Indice.Angular | 6 | `mock-server.js` | CJS `require('oauth2-mock-server')`, standalone mock server script |
| data-fair/simple-directory | 5 | `dev/mock-oidc-server.ts` | imports `OAuth2Server`, development mock OIDC server with custom endpoints |
| data-fair/simple-directory | 5 | `tests/features/oidc-ldap.inproc.spec.ts` | imports `OAuth2Server`, Playwright OIDC+LDAP integration spec |
| govuk-one-login/performance-testing | 5 | `koa-stub/src/tests/app.test.js` | CJS `require('oauth2-mock-server')`, Jest test |
| govuk-one-login/performance-testing | 5 | `koa-stub/README.md` | CLI usage: `npx oauth2-mock-server` |
| kubesmarts/kie-tools | 5 | — | ⚠ Search returned empty — see verification table below |
| mitmh2025/hunt2025 | 4 | `site/lib/auth.ts` | references oauth2-mock-server in auth utility |
| mitmh2025/hunt2025 | 4 | `site/rspack.config.mjs` | references oauth2-mock-server in bundler config |
| bcgov/psa-job-store | 4 | — | ⚠ Dependency in `apps/app/package.json` only; no code usage files found — see verification table below |
| ministryofjustice/hmpps-dpr-tools-ui | 3 | `oauth2-mock-server/` (directory) | Vendored full copy of the library source tree; custom `start:oauth` script |
| dnitsch/reststrategy | 3 | `seeder/hack/oauth2-mock.Dockerfile` | Dockerfile launching oauth2-mock-server CLI for integration seeder |
| dnitsch/reststrategy | 3 | `docs/demo.md` | documentation reference |
| abinnovision/github-workflow-dispatch-proxy | 2 | `scripts/oauth2-server.mjs` | ESM script starting oauth2-mock-server for proxy tests |
| abinnovision/github-workflow-dispatch-proxy | 2 | `test/utils/setup-oauth-server.ts` | imports `OAuth2Server`, test setup utility |
| bcgov/common-notify | 2 | `.devcontainer/docker-compose.yml` | Docker Compose service running oauth2-mock-server CLI |
| Ecasept/simplelogic | 2 | `playwright/oauth/mock_server.ts` | imports `OAuth2Server`, Playwright OAuth mock server fixture |
| phellowseven/phellow-community | 2 | `samples/oidc-mock-server/server.mjs` | ESM sample server using oauth2-mock-server |
| advanced-rest-client/authorization | 1 | `web-dev-server.config.mjs` | dev server config referencing oauth2-mock-server |
| jdutton/mcp-typescript-simple | 1 | `packages/testing/src/mock-oauth-server.ts` | imports `OAuth2Server`, reusable mock OAuth server for MCP tests |
| jdutton/mcp-typescript-simple | 1 | `packages/create-mcp-typescript-simple/src/utils/dependencies.ts` | dependency scaffolding including oauth2-mock-server |
| LuxChanLu/yet-another-nuxt-oauth2 | 1 | `cypress/fixtures/nuxt/nuxt.config.js` | Cypress fixture Nuxt config referencing oauth2-mock-server |
| navikt/su-se-framover | 1 | `server/auth/utils.ts` | TypeScript auth utilities referencing oauth2-mock-server |
| radyak/chronos | 1 | `chronos-dev-auth/mock.js` | CJS mock auth script using oauth2-mock-server |
| RJK134/herm-platform | 1 | `server/src/api/sso/oidc.ts` | imports `OAuth2Server`, SSO OIDC server implementation |
| colorfulcompany/node-indeed-job-campaign-api-client | 0 | `test/support/oauth2-mock-server-controller.js` | CJS controller wrapping oauth2-mock-server for API client tests |
| corntoole/oauth2-mock-server-docker | 0 | `docker-compose.yml` | Docker Compose running oauth2-mock-server via CLI |
| davidvanlaatum/dvnetman | 0 | — | ⚠ Search returned empty — see verification table below |
| DEFRA/trade-imports-reference-data | 0 | `src/test/java/uk/gov/defra/trade/imports/integration/OAuthMockServerContainer.java` | Java Testcontainers wrapper launching oauth2-mock-server as a container |
| DEFRA/trade-imports-stub | 0 | `src/test/java/uk/gov/defra/trade/imports/integration/OAuthMockServerContainer.java` | Java Testcontainers wrapper launching oauth2-mock-server as a container |
| gjovanov/roomler-ai | 0 | `ui/playwright.config.cjs` | Playwright config referencing oauth2-mock-server |
| j0zsef/energy-broker | 0 | `apps/mock-green-button-server/src/main.ts` | imports `OAuth2Server`, mock Green Button OAuth server entry point |
| j0zsef/energy-broker | 0 | `apps/mock-green-button-server/src/mock-oauth/mock-oauth.ts` | OAuth mock implementation for energy broker |
| jeremy-boschen/knurl | 0 | `src-common/e2e/support/mock-endpoint-server.mjs` | ESM E2E mock endpoint server using oauth2-mock-server |
| jimdavies72/orderbook-api | 0 | `src/utils/test-utils/mockAuthServer/mockAuth.js` | CJS mock auth server utility for orderbook API tests |
| meesvandongen/react-router-auth | 0 | `apps/mock-idp/mock-idp.ts` | imports `OAuth2Server`, mock IdP for react-router auth tests |
| murillio4/kong-openidc | 0 | `.pongo/oidc-mock/index.js` | CJS OIDC mock for Kong OpenIDC pongo tests |
| NaturalHistoryMuseum/phthiraptera-transcription | 0 | `dev/oauth-server.js` | CJS development OAuth server script |
| petersmith-hun/leaflet-static-resource-server | 0 | `acceptance/support/auth-manager.ts` | TypeScript auth manager for acceptance tests |
| RIVM-bioinformatics/gen-epix-ui-tools | 0 | `packages/oidc-mock-server/src/oidc-mock-server.ts` | imports `OAuth2Server`, dedicated OIDC mock server package |
| Salamahin/chai-s-romashkoi | 0 | `integration_tests/start-mock-server.mjs` | ESM script starting oauth2-mock-server for integration tests |
| wemogy/oauth2-mock | 0 | `src/index.ts` | imports `OAuth2Server`, thin wrapper around oauth2-mock-server |
| WhiteLighterIO/turbo-blitz | 0 | `packages/oauth-mock/src/server.ts` | imports `OAuth2Server`, Turborepo OAuth mock package |
| wxmohd/Mock-Oauth | 0 | `oauth-server.js` | CJS standalone OAuth mock server |

---

## Manual Verification — Repos With No Code Usage Found

These repos returned 0 results or a search error. Links open GitHub's code search scoped to each repo.

| Repo                                    | Stars | Reason                                       | GitHub Search Link                                                                                                  | Repo Link                                                          |
| --------------------------------------- | ----: | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| liblaber/ai                             |   340 | Search returned empty                        | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Aliblaber%2Fai&type=code)                             | [Repo](https://github.com/liblaber/ai)                             |
| payload-auth/payload-auth               |   307 | Search returned empty                        | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Apayload-auth%2Fpayload-auth&type=code)               | [Repo](https://github.com/payload-auth/payload-auth)               |
| CaoMeiYouRen/caomei-auth                |   215 | Search returned empty                        | [Search](https://github.com/search?q=oauth2-mock-server+repo%3ACaoMeiYouRen%2Fcaomei-auth&type=code)                | [Repo](https://github.com/CaoMeiYouRen/caomei-auth)                |
| digital-asset/decentralized-canton-sync |    16 | Persistent search tool error                 | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Adigital-asset%2Fdecentralized-canton-sync&type=code) | [Repo](https://github.com/digital-asset/decentralized-canton-sync) |
| otto-etl/otto                           |    10 | In devDependencies only; no usage code found | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Aotto-etl%2Fotto&type=code)                           | [Repo](https://github.com/otto-etl/otto)                           |
| kubesmarts/kie-tools                    |     5 | Search returned empty                        | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Akubesmarts%2Fkie-tools&type=code)                    | [Repo](https://github.com/kubesmarts/kie-tools)                    |
| bcgov/psa-job-store                     |     4 | In devDependencies only; no usage code found | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Abcgov%2Fpsa-job-store&type=code)                     | [Repo](https://github.com/bcgov/psa-job-store)                     |
| davidvanlaatum/dvnetman                 |     0 | Search returned empty                        | [Search](https://github.com/search?q=oauth2-mock-server+repo%3Adavidvanlaatum%2Fdvnetman&type=code)                 | [Repo](https://github.com/davidvanlaatum/dvnetman)                 |
