# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [4.0.0](https://github.com/axa-group/oauth2-mock-server/compare/v3.2.0...v4.0.0) — 2021-08-TODO

### Added

- Add `/endsession` endpoint (thanks [AndTem](https://github.com/AndTem)!)
- Support `EdDSA` algorithm

### Removed

- **Breaking:** Drop support for Node.js 10
- No longer accepts PEM encoded keys
- No longer supports generating unsigned JWTs

### Changed

- **Breaking:** Reworked exposed API. Please refer to the [migration guide](./MIGRATION.md) for more information.
- Add support for Node.js 16

## [3.2.0](https://github.com/axa-group/oauth2-mock-server/compare/v3.1.0...v3.2.0) — 2021-08-03

### Added

- Add `subject_types_supported` OpenID Provider Metadata field (thanks [jjbooth74](https://github.com/jjbooth74)!)

## [3.1.0](https://github.com/axa-group/oauth2-mock-server/compare/v3.0.3...v3.1.0) — 2020-11-30

### Added

- Add authorize redirect event (thanks [markwallsgrove](https://github.com/markwallsgrove)!)

## [3.0.3](https://github.com/axa-group/oauth2-mock-server/compare/v3.0.2...v3.0.3) — 2020-11-12

### Fixed

- Fix regression: When adding a key to the KeyStore, do not normalize key "use" value to "sig" when already defined

## [3.0.2](https://github.com/axa-group/oauth2-mock-server/compare/v3.0.1...v3.0.2) — 2020-10-29

### Added

- Support Nodejs 14.15 LTS

## [3.0.1](https://github.com/axa-group/oauth2-mock-server/compare/v3.0.0...v3.0.1) — 2020-10-23

### Fixed

- Include missing files on pack/publish

## [3.0.0](https://github.com/axa-group/oauth2-mock-server/compare/v2.0.0...v3.0.0) — 2020-10-22

### Added

- TypeScript type definitions ([#48](https://github.com/axa-group/oauth2-mock-server/pull/48))

### Changed

- Straightened definitions of optional parameters: `null` is no longer considered as a non valued parameter value; `undefined` bears that meaning.

## [2.0.0](https://github.com/axa-group/oauth2-mock-server/compare/v1.5.1...v2.0.0) — 2020-10-01

### Added

- Honor OpenID Connect `nonce` ([#34](https://github.com/axa-group/oauth2-mock-server/pull/34) by [@HASHIMOTO-Takafumi](https://github.com/HASHIMOTO-Takafumi))

### Removed

- No longer support Node 8

## [1.5.1](https://github.com/axa-group/oauth2-mock-server/compare/v1.5.0...v1.5.1) — 2020-04-06

### Security

- Update `npm` dependencies to fix:
  - [CVE-2020-7598](https://github.com/advisories/GHSA-vh95-rmgr-6w4m)

## [1.5.0](https://github.com/axa-group/oauth2-mock-server/compare/v1.4.0...v1.5.0) — 2020-01-23

### Added

- Add HTTP request object to `OAuth2Service`'s events
- Add `beforeTokenSigning` event to `OAuth2Service`

## [1.4.0](https://github.com/axa-group/oauth2-mock-server/compare/v1.3.3...v1.4.0) — 2020-01-15

### Security

- Update `npm` dependencies to fix:
  - [NPM Security Advisory 1164](https://www.npmjs.com/advisories/1164)
  - [NPM Security Advisory 1300](https://www.npmjs.com/advisories/1300)
  - [NPM Security Advisory 1316](https://www.npmjs.com/advisories/1316)
  - [NPM Security Advisory 1324](https://www.npmjs.com/advisories/1324)
  - [NPM Security Advisory 1325](https://www.npmjs.com/advisories/1325)

### Fixed

- Add missing `aud` claim under Authorization Code Flow

### Added

- Add CORS support

## [1.3.3](https://github.com/axa-group/oauth2-mock-server/compare/v1.3.2...v1.3.3) — 2019-09-25

### Security

- Update `npm` dependencies to fix:
  - [CVE-2019-15657](https://nvd.nist.gov/vuln/detail/CVE-2019-15657)
  - [CVE-2019-10746](https://nvd.nist.gov/vuln/detail/CVE-2019-10746)
  - [CVE-2019-10747](https://nvd.nist.gov/vuln/detail/CVE-2019-10747)

### Changed

- Update license's legal entity.

## [1.3.2](https://github.com/axa-group/oauth2-mock-server/compare/v1.3.1...v1.3.2) — 2019-08-09

### Security

- Update `npm` dependencies to fix:
  - [CVE-2019-10744](https://github.com/lodash/lodash/pull/4336)

## [1.3.1](https://github.com/axa-group/oauth2-mock-server/compare/v1.3.0...v1.3.1) — 2019-06-07

### Security

- Update `npm` dependencies to fix:
  - [WS-2019-0032](https://github.com/nodeca/js-yaml/issues/475)
  - [WS-2019-0063](https://github.com/nodeca/js-yaml/pull/480)
  - [WS-2019-0064](https://github.com/wycats/handlebars.js/compare/v4.1.1...v4.1.2)

## [1.3.0](https://github.com/axa-group/oauth2-mock-server/compare/v1.2.0...v1.3.0) — 2019-06-03

### Added

- Add revocation endpoint

## [1.2.0](https://github.com/axa-group/oauth2-mock-server/compare/v1.1.0...v1.2.0) — 2019-03-19

### Added

- Add Authorization code grant
- Add Refresh token grant
- Add Userinfo endpoint

### Security

- Update `npm` dependencies to fix [CVE-2018-16469](https://nvd.nist.gov/vuln/detail/CVE-2018-16469)

## [1.1.0](https://github.com/axa-group/oauth2-mock-server/compare/v1.0.0...v1.1.0) — 2018-08-02

### Added

- Add Resource Owner Password Credentials grant

### Fixed

- Add missing cache control headers on `/token` responses

## 1.0.0 — 2018-08-01

Initial release.
