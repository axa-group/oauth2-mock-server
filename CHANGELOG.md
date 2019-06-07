# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

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
