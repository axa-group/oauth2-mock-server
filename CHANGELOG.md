# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

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
