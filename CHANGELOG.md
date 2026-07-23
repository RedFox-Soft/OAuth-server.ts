# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **BREAKING (behavior): `allowOmittingSingleRegisteredRedirectUri` relocated and now defaults to disabled.**
  The setting moved from the provider configuration into the central Application Configuration under the key
  `authorization.allowOmittingSingleRegisteredRedirectUri`, and its default changed from enabled to **disabled**
  (secure-by-default). After upgrading, an authorization request or authorization-code token exchange that omits
  `redirect_uri` for a client with a single registered redirect_uri is **rejected** unless an operator explicitly
  enables the setting via the super-admin settings page (or the persisted configuration). It is surfaced in the
  admin settings catalog under the "Authorization" group. To retain the previous behavior, enable
  `authorization.allowOmittingSingleRegisteredRedirectUri` and restart the server.
