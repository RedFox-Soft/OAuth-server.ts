# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **BREAKING (configuration): `richAuthorizationRequests.types` is now a serializable descriptor map.**
  The former shape was `{ '<type>': { validate: fn } }`, which no admin settings entry could ever carry —
  that is precisely why the feature could not be configured by an operator. A type is now declared as data:

  ```json
  {
  	"https://scheme.example/payment": {
  		"label": "Initiate a payment",
  		"fields": { "actions": { "required": true, "allowed": ["initiate"] } },
  		"allowUnknownFields": false
  	}
  }
  ```

  `label` is required and is what the consent screen shows. Constraints may only name the RFC 9396 §2
  common fields (`actions`, `locations`, `datatypes`, `privileges`, `identifier`); `identifier` is
  single-valued so it takes `required` only. A per-type `validate` function may still be supplied in an
  in-process bootstrap as an optional escape hatch, and a rejection from it now surfaces as
  `invalid_authorization_details` rather than a server fault. **Enabling `richAuthorizationRequests` with an
  empty type map now fails validation** — at boot and through the admin settings API — because every request
  would otherwise be refused. No deployment can have been running a _working_ configuration of this key (the
  feature had no working configuration at all), but one may have been booting, so this is called out as
  breaking. The map is editable at the super-admin settings page as the catalog's first structured setting,
  and the per-client `authorizationDetailsTypes` field is now settable through the admin client API and form.

  Also in this change: `authorization_details` works end to end on the authorization-code and refresh-token
  flows — displayed at consent, recorded on the grant, returned in the token response, present as a
  top-level JWT claim, and returned by introspection. The four shaping hooks have working defaults, so the
  feature no longer requires code overrides. The device-authorization, CIBA, and token-request channels
  continue to refuse the parameter, as a recorded deviation from §3 and §6.

- **BREAKING (behavior): `allowOmittingSingleRegisteredRedirectUri` relocated and now defaults to disabled.**
  The setting moved from the provider configuration into the central Application Configuration under the key
  `authorization.allowOmittingSingleRegisteredRedirectUri`, and its default changed from enabled to **disabled**
  (secure-by-default). After upgrading, an authorization request or authorization-code token exchange that omits
  `redirect_uri` for a client with a single registered redirect_uri is **rejected** unless an operator explicitly
  enables the setting via the super-admin settings page (or the persisted configuration). It is surfaced in the
  admin settings catalog under the "Authorization" group. To retain the previous behavior, enable
  `authorization.allowOmittingSingleRegisteredRedirectUri` and restart the server.
