import { configStore, dpopNonceSecretStore } from '../adapters/index.js';
import { validateConfiguration, type Configuration } from './configuration.js';
import { resolveNonceSecret } from './nonceSecret.js';

export const ApplicationConfig = {
	/*
	 * authorization.allowOmittingSingleRegisteredRedirectUri
	 *
	 * title: Allow omitting the redirect_uri parameter when only a single one is registered for a client.
	 *
	 * description: When enabled, an authorization request (and the authorization-code token exchange)
	 * that omits redirect_uri is resolved to the client's sole registered redirect_uri. This is a
	 * deviation from strict OAuth 2.1 (which expects redirect_uri present); it is isolated behind this
	 * named flag and defaults to disabled (secure-by-default) so omission is an explicit opt-in.
	 */
	'authorization.allowOmittingSingleRegisteredRedirectUri': false,

	/*
	 * pushedAuthorizationRequests
	 *
	 * title: [`RFC9126`](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (`PAR`)
	 *
	 * description: Enables the use of `pushed_authorization_request_endpoint` defined by the Pushed
	 * Authorization Requests RFC.
	 */
	'par.enabled': false,
	/*
	 * allowUnregisteredRedirectUris
	 *
	 * description: Allows unregistered redirect_uri values to be used by authenticated clients using PAR that do not use a `sector_identifier_uri`.
	 */
	'par.allowUnregisteredRedirectUris': false,

	/*
	 * features.dPoP
	 *
	 * title: [`RFC9449`](https://www.rfc-editor.org/rfc/rfc9449.html) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (`DPoP`)
	 *
	 * description: Enables `DPoP` - mechanism for sender-constraining tokens via a
	 * proof-of-possession mechanism on the application level.
	 */
	'dpop.enabled': false,
	/**
	 * features.dPoP.nonceSecret
	 *
	 * description: The secret every server-provided DPoP nonce is derived from. A 32-byte Buffer.
	 *
	 * Server-owned state, not an operator setting: it is deliberately absent from the admin settings
	 * catalog, and since the settings API filters submissions against that catalog, no operator can
	 * reach it. The server provisions one at startup when its store holds none (configs/nonceSecret.ts),
	 * so this is `undefined` only in the instant before that resolution runs — never while serving.
	 *
	 * An in-process bootstrap may supply one, which is the only way a value arrives from outside, and
	 * is how the test suite pins a fixed secret. A supplied value that is not 32 bytes is ignored in
	 * favour of the stored one rather than being fatal.
	 *
	 * The widening is needed because the initial value is `undefined` while the resolved value is byte
	 * material; TypeScript infers the literal's type from the initialiser alone, and there is no way to
	 * annotate one property of an object literal in place. `Uint8Array` rather than `Buffer` for the
	 * reason given on isUsableNonceSecret: a Buffer is one, and a structured clone of this object
	 * downgrades it to one.
	 */
	'dpop.nonceSecret': undefined as Uint8Array | undefined,
	/**
	 * features.dPoP.requireNonce
	 *
	 * description: Determine whether a DPoP nonce is required or not.
	 */
	'dpop.requireNonce': false,
	/**
	 * features.dPoP.allowReplay
	 *
	 * description: Controls whether DPoP Proof Replay Detection is used or not.
	 */
	'dpop.allowReplay': false,

	/*
	 * features.introspection
	 *
	 * title: [`RFC7662`](https://www.rfc-editor.org/rfc/rfc7662.html) - OAuth 2.0 Token Introspection
	 *
	 * description: Enables Token Introspection for:
	 *   - opaque access tokens
	 *   - refresh tokens
	 */
	'introspection.enabled': false,

	/*
	 * features.jwtResponseModes
	 *
	 * title: [JWT Secured Authorization Response Mode (`JARM`)](https://openid.net/specs/oauth-v2-jarm-final.html)
	 *
	 * description: Enables JWT Secured Authorization Responses
	 */
	'responseMode.jwt.enabled': false,

	/*
	 * features.fapi
	 *
	 * title: Financial-grade API Security Profile (`FAPI`)
	 *
	 * description: Enables extra Authorization Server behaviours defined in FAPI that cannot be
	 * achieved by other configuration options.
	 *
	 * '2.0' Enables behaviours from [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
	 */
	'fapi.enabled': false,

	/*
	 * features.clientCredentials
	 *
	 * title: [`RFC6749`](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3.4) - Client Credentials
	 *
	 * description: Enables `grant_type=client_credentials` to be used on the token endpoint.
	 */
	'clientCredentials.enabled': false,

	/*
	 * refreshToken
	 *
	 * description: Advertises `grant_type=refresh_token` even when the client is not
	 *   requesting the `offline_access` scope. Issuance itself is governed by the
	 *   `issueRefreshToken` addon; this flag only controls grant-type advertisement
	 *   (it replaces the former `issueRefreshToken !== default` boot-time heuristic).
	 */
	'refreshToken.enabled': false,

	/*
	 * features.backchannelLogout
	 *
	 * title: [`OIDC Back-Channel Logout 1.0`](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)
	 *
	 * description: Enables Back-Channel Logout features.
	 */
	'backchannelLogout.enabled': false,

	/*
	 * features.encryption
	 *
	 * description: Enables encryption features such as receiving encrypted UserInfo responses,
	 * encrypted ID Tokens and signing/encrypting Request Objects.
	 */
	'encryption.enabled': false,

	/*
	 * features.jwtIntrospection
	 *
	 * title: [JWT Response for OAuth Token Introspection - RFC9701](https://www.rfc-editor.org/rfc/rfc9701.html)
	 *
	 * description: Enables JWT responses for Token Introspection features. Only available in
	 * conjunction with `introspection.enabled`.
	 */
	'jwtIntrospection.enabled': false,

	/*
	 * features.jwtUserinfo
	 *
	 * description: Enables JWT responses for the UserInfo endpoint. Only available in conjunction
	 * with `userinfo.enabled`.
	 */
	'jwtUserinfo.enabled': false,

	/*
	 * features.revocation
	 *
	 * title: [`RFC7009`](https://www.rfc-editor.org/rfc/rfc7009.html) - OAuth 2.0 Token Revocation
	 *
	 * description: Enables Token Revocation.
	 */
	'revocation.enabled': false,

	/*
	 * features.userinfo
	 *
	 * description: Enables the UserInfo endpoint.
	 */
	'userinfo.enabled': true,

	/*
	 * features.rpInitiatedLogout
	 *
	 * title: [`OIDC RP-Initiated Logout 1.0`](https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html)
	 *
	 * description: Enables RP-Initiated Logout features.
	 */
	'rpInitiatedLogout.enabled': true,

	/*
	 * features.claimsParameter
	 *
	 * title: [`claims` parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
	 *
	 * description: Enables the use and validations of the `claims` parameter.
	 */
	'claimsParameter.enabled': false,

	/*
	 * features.mTLS
	 *
	 * title: [`RFC8705`](https://www.rfc-editor.org/rfc/rfc8705.html) - OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens
	 *
	 * description: Enables specific features from the Mutual TLS specification.
	 */
	'mTLS.enabled': false,
	/*
	 * features.mTLS.certificateBoundAccessTokens
	 *
	 * description: Enables Mutual TLS Client Certificate-Bound Tokens.
	 */
	'mTLS.certificateBoundAccessTokens': false,
	/*
	 * features.mTLS.selfSignedTlsClientAuth
	 *
	 * description: Enables the `self_signed_tls_client_auth` client authentication method.
	 */
	'mTLS.selfSignedTlsClientAuth': false,
	/*
	 * features.mTLS.tlsClientAuth
	 *
	 * description: Enables the `tls_client_auth` client authentication method.
	 */
	'mTLS.tlsClientAuth': false,

	/*
	 * features.deviceFlow
	 *
	 * title: [`RFC8628`](https://www.rfc-editor.org/rfc/rfc8628.html) - OAuth 2.0 Device Authorization Grant (Device Flow)
	 *
	 * description: Enables Device Authorization Grant features.
	 */
	'deviceFlow.enabled': false,
	/*
	 * features.deviceFlow.charset
	 *
	 * description: Character set for generated user codes — `base-20` or `digits`.
	 */
	'deviceFlow.charset': 'base-20',
	/*
	 * features.deviceFlow.mask
	 *
	 * description: Template for generated user codes; `*` is replaced by random chars from the charset.
	 */
	'deviceFlow.mask': '****-****',

	/*
	 * features.ciba
	 *
	 * title: [OIDC Client Initiated Backchannel Authentication Flow (`CIBA`)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)
	 *
	 * description: Enables Core `CIBA` Flow.
	 */
	'ciba.enabled': false,
	/*
	 * features.ciba.deliveryModes
	 *
	 * description: Supported token delivery modes — any of `poll`, `ping`.
	 */
	'ciba.deliveryModes': ['poll'],

	/*
	 * features.requestObjects
	 *
	 * title: [`JAR`](https://www.rfc-editor.org/rfc/rfc9101.html) - JWT Secured Authorization Request
	 *
	 * description: Enables the use and validation of the `request` (Request Object) parameter.
	 */
	'requestObjects.enabled': false,
	/*
	 * features.requestObjects.requireSignedRequestObject
	 *
	 * description: Makes signed request objects required for all authorization requests.
	 */
	'requestObjects.requireSignedRequestObject': false,

	/*
	 * features.resourceIndicators
	 *
	 * title: [`RFC8707`](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource Indicators for OAuth 2.0
	 *
	 * description: Enables Resource Indicators features.
	 */
	'resourceIndicators.enabled': true,

	/*
	 * features.richAuthorizationRequests
	 *
	 * title: [`RFC9396`](https://www.rfc-editor.org/rfc/rfc9396.html) - OAuth 2.0 Rich Authorization Requests
	 *
	 * description: Enables the use of the `authorization_details` parameter.
	 */
	'richAuthorizationRequests.enabled': false,
	/*
	 * features.richAuthorizationRequests.types
	 *
	 * description: The authorization details types this server accepts, as a map of type identifier to
	 * a serializable descriptor:
	 *
	 *   {
	 *     'https://scheme.example/payment': {
	 *       label: 'Initiate a payment',            // required — what the consent screen shows
	 *       fields: {                               // optional constraints on the RFC 9396 §2 fields
	 *         actions: { required: true, allowed: ['initiate', 'status'] },
	 *         locations: {}, datatypes: {}, privileges: {},
	 *         identifier: { required: false }       // single-valued: no `allowed`
	 *       },
	 *       allowUnknownFields: false               // default — §5 requires refusing unknown fields
	 *     }
	 *   }
	 *
	 * The identifier is opaque: §2.1 leaves it to the server and recommends a collision-resistant
	 * namespace such as a URI. Every member is JSON, so the map round-trips through storage and the
	 * admin settings API. A per-type `validate` function may still be supplied in an in-process
	 * bootstrap as an escape hatch for semantics a descriptor cannot express; it is optional, and a
	 * rejection from it surfaces as `invalid_authorization_details`. Enabling the feature with an empty
	 * map fails validation, because every request would then be refused.
	 */
	'richAuthorizationRequests.types': {},

	/*
	 * cors
	 *
	 * title: Cross-Origin Resource Sharing for browser-based clients
	 *
	 * description: Enables the CORS layer: public metadata endpoints answer any origin, and the
	 * endpoints a browser app calls directly answer origins listed on the owning project's
	 * `corsOrigins`. Defaults to enabled because closure is achieved by data — a project with no
	 * origins grants nothing, so a fresh deployment is closed with this on. It exists as an incident
	 * kill switch. There is deliberately no `cors.maxAge` companion: the preflight cache lifetime is
	 * dictated by browser behaviour, not by deployment, and would be the first numeric key here.
	 */
	'cors.enabled': true,

	/*
	 * features.registration
	 *
	 * title: [`OIDC Dynamic Client Registration 1.0`](https://openid.net/specs/openid-connect-registration-1_0-final.html) and [`RFC7591`](https://www.rfc-editor.org/rfc/rfc7591.html) - OAuth 2.0 Dynamic Client Registration Protocol
	 *
	 * description: Enables Dynamic Client Registration.
	 */
	'registration.enabled': false,
	/*
	 * features.registration.initialAccessToken
	 *
	 * description: Requires a valid initial access token for registration. `string` (static) or
	 * `boolean` (adapter-backed).
	 */
	'registration.initialAccessToken': false,
	/*
	 * features.registration.policies
	 *
	 * description: Registration/registration-management policies applied to client properties.
	 */
	'registration.policies': undefined,
	/*
	 * features.registration.issueRegistrationAccessToken
	 *
	 * description: Whether (or a function deciding whether) a registration access token is issued.
	 */
	'registration.issueRegistrationAccessToken': true,

	/*
	 * features.registrationManagement
	 *
	 * title: [`OAuth 2.0 Dynamic Client Registration Management Protocol`](https://www.rfc-editor.org/rfc/rfc7592.html)
	 *
	 * description: Enables Update and Delete features for dynamically registered clients.
	 */
	'registrationManagement.enabled': false,
	/*
	 * features.registrationManagement.rotateRegistrationAccessToken
	 *
	 * description: Enables registration access token rotation (boolean or function).
	 */
	'registrationManagement.rotateRegistrationAccessToken': true,

	/*
	 * scopes
	 *
	 * description: Array of additional scope values that the authorization server signals to support in the discovery
	 *   endpoint. Only add scopes the authorization server has a corresponding resource for.
	 *   Resource Server scopes don't belong here, see `features.resourceIndicators` for configuring
	 *   those.
	 */
	scopes: ['openid', 'offline_access'],

	/*
	 * claims
	 *
	 * description: Claims map used to derive `claims_supported` and claim-defined scopes for discovery.
	 *   `{ claimName: null }` exposes a standalone claim; `{ scopeName: ['claim', ...] }` groups claims under a scope.
	 */
	claims: {
		acr: null,
		sid: null,
		auth_time: null,
		iss: null,
		openid: ['sub']
	},

	/*
	 * acrValues
	 *
	 * description: Authentication Context Class References the server supports; surfaced as `acr_values_supported`.
	 */
	acrValues: [],

	/*
	 * conformIdTokenClaims
	 *
	 * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
	 */
	conformIdTokenClaims: true,

	/*
	 * discovery
	 *
	 * description: Pass additional properties to this object to extend the discovery document.
	 *   Relocated here as the single source for server-owned settings, but intentionally absent
	 *   from the admin settings catalog: it is not operator-editable, so it is neither returned by
	 *   nor writable through the settings API.
	 */
	discovery: {
		claim_types_supported: ['normal'],
		claims_locales_supported: undefined,
		display_values_supported: undefined,
		op_policy_uri: undefined,
		op_tos_uri: undefined,
		service_documentation: undefined,
		ui_locales_supported: undefined
	},

	/*
	 * clientAuthMethods
	 *
	 * description: Supported client authentication methods; surfaced as `token_endpoint_auth_methods_supported`.
	 *   mTLS methods are added on top when the corresponding mTLS options are enabled.
	 */
	clientAuthMethods: [
		'client_secret_basic',
		'client_secret_jwt',
		'client_secret_post',
		'private_key_jwt',
		'none'
	]
};
Object.assign(ApplicationConfig, await configStore.get());

/*
 * Resolved here, between loading the persisted settings and validating them, and the position is the
 * point. The validator below rejects "nonces required with no usable secret"; if that rule could ever
 * run before this line, it would fail a perfectly healthy boot. Two consecutive statements in one
 * module make the ordering a fact rather than a property of the import graph — which is why this is
 * not a side-effect import from event_bus.ts, the way signing keys are anchored.
 *
 * Every entry path imports this module, so nothing can serve a request before this has completed.
 */
ApplicationConfig['dpop.nonceSecret'] = await resolveNonceSecret(
	dpopNonceSecretStore,
	ApplicationConfig['dpop.nonceSecret']
);

export type ApplicationConfigType = typeof ApplicationConfig;

/*
 * configuration
 *
 * The values derived from the settings above — collections as Sets, and the results of
 * cross-referencing scopes against claims. Validated here, at the point the settings finish
 * loading, so an unrunnable configuration fails at startup and no code can observe an
 * unvalidated one. Read flat from ApplicationConfig for anything not listed here.
 *
 * Mutated in place by reloadConfiguration, never reassigned, so every module holding the imported
 * reference sees the current values — the same rule the key material follows (configs/keystore.ts).
 */
export const configuration: Configuration =
	validateConfiguration(ApplicationConfig);

/*
 * reloadConfiguration
 *
 * Re-derive after ApplicationConfig has been changed in place. The settings are boot-only in a
 * deployment — they are persisted and applied by a restart — so this exists for the tests, which
 * reconfigure the server per spec and would otherwise be reading values derived from the previous
 * spec's settings.
 */
export function reloadConfiguration(): Configuration {
	Object.assign(configuration, validateConfiguration(ApplicationConfig));
	return configuration;
}
