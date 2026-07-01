import { configStore } from '../adapters/index.js';

export const ApplicationConfig = {
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
	 * description: A secret value used for generating server-provided DPoP nonces.
	 * Must be a 32-byte length Buffer instance when provided.
	 */
	'dpop.nonceSecret': undefined,
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
	 * features.devInteractions
	 *
	 * description: Development-ONLY out-of-the-box interaction views. Disable and replace with your
	 * own frontend/authentication flows before production.
	 */
	'devInteractions.enabled': true,

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
	 * features.richAuthorizationRequests.ack
	 *
	 * description: Acknowledges the implemented draft/experiment version.
	 */
	'richAuthorizationRequests.ack': undefined,
	/*
	 * features.richAuthorizationRequests.types
	 *
	 * description: Supported authorization details type identifiers and their validators.
	 */
	'richAuthorizationRequests.types': {},

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

export type ApplicationConfigType = typeof ApplicationConfig;
