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
	'fapi.enabled': false
};
Object.assign(ApplicationConfig, await configStore.get());

export type ApplicationConfigType = typeof ApplicationConfig;
