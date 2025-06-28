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
	 * description: Function used to determine whether a DPoP nonce is required or not.
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
	'responseMode.jwt.enabled': false
};

export type ApplicationConfigType = typeof ApplicationConfig;
