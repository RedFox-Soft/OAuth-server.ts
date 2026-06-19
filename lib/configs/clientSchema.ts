import { Type as t, type Static } from '@sinclair/typebox';

export const vsCHAR = /[\x20-\x7E]/;

export const ClientSchema = t.Object({
	/*
	 * clientId
	 *
	 * description: The client identifier.
	 */
	clientId: t.String({ pattern: vsCHAR.source }),
	/*
	 * clientSecret
	 *
	 * description: The client secret. The client MAY omit the parameter if the
	 * client is public.
	 */
	clientSecret: t.Optional(t.String({ pattern: vsCHAR.source })),
	/*
	 * redirectUris
	 *
	 * description: The list of allowed redirect URIs for the client.
	 */
	redirectUris: t.Array(t.String({ format: 'uri' })),
	/*
	 * applicationType
	 *
	 * description: The type of application the client is using.
	 */
	applicationType: t.Union([t.Literal('web'), t.Literal('native')]),
	/*
	 * responseTypes
	 *
	 * description: The list of response types supported by the client.
	 */
	responseTypes: t.Array(t.Union([t.Literal('code'), t.Literal('none')])),
	/*
	 * responseModes
	 *
	 * description: The list of response modes supported by the client.
	 */
	responseModes: t.Optional(
		t.Array(
			t.Union([
				t.Literal('query'),
				t.Literal('form_post'),
				t.Literal('jwt'),
				t.Literal('jwt.query'),
				t.Literal('jwt.form_post')
			])
		)
	),
	/*
	 * grantTypes
	 *
	 * description: The list of grant types supported by the client.
	 */
	grantTypes: t.Array(
		t.Union([
			t.Literal('authorization_code'),
			t.Literal('refresh_token'),
			t.Literal('client_credentials'),
			t.Literal('urn:ietf:params:oauth:grant-type:device_code'),
			t.Literal('urn:openid:params:grant-type:ciba'),
			t.String()
		])
	),
	/*
	 * subjectType
	 *
	 * description: The subject type requested for responses to this client.
	 */
	subjectType: t.Union([t.Literal('pairwise'), t.Literal('public')]),
	/*
	 * requirePushedAuthorizationRequests
	 *
	 * description: Makes the use of `PAR` required for authorization
	 * request as an authorization server policy.
	 */
	'authorization.requirePushedAuthorizationRequests': t.Boolean(),
	/*
	 * requestObject.require
	 *
	 * description: Makes the use of request objects required for authorization
	 */
	'requestObject.require': t.Boolean(),
	/*
	 * requestObject.signingAlg
	 *
	 * description: The default signing algorithm for request objects.
	 * If not set, the server will use the algorihm from JWT Token.
	 */
	'requestObject.signingAlg': t.Optional(t.String()),
	/*
	 * requestObject.backChannelSigningAlg
	 *
	 * description: The default signing algorithm for request objects
	 * when using backchannel authentication.
	 */
	'requestObject.backChannelSigningAlg': t.Optional(t.String()),
	/*
	 * consent.require
	 *
	 * description: Makes end-user consent required for this client.
	 */
	'consent.require': t.Boolean(),

	/*
	 * The remaining members describe the full shape of a *validated* client
	 * object: the schema engine (lib/models/client/schema.ts) projects the
	 * recognised snake_case metadata onto these camelCased properties. They are
	 * all optional and feature-gated at runtime; they are declared here so
	 * `ClientSchemaType` types the object the client model operates on. Runtime
	 * validation/picking is unaffected (validateClient freezes the picked keys).
	 */

	// clientSecretExpiresAt: epoch seconds at which the secret expires (0 = never).
	clientSecretExpiresAt: t.Optional(t.Number()),
	// tokenEndpointAuthMethod: the registered client authentication method.
	tokenEndpointAuthMethod: t.Optional(t.String()),
	// tokenEndpointAuthSigningAlg: signing alg for *_jwt client authentication.
	tokenEndpointAuthSigningAlg: t.Optional(t.String()),
	// jwks: inline JSON Web Key Set (left permissive — the schema engine performs
	// the structural JWKS validation; this only contributes the type).
	jwks: t.Optional(t.Any()),
	// jwksUri: remote JSON Web Key Set location.
	jwksUri: t.Optional(t.String()),
	// sectorIdentifierUri: pairwise sector identifier document location.
	sectorIdentifierUri: t.Optional(t.String()),
	// postLogoutRedirectUris: allowed RP-initiated logout redirect targets.
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	// backchannelLogoutUri: back-channel logout notification endpoint.
	backchannelLogoutUri: t.Optional(t.String()),
	// backchannelLogoutSessionRequired: include sid in the logout token.
	backchannelLogoutSessionRequired: t.Optional(t.Boolean()),
	// backchannelTokenDeliveryMode: CIBA delivery mode (poll/ping/push).
	backchannelTokenDeliveryMode: t.Optional(t.String()),
	// backchannelClientNotificationEndpoint: CIBA ping/push notification endpoint.
	backchannelClientNotificationEndpoint: t.Optional(t.String()),
	// backchannelAuthenticationRequestSigningAlg: CIBA request signing alg.
	backchannelAuthenticationRequestSigningAlg: t.Optional(t.String()),
	// idTokenSignedResponseAlg / *Encrypted*: ID Token JWT signing/encryption.
	idTokenSignedResponseAlg: t.Optional(t.String()),
	idTokenEncryptedResponseAlg: t.Optional(t.String()),
	idTokenEncryptedResponseEnc: t.Optional(t.String()),
	// userinfoSignedResponseAlg / *Encrypted*: UserInfo JWT signing/encryption.
	userinfoSignedResponseAlg: t.Optional(t.String()),
	userinfoEncryptedResponseAlg: t.Optional(t.String()),
	userinfoEncryptedResponseEnc: t.Optional(t.String()),
	// introspectionSignedResponseAlg / *Encrypted*: introspection JWT signing/encryption.
	introspectionSignedResponseAlg: t.Optional(t.String()),
	introspectionEncryptedResponseAlg: t.Optional(t.String()),
	introspectionEncryptedResponseEnc: t.Optional(t.String()),
	// authorizationSignedResponseAlg / *Encrypted*: JARM signing/encryption.
	authorizationSignedResponseAlg: t.Optional(t.String()),
	authorizationEncryptedResponseAlg: t.Optional(t.String()),
	authorizationEncryptedResponseEnc: t.Optional(t.String()),
	// requestObjectSigningAlg / *Encryption*: request object JWT signing/encryption.
	requestObjectSigningAlg: t.Optional(t.String()),
	requestObjectEncryptionAlg: t.Optional(t.String()),
	requestObjectEncryptionEnc: t.Optional(t.String()),
	// requireSignedRequestObject: require signed request objects from this client.
	requireSignedRequestObject: t.Optional(t.Boolean()),
	// dpopBoundAccessTokens: require DPoP-bound access tokens.
	dpopBoundAccessTokens: t.Optional(t.Boolean()),
	// tlsClientCertificateBoundAccessTokens: require mTLS certificate-bound tokens.
	tlsClientCertificateBoundAccessTokens: t.Optional(t.Boolean()),
	// tlsClientAuth* : mTLS subject value the client certificate must match.
	tlsClientAuthSubjectDn: t.Optional(t.String()),
	tlsClientAuthSanDns: t.Optional(t.String()),
	tlsClientAuthSanUri: t.Optional(t.String()),
	tlsClientAuthSanIp: t.Optional(t.String()),
	tlsClientAuthSanEmail: t.Optional(t.String()),
	// useMtlsEndpointAliases: advertise/use the mTLS endpoint aliases.
	useMtlsEndpointAliases: t.Optional(t.Boolean()),
	// defaultMaxAge: default max authentication age in seconds.
	defaultMaxAge: t.Optional(t.Number()),
	// scope: space-delimited scope whitelist for the client.
	scope: t.Optional(t.String()),
	// authorizationDetailsTypes: allowed RAR authorization_details types.
	authorizationDetailsTypes: t.Optional(t.Array(t.String()))
});

export type ClientSchemaType = Static<typeof ClientSchema>;
