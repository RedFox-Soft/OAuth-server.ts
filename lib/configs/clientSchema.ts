import { Type as t, FormatRegistry, type Static } from '@sinclair/typebox';
import * as validUrl from '../helpers/valid_url.ts';
import {
	authorizationEncryptionAlgValues,
	authorizationEncryptionEncValues,
	backchannelAuthenticationRequestSigningAlgValues,
	idTokenEncryptionAlgValues,
	idTokenEncryptionEncValues,
	introspectionEncryptionAlgValues,
	introspectionEncryptionEncValues,
	requestObjectEncryptionEncValues,
	requestObjectSigningAlgValues,
	userinfoEncryptionAlgValues,
	userinfoEncryptionEncValues
} from './jwaAlgorithms.ts';

export const vsCHAR = /[\x20-\x7E]/;

// A closed set of allowed string values → a TypeBox literal union. Used for the
// statically-known algorithm enumerations so the schema is the single source of
// truth for them (the imperative engine no longer re-checks these).
const literalUnion = (values: readonly string[]) =>
	t.Union(values.map((value) => t.Literal(value)));

// URL format checkers delegate to the existing validators so TypeBox enforces the
// exact same semantics the engine's webUris() pass used — only the rejection message
// changes. 'web-uri' allows http/https; 'https-uri' requires https.
FormatRegistry.Set('web-uri', (value) => validUrl.isWebUri(value));
FormatRegistry.Set('https-uri', (value) => validUrl.isHttpsUri(value));

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
	'requestObject.signingAlg': t.Optional(
		t.Union(requestObjectSigningAlgValues.map((alg) => t.Literal(alg)))
	),
	/*
	 * requestObject.backChannelSigningAlg
	 *
	 * description: The default signing algorithm for request objects
	 * when using backchannel authentication.
	 */
	'requestObject.backChannelSigningAlg': t.Optional(
		t.Union(
			backchannelAuthenticationRequestSigningAlgValues.map((alg) =>
				t.Literal(alg)
			)
		)
	),
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
	// Bounded to MAX_SAFE_INTEGER to match the engine's former Number.isSafeInteger check.
	clientSecretExpiresAt: t.Optional(
		t.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER })
	),
	// Informational client URLs (RFC 7591) — web URIs validated by TypeBox format.
	clientUri: t.Optional(t.String({ format: 'web-uri' })),
	logoUri: t.Optional(t.String({ format: 'web-uri' })),
	policyUri: t.Optional(t.String({ format: 'web-uri' })),
	tosUri: t.Optional(t.String({ format: 'web-uri' })),
	// initiateLoginUri must be https (HTTPS_URI).
	initiateLoginUri: t.Optional(t.String({ format: 'https-uri' })),
	// tokenEndpointAuthMethod: the registered client authentication method.
	tokenEndpointAuthMethod: t.Optional(t.String()),
	// tokenEndpointAuthSigningAlg: signing alg for *_jwt client authentication.
	tokenEndpointAuthSigningAlg: t.Optional(t.String()),
	// jwks: inline JSON Web Key Set (left permissive — the schema engine performs
	// the structural JWKS validation; this only contributes the type).
	jwks: t.Optional(
		t.Object({
			keys: t.Array(t.Object({}))
		})
	),
	// jwksUri: remote JSON Web Key Set location.
	jwksUri: t.Optional(t.String({ format: 'web-uri' })),
	// sectorIdentifierUri: pairwise sector identifier document location (https).
	sectorIdentifierUri: t.Optional(t.String({ format: 'https-uri' })),
	// postLogoutRedirectUris: allowed RP-initiated logout redirect targets.
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	// backchannelLogoutUri: back-channel logout notification endpoint (web uri).
	backchannelLogoutUri: t.Optional(t.String({ format: 'web-uri' })),
	// backchannelLogoutSessionRequired: include sid in the logout token.
	backchannelLogoutSessionRequired: t.Optional(t.Boolean()),
	// requireAuthTime / backchannelUserCodeParameter: boolean client flags.
	requireAuthTime: t.Optional(t.Boolean()),
	backchannelUserCodeParameter: t.Optional(t.Boolean()),
	// backchannelTokenDeliveryMode: CIBA delivery mode (poll/ping/push).
	backchannelTokenDeliveryMode: t.Optional(t.String()),
	// backchannelClientNotificationEndpoint: CIBA ping/push notification endpoint (https).
	backchannelClientNotificationEndpoint: t.Optional(
		t.String({ format: 'https-uri' })
	),
	// (CIBA request signing alg is the canonical `requestObject.backChannelSigningAlg` above.)
	// *SignedResponseAlg fields stay t.String(): their allowed sets are derived at
	// startup from the configured JWKS (runtime), so the engine still validates them.
	// The *Encrypted*Alg/Enc fields below have statically-known sets → TypeBox literal unions.
	idTokenSignedResponseAlg: t.Optional(t.String()),
	idTokenEncryptedResponseAlg: t.Optional(
		literalUnion(idTokenEncryptionAlgValues)
	),
	idTokenEncryptedResponseEnc: t.Optional(
		literalUnion(idTokenEncryptionEncValues)
	),
	userinfoSignedResponseAlg: t.Optional(t.String()),
	userinfoEncryptedResponseAlg: t.Optional(
		literalUnion(userinfoEncryptionAlgValues)
	),
	userinfoEncryptedResponseEnc: t.Optional(
		literalUnion(userinfoEncryptionEncValues)
	),
	introspectionSignedResponseAlg: t.Optional(t.String()),
	introspectionEncryptedResponseAlg: t.Optional(
		literalUnion(introspectionEncryptionAlgValues)
	),
	introspectionEncryptedResponseEnc: t.Optional(
		literalUnion(introspectionEncryptionEncValues)
	),
	authorizationSignedResponseAlg: t.Optional(t.String()),
	authorizationEncryptedResponseAlg: t.Optional(
		literalUnion(authorizationEncryptionAlgValues)
	),
	authorizationEncryptedResponseEnc: t.Optional(
		literalUnion(authorizationEncryptionEncValues)
	),
	// requestObjectEncryptionAlg stays t.String(): its set is JWKS-derived (runtime).
	// requestObjectEncryptionEnc has a static set → TypeBox literal union.
	requestObjectEncryptionAlg: t.Optional(t.String()),
	requestObjectEncryptionEnc: t.Optional(
		literalUnion(requestObjectEncryptionEncValues)
	),
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
	// defaultMaxAge: default max authentication age in seconds (non-negative safe integer).
	defaultMaxAge: t.Optional(
		t.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER })
	),
	// scope: space-delimited scope whitelist for the client.
	scope: t.Optional(t.String()),
	// authorizationDetailsTypes: allowed RAR authorization_details types.
	authorizationDetailsTypes: t.Optional(t.Array(t.String()))
});

export type ClientSchemaType = Static<typeof ClientSchema>;
