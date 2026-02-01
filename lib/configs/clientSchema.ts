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
	'consent.require': t.Boolean()
});

export type ClientSchemaType = Static<typeof ClientSchema>;
