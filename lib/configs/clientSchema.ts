import { Type as t, type Static } from '@sinclair/typebox';

export const noVSCHAR = /[\x20-\x7E]/;

export const ClientSchema = t.Object({
	/*
	 * clientId
	 *
	 * description: The client identifier.
	 */
	clientId: t.String({ pattern: noVSCHAR.source }),
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
	'requestObject.backChannelSigningAlg': t.Optional(t.String())
});

export type ClientSchemaType = Static<typeof ClientSchema>;
