import { type Static } from '@sinclair/typebox';

import { type ClientSchema } from '../../configs/clientSchema.ts';

/* The attributes of a validated client, camelCase, as ClientSchema declares them. */
export type ClientData = Static<typeof ClientSchema>;

/*
 * Attributes every validated client carries because a default always fills them: the base defaults in
 * ClientDefaults, and the recognised attributes whose declaration gives a default with no capability
 * requirement. A capability-gated default (post_logout_redirect_uris, introspection_signed_response_alg,
 * …) is absent while its capability is off, so it stays optional. A list rather than only a type so
 * test/dynamic_registration/defaults.spec.ts can hold it to the declaration.
 */
export const ALWAYS_PRESENT = [
	'redirectUris',
	'applicationType',
	'responseTypes',
	'grantTypes',
	'subjectType',
	'tokenEndpointAuthMethod',
	'idTokenSignedResponseAlg',
	'requireAuthTime',
	'dpopBoundAccessTokens',
	'authorization.requirePushedAuthorizationRequests',
	'requestObject.require',
	'consent.require'
] as const;

export type AlwaysPresent = (typeof ALWAYS_PRESENT)[number];

/* A validated, frozen client: flat registration data and nothing else. */
export type Client = Readonly<
	ClientData & Required<Pick<ClientData, AlwaysPresent>>
>;

/*
 * What validation reads and what storage holds — one naming convention: base attributes under their
 * canonical names, recognised metadata under its wire name.
 */
export type ClientRecord = { readonly clientId?: string } & Record<
	string,
	unknown
>;

/* RFC 7591 / 7592 client metadata: every member under its snake_case wire name. */
export type WireClient = Record<string, unknown>;
