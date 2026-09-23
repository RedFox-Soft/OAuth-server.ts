import { type Static } from '@sinclair/typebox';

import { type ClientSchema } from '../../configs/clientSchema.ts';
import {
	type encryptionAlgValues,
	type signingAlgValues
} from '../../configs/jwaConsts.ts';
import {
	type CibaDeliveryMode,
	type TokenEndpointAuthMethod
} from '../../consts/client_attributes.ts';

/*
 * Attributes ClientSchema declares as any string, because the set a deployment admits is resolved while
 * validation runs. Every such set is a subset of a fixed list — the methods and modes the configuration
 * check admits, the JWA algorithms — and a validated client has passed the check against it, so its
 * type can name the list. ClientSchema itself is left as it is: widening its runtime check is not what
 * this is for.
 */
type Refined = {
	tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
	tokenEndpointAuthSigningAlg?: signingAlgValues;
	backchannelTokenDeliveryMode?: CibaDeliveryMode;
	idTokenSignedResponseAlg?: signingAlgValues;
	userinfoSignedResponseAlg?: signingAlgValues;
	introspectionSignedResponseAlg?: signingAlgValues;
	authorizationSignedResponseAlg?: signingAlgValues;
	requestObjectEncryptionAlg?: encryptionAlgValues;
	jwks?: { keys: Array<Record<string, unknown>> };
};

/* The attributes of a validated client, camelCase: ClientSchema's, with the closed sets named. */
export type ClientData = Omit<Static<typeof ClientSchema>, keyof Refined> &
	Refined;

/* Readonly all the way down, because a validated client is frozen all the way down. */
type DeepReadonly<T> = T extends (infer U)[]
	? readonly DeepReadonly<U>[]
	: T extends object
		? { readonly [K in keyof T]: DeepReadonly<T[K]> }
		: T;

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
export type Client = DeepReadonly<
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

/* A record as the adapter holds it: always under its id. */
export type StoredClient = ClientRecord & { readonly clientId: string };

/* RFC 7591 / 7592 client metadata: every member under its snake_case wire name. */
export type WireClient = Record<string, unknown>;
