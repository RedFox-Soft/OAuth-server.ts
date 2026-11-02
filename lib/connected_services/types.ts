import { Type as t, type Static } from '@sinclair/typebox';

/*
 * The connected-service and connected-account shapes (specs/117). Import-free beyond TypeBox, like
 * lib/federation/types.ts, because lib/adapters/types.ts embeds the service on the project record and every
 * backend reads the account.
 */

export const CONNECTED_SERVICE_CATALOGUE_IDS = [
	'google',
	'github',
	'slack',
	'microsoft'
] as const;
export const ConnectedServiceCatalogueId = t.Union(
	CONNECTED_SERVICE_CATALOGUE_IDS.map((id) => t.Literal(id))
);
export type ConnectedServiceCatalogueId = Static<
	typeof ConnectedServiceCatalogueId
>;

/*
 * Where a plain OAuth 2.0 provider says who the account is (specs/117 FR-003a). A path is dotted, and `a|b`
 * takes the first that is present: two observed shapes, no expression language.
 */
export const IdentitySource = t.Union([
	t.Object(
		{
			source: t.Literal('endpoint'),
			url: t.String({ maxLength: 2048 }),
			idPath: t.String({ minLength: 1, maxLength: 200 }),
			labelPath: t.Optional(t.String({ minLength: 1, maxLength: 200 }))
		},
		{ additionalProperties: false }
	),
	t.Object(
		{
			source: t.Literal('token'),
			idPath: t.String({ minLength: 1, maxLength: 200 }),
			labelPath: t.Optional(t.String({ minLength: 1, maxLength: 200 }))
		},
		{ additionalProperties: false }
	)
]);
export type IdentitySource = Static<typeof IdentitySource>;

/*
 * A service a project lets its people connect, with the project's own registration at the provider. Embedded
 * on the project record beside `federation` (specs/117 R1): owned by the project for life, moved and deleted
 * with it, sealed by the project store's decorator.
 *
 * The provider and the client id never change: the tokens of every connected account belong to that
 * registration, so a different one is a different service.
 */
export const ConnectedService = t.Object({
	id: t.String(),
	kind: t.Union([
		t.Literal('catalogue'),
		t.Literal('oidc'),
		t.Literal('oauth2')
	]),
	catalogueId: t.Optional(ConnectedServiceCatalogueId),
	issuer: t.Optional(t.String()),
	/* Microsoft only: `common`, `organizations`, `consumers` or a directory id. */
	tenant: t.Optional(t.String()),
	authorizationEndpoint: t.Optional(t.String()),
	tokenEndpoint: t.Optional(t.String()),
	identity: t.Optional(IdentitySource),
	revocationEndpoint: t.Optional(t.String()),
	clientId: t.String(),
	/*
	 * Write-only: masked on every read, sealed at rest (specs/116 kind `connectedServiceSecret`). Always written;
	 * absent on a read only when it cannot be opened with this keyring, which every consumer refuses.
	 */
	clientSecret: t.Optional(t.String()),
	scopes: t.Array(t.String()),
	displayName: t.String(),
	createdAt: t.String(),
	updatedAt: t.String()
});
export type ConnectedService = Static<typeof ConnectedService>;

/*
 * One person's account at one connected service. `_id` is derived from (project, service, person, upstream
 * account), so a reconnect of the same upstream account lands on the same record on every backend by its
 * primary key, with no second unique index to keep in step.
 */
export const ConnectedAccount = t.Object({
	_id: t.String(),
	bucketId: t.String(),
	serviceId: t.String(),
	accountId: t.String(),
	upstreamId: t.String(),
	label: t.String(),
	/* Both sealed (kind `connectedAccountToken`); never written while no keyring is in use. */
	refreshToken: t.Optional(t.String()),
	accessToken: t.Optional(t.String()),
	tokenType: t.String(),
	/* Epoch seconds; absent means the provider gave none, so the token does not expire. */
	accessTokenExpiresAt: t.Optional(t.Number()),
	refreshTokenExpiresAt: t.Optional(t.Number()),
	scopes: t.Array(t.String()),
	/* The provider sent no scope list, so `scopes` holds what was asked for. */
	scopesInferred: t.Boolean(),
	connectedAt: t.String(),
	updatedAt: t.String()
});
export type ConnectedAccount = Static<typeof ConnectedAccount>;

/*
 * A connect flow in flight (specs/117 R5): what the callback needs to finish it and to prove it is finishing
 * the flow this person started in this session. Keyed by sha256(state); the raw state, nonce and verifier are
 * handed to the browser's redirect and never stored as identifiers.
 */
export const ConnectStatePayload = t.Object({
	bucketId: t.String(),
	serviceId: t.String(),
	accountId: t.String(),
	/* SHA-256 of the session id that started the flow. */
	sessionDigest: t.String(),
	verifier: t.Optional(t.String()),
	nonce: t.Optional(t.String()),
	requestedScopes: t.Array(t.String()),
	/* Epoch seconds, checked on every read as well as reaped. */
	exp: t.Number()
});
export type ConnectStatePayload = Static<typeof ConnectStatePayload>;
