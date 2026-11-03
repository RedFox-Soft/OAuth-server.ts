import { t } from 'elysia';

/*
 * Encryption at rest (specs/116 contracts/admin-surface.md). Its own module, not inline in the routes, because
 * the MCP catalogue imports schema modules and must never import a route module.
 */
const UnreadableSecret = t.Object({
	kind: t.String(),
	owner: t.Record(t.String(), t.String()),
	needsKid: t.Optional(t.String()),
	reason: t.Union([
		t.Literal('missing-key'),
		t.Literal('integrity'),
		t.Literal('binding')
	])
});

export const KeyringStatusResponse = t.Object({
	state: t.Union([
		t.Literal('none'),
		t.Literal('generated-not-applied'),
		t.Literal('in-use')
	]),
	source: t.Optional(t.Union([t.Literal('environment'), t.Literal('file')])),
	writeKid: t.Optional(t.String()),
	kids: t.Array(
		t.Object({ kid: t.String(), inKeyring: t.Boolean(), values: t.Number() })
	),
	plaintext: t.Number(),
	unreadable: t.Array(UnreadableSecret),
	unreadableTotal: t.Number(),
	backupConfirmed: t.Union([t.Object({ at: t.String() }), t.Null()]),
	lastPassAt: t.Union([t.String(), t.Null()]),
	passPending: t.Boolean(),
	regenerated: t.Union([
		t.Object({
			errorOriginSalt: t.Optional(t.String()),
			dpopNonceSecret: t.Optional(t.String()),
			note: t.String()
		}),
		t.Null()
	])
});

/* The one answer that carries key material, once, at the moment it is made. Never published to an agent. */
export const KeyringGeneratedResponse = t.Object({
	keyring: t.String(),
	applied: t.Boolean(),
	location: t.Optional(t.String())
});
