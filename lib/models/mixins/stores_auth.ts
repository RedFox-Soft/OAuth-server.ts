import { Type as t } from '@sinclair/typebox';

export const authPayloadModel = t.Object({
	accountId: t.Optional(t.String()),
	acr: t.Optional(t.String()),
	amr: t.Optional(t.Array(t.String())),
	authTime: t.Optional(t.Number()),
	claims: t.Optional(t.Object({})),
	nonce: t.Optional(t.String()),
	// One resource is stored as itself, several as the list (process_response_types, device, CIBA).
	resource: t.Optional(t.Union([t.String(), t.Array(t.String())])),
	scope: t.Optional(t.String()),
	sid: t.Optional(t.String())
});

/*
 * How the authorization that produced this artifact signed the person in, when it did: at this server, or
 * through an upstream identity provider. Absent when the authorization ran no sign-in — a session reused,
 * silently or otherwise — which is how the activity recorder tells a sign-in from a renewal (specs/076).
 *
 * Only the request knows whether it signed someone in; a timestamp comparison cannot tell a slow consent
 * screen from a reused session. Absent also on an artifact written before this field existed, which then
 * counts as a renewal: the conservative reading, and why no migration is needed.
 *
 * On the three artifacts a sign-in produces — never on a refresh token, whose use is a renewal by definition.
 */
export const signInPayload = t.Object({
	signIn: t.Optional(t.Union([t.Literal('local'), t.Literal('federated')]))
});
