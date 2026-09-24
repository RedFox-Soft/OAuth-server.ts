import { t } from 'elysia';

/*
 * Shared response schemas for per-endpoint typed responses (FR-013).
 *
 * These describe today's on-the-wire responses; they do not change them. Elysia runtime-validates
 * the value a handler RETURNS against the matching success-status schema, so success schemas that
 * carry dynamic/extra fields are declared with `additionalProperties: true` to stay permissive
 * (never 422 a real body). Error-status schemas are NOT runtime-validated against the shared
 * `onError` handler's output — they exist purely so the Eden client can infer the error union.
 */

// RFC 6749 §5.2 error body (+ state/iss for authorization-endpoint errors).
export const OAuthError = t.Object({
	error: t.String(),
	error_description: t.Optional(t.String()),
	state: t.Optional(t.String()),
	iss: t.Optional(t.String())
});

// Token endpoint (RFC 6749 §5.1). Which members a success body carries depends on grant_type:
//   - client_credentials                → access token only (no id_token / refresh_token)
//   - device_code, ciba                 → + id_token, refresh_token
//   - authorization_code, refresh_token → + id_token, refresh_token, authorization_details (RAR)
// One object with those members optional, not a union per grant: every member beyond the access
// token is already optional, so each grant's body was valid against the widest branch and the union
// admitted exactly what this admits. The union only made a member absent from one branch unreadable
// on the others. `additionalProperties` stays open (DPoP `cnf` and other dynamic extras) so a real
// body never 422s.
export const TokenResponse = t.Object(
	{
		access_token: t.String(),
		token_type: t.String(),
		expires_in: t.Number(),
		scope: t.Optional(t.String()),
		id_token: t.Optional(t.String()),
		refresh_token: t.Optional(t.String()),
		authorization_details: t.Optional(t.Array(t.Unknown()))
	},
	{ additionalProperties: true }
);

// Introspection (RFC 7662) — JSON variant; the JWT variant returns a `Response` (bypasses schema).
// The active branch declares the members RFC 7662 §2.2 defines and this server emits, with the types
// it emits them in (`cnf` carries `x5t#S256` or `jkt`), so a reader can use them without a cast.
export const IntrospectionResponse = t.Union([
	t.Object({ active: t.Literal(false) }, { additionalProperties: true }),
	t.Object(
		{
			active: t.Literal(true),
			client_id: t.String(),
			scope: t.Optional(t.String()),
			token_type: t.Optional(t.String()),
			exp: t.Optional(t.Number()),
			iat: t.Optional(t.Number()),
			sub: t.Optional(t.String()),
			aud: t.Optional(t.String()),
			iss: t.Optional(t.String()),
			jti: t.Optional(t.String()),
			sid: t.Optional(t.String()),
			cnf: t.Optional(t.Record(t.String(), t.String())),
			authorization_details: t.Optional(t.Array(t.Unknown()))
		},
		{ additionalProperties: true }
	)
]);

// PAR (RFC 9126) — handler returns a plain object with `set.status = 201`, so this schema is what
// serializes it: as a hand-built `Response` it went out untyped, i.e. application/octet-stream.
export const ParResponse = t.Object({
	request_uri: t.String(),
	expires_in: t.Number()
});

// Device authorization (RFC 8628) — returned as a plain object (runtime-validated).
export const DeviceAuthorizationResponse = t.Object(
	{
		device_code: t.Optional(t.String()),
		user_code: t.Optional(t.String()),
		verification_uri: t.Optional(t.String()),
		verification_uri_complete: t.Optional(t.String()),
		expires_in: t.Optional(t.Number()),
		interval: t.Optional(t.Number())
	},
	{ additionalProperties: true }
);

// CIBA backchannel authentication (OpenID CIBA). The handler currently returns no body; the Void
// branch keeps that behaviour while the object branch documents the negotiated shape for Eden.
export const BackchannelAuthenticationResponse = t.Union([
	t.Object(
		{
			auth_req_id: t.String(),
			expires_in: t.Number(),
			interval: t.Optional(t.Number())
		},
		{ additionalProperties: true }
	),
	t.Void()
]);

// Authorization / end-session deliver via redirect (302) or auto-submitting HTML form / logout
// confirmation page. Handlers return `Response` objects, so this is type-level only (bypassed).
export const RedirectOrHtmlResponse = t.Union([
	t.String(),
	t.Object({}, { additionalProperties: true }),
	t.Void()
]);

// UserInfo — claims object (runtime-validated); signed/encrypted variant returns a `Response`.
export const UserinfoResponse = t.Union([
	t.Object({}, { additionalProperties: true }),
	t.String()
]);

// Dynamic Client Registration / Registration Management (RFC 7591/7592). Create, read and update
// return the client metadata (snake_case) plus, when issued, the registration credentials. The members
// both RFCs define for the response are declared; the rest of the metadata varies per client and stays
// open. Delete answers 204 with no body, declared on its own route.
export const RegistrationResponse = t.Object(
	{
		client_id: t.String(),
		client_secret: t.Optional(t.String()),
		client_id_issued_at: t.Optional(t.Number()),
		client_secret_expires_at: t.Optional(t.Number()),
		registration_access_token: t.Optional(t.String()),
		registration_client_uri: t.Optional(t.String()),
		redirect_uris: t.Optional(t.Array(t.String())),
		grant_types: t.Optional(t.Array(t.String())),
		response_types: t.Optional(t.Array(t.String()))
	},
	{ additionalProperties: true }
);

// Discovery metadata is a large dynamic object assembled from enabled features (runtime-validated).
export const DiscoveryResponse = t.Object({}, { additionalProperties: true });

// Health probe — current literal body `{ status: 'OK', timestamp }`.
/*
 * Readiness. `subsystem` names what is unreachable and appears only on a failure — enough for an
 * operator to know where to look, and never the connection detail that would tell them more than
 * they should paste into an issue.
 */
export const ReadyResponse = t.Object(
	{
		status: t.Union([t.Literal('ready'), t.Literal('not_ready')]),
		subsystem: t.Optional(t.Literal('storage'))
	},
	{ additionalProperties: false }
);

export const HealthResponse = t.Object(
	{
		status: t.String(),
		timestamp: t.Optional(t.String())
	},
	{ additionalProperties: true }
);
