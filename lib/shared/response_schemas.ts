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

// Token endpoint (RFC 6749 §5.1). Per-grant handlers resolve through `executeGrant`, whose return
// type is `Response | Record<string, unknown>` (the grant handlers are not yet individually typed —
// US2/US3 typing debt). Typing the success body as an open record keeps it assignable (no `any`,
// no new compile error) while still runtime-accepting every grant's body; the named field set
// (access_token, token_type, expires_in, scope, id_token, refresh_token) is documented in
// contracts/endpoint-responses.md and can be tightened once grant returns are typed.
export const TokenResponse = t.Record(t.String(), t.Unknown());

// Introspection (RFC 7662) — JSON variant; the JWT variant returns a `Response` (bypasses schema).
export const IntrospectionResponse = t.Union([
	t.Object({ active: t.Literal(false) }, { additionalProperties: true }),
	t.Object(
		{ active: t.Literal(true), client_id: t.String() },
		{ additionalProperties: true }
	)
]);

// PAR (RFC 9126) — handler returns a `Response` with status 201 (bypasses schema).
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

// Dynamic Client Registration / Registration Management (RFC 7591/7592). Create/read/update return
// the client metadata (snake_case) plus, when issued, registration_access_token/registration_client_uri;
// the field set is dynamic per client, so this stays permissive. Delete returns 204 with no body (Void).
export const RegistrationResponse = t.Union([
	t.Object(
		{
			client_id: t.String()
		},
		{ additionalProperties: true }
	),
	t.Void()
]);

// Discovery metadata is a large dynamic object assembled from enabled features (runtime-validated).
export const DiscoveryResponse = t.Object({}, { additionalProperties: true });

// Health probe — current literal body `{ status: 'OK', timestamp }`.
export const HealthResponse = t.Object(
	{
		status: t.String(),
		timestamp: t.Optional(t.String())
	},
	{ additionalProperties: true }
);
