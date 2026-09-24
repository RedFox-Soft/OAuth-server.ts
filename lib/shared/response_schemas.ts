import { t, type Static } from 'elysia';

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

/*
 * What a page route (the interaction pages, the device code entry) answers with when it refuses: the
 * shared error body, or an HTML page — a form re-rendered with its error, or any refusal when the
 * caller's Accept asks for a page. Its pages themselves are HTML strings.
 */
export const PageError = t.Union([OAuthError, t.String()]);

// Pages answer 200 with HTML; these are the refusals the shared error handler and the pages produce.
export const PageResponses = {
	200: t.String(),
	400: PageError,
	401: PageError,
	403: PageError,
	422: PageError,
	429: PageError,
	500: PageError
};

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
	),
	// A client registered for a signed or encrypted answer receives it as a JWT (RFC 9701 §5).
	t.String()
]);

// PAR (RFC 9126) — handler returns a plain object with `set.status = 201`, so this schema is what
// serializes it: as a hand-built `Response` it went out untyped, i.e. application/octet-stream.
export const ParResponse = t.Object({
	request_uri: t.String(),
	expires_in: t.Number()
});

// Device authorization (RFC 8628 §3.2) — returned as a plain object (runtime-validated).
export const DeviceAuthorizationResponse = t.Object(
	{
		device_code: t.String(),
		user_code: t.String(),
		verification_uri: t.String(),
		verification_uri_complete: t.Optional(t.String()),
		expires_in: t.Number(),
		interval: t.Optional(t.Number())
	},
	{ additionalProperties: true }
);

// CIBA backchannel authentication response (CIBA Core §7.3) — returned as a plain object.
export const BackchannelAuthenticationResponse = t.Object(
	{
		auth_req_id: t.String(),
		expires_in: t.Number(),
		interval: t.Optional(t.Number())
	},
	{ additionalProperties: true }
);

// Authorization / end-session deliver via redirect (302) or auto-submitting HTML form / logout
// confirmation page. Handlers return `Response` objects, so this is type-level only (bypassed).
export const RedirectOrHtmlResponse = t.Union([
	t.String(),
	t.Object({}, { additionalProperties: true }),
	t.Void()
]);

// UserInfo — the claims object, or the signed/encrypted JWT as a string (OIDC Core §5.3.2). `sub` is
// always sent but optional here, so a grant that rejected it answers without it rather than failing
// validation; the members that locate distributed and aggregated claims (§5.6.2) are declared.
export const UserinfoResponse = t.Union([
	t.Object(
		{
			sub: t.Optional(t.String()),
			_claim_names: t.Optional(t.Record(t.String(), t.String())),
			_claim_sources: t.Optional(t.Record(t.String(), t.Unknown()))
		},
		{ additionalProperties: true }
	),
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

/*
 * The discovery document (OIDC Discovery 1.0 §3, RFC 8414 §2): every member the server computes, plus
 * the ones an operator may add (DiscoveryExtensions). All are optional because a disabled feature
 * removes its members; any other member an operator configures is passed through as given.
 */
export const DiscoveryResponse = t.Object(
	{
		issuer: t.Optional(t.String()),
		authorization_endpoint: t.Optional(t.String()),
		token_endpoint: t.Optional(t.String()),
		jwks_uri: t.Optional(t.String()),
		userinfo_endpoint: t.Optional(t.String()),
		registration_endpoint: t.Optional(t.String()),
		device_authorization_endpoint: t.Optional(t.String()),
		end_session_endpoint: t.Optional(t.String()),
		revocation_endpoint: t.Optional(t.String()),
		introspection_endpoint: t.Optional(t.String()),
		pushed_authorization_request_endpoint: t.Optional(t.String()),
		backchannel_authentication_endpoint: t.Optional(t.String()),
		op_policy_uri: t.Optional(t.String()),
		op_tos_uri: t.Optional(t.String()),
		service_documentation: t.Optional(t.String()),
		scopes_supported: t.Optional(t.Array(t.String())),
		claims_supported: t.Optional(t.Array(t.String())),
		grant_types_supported: t.Optional(t.Array(t.String())),
		token_endpoint_auth_methods_supported: t.Optional(t.Array(t.String())),
		acr_values_supported: t.Optional(t.Array(t.String())),
		response_types_supported: t.Optional(t.Array(t.String())),
		response_modes_supported: t.Optional(t.Array(t.String())),
		subject_types_supported: t.Optional(t.Array(t.String())),
		code_challenge_methods_supported: t.Optional(t.Array(t.String())),
		id_token_signing_alg_values_supported: t.Optional(t.Array(t.String())),
		token_endpoint_auth_signing_alg_values_supported: t.Optional(
			t.Array(t.String())
		),
		dpop_signing_alg_values_supported: t.Optional(t.Array(t.String())),
		id_token_encryption_alg_values_supported: t.Optional(t.Array(t.String())),
		id_token_encryption_enc_values_supported: t.Optional(t.Array(t.String())),
		request_object_signing_alg_values_supported: t.Optional(
			t.Array(t.String())
		),
		request_object_encryption_alg_values_supported: t.Optional(
			t.Array(t.String())
		),
		request_object_encryption_enc_values_supported: t.Optional(
			t.Array(t.String())
		),
		userinfo_signing_alg_values_supported: t.Optional(t.Array(t.String())),
		userinfo_encryption_alg_values_supported: t.Optional(t.Array(t.String())),
		userinfo_encryption_enc_values_supported: t.Optional(t.Array(t.String())),
		authorization_signing_alg_values_supported: t.Optional(t.Array(t.String())),
		authorization_encryption_alg_values_supported: t.Optional(
			t.Array(t.String())
		),
		authorization_encryption_enc_values_supported: t.Optional(
			t.Array(t.String())
		),
		introspection_signing_alg_values_supported: t.Optional(t.Array(t.String())),
		introspection_encryption_alg_values_supported: t.Optional(
			t.Array(t.String())
		),
		introspection_encryption_enc_values_supported: t.Optional(
			t.Array(t.String())
		),
		backchannel_token_delivery_modes_supported: t.Optional(t.Array(t.String())),
		backchannel_authentication_request_signing_alg_values_supported: t.Optional(
			t.Array(t.String())
		),
		authorization_details_types_supported: t.Optional(t.Array(t.String())),
		claim_types_supported: t.Optional(t.Array(t.String())),
		claims_locales_supported: t.Optional(t.Array(t.String())),
		display_values_supported: t.Optional(t.Array(t.String())),
		ui_locales_supported: t.Optional(t.Array(t.String())),
		authorization_response_iss_parameter_supported: t.Optional(t.Boolean()),
		client_id_metadata_document_supported: t.Optional(t.Boolean()),
		request_uri_parameter_supported: t.Optional(t.Boolean()),
		claims_parameter_supported: t.Optional(t.Boolean()),
		require_pushed_authorization_requests: t.Optional(t.Boolean()),
		request_parameter_supported: t.Optional(t.Boolean()),
		require_signed_request_object: t.Optional(t.Boolean()),
		backchannel_logout_supported: t.Optional(t.Boolean()),
		backchannel_logout_session_supported: t.Optional(t.Boolean()),
		tls_client_certificate_bound_access_tokens: t.Optional(t.Boolean()),
		backchannel_user_code_parameter_supported: t.Optional(t.Boolean())
	},
	{ additionalProperties: true }
);
// Indexable by any member name, as the pruning in lib/actions/discovery.ts reads and deletes them.
export type DiscoveryDocument = Static<typeof DiscoveryResponse> &
	Record<string, unknown>;

// The published key set (RFC 7517 §5): each key carries its own members beyond `kty`.
export const JwksResponse = t.Object({
	keys: t.Array(
		t.Object(
			{ kty: t.String(), kid: t.Optional(t.String()) },
			{ additionalProperties: true }
		)
	)
});

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
