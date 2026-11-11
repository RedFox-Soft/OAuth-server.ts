import { Type as t, type Static } from '@sinclair/typebox';

/*
 * The two model areas of sign-in in front of an app behind a proxy (specs/122 R6, data-model.md). Written straight
 * through `checkedAdapter` (lib/behind_proxy/records.ts), never through a model class, so these schemas are what a
 * read is checked against. Import-free beyond TypeBox, so the storage guards can read them.
 *
 * Both carry `exp` (epoch seconds) mirroring the adapter's expiry, because a find answers a record a lazily
 * reaping datastore has not removed yet; a reader refuses one past it.
 */

/*
 * A person's session at one app, stored under the SHA-256 (base64url) of the cookie value; the value itself is
 * never stored. Accepted only by its own app of its own project.
 */
export const BehindProxySessionPayload = t.Object({
	accountId: t.String(),
	appId: t.String(),
	bucketId: t.String(),
	/* Epoch seconds. */
	createdAt: t.Number(),
	exp: t.Number(),
	/*
	 * When and how the person signed in, from the code this session was made from (specs/124 FR-020): what a fresh
	 * sign-in condition is judged on. Absent on a session made before conditions, which then fails such a condition.
	 */
	authTime: t.Optional(t.Number()),
	acr: t.Optional(t.String()),
	amr: t.Optional(t.Array(t.String()))
});
export type BehindProxySessionPayload = Static<
	typeof BehindProxySessionPayload
>;

/*
 * A sign-in between its start and its callback, stored under a random id sent as the OAuth `state`. The PKCE
 * verifier and the browser marker's digest are server-only and live ten minutes (lib/consts/sealed_fields.ts).
 */
export const BehindProxySignInPayload = t.Object({
	appId: t.String(),
	bucketId: t.String(),
	/* An absolute path on the app's origin, or `/`. */
	returnTo: t.String(),
	codeVerifier: t.String(),
	/* SHA-256 of the `__Host-foxauth-signin-<appId>` cookie value. */
	markerDigest: t.String(),
	used: t.Boolean(),
	exp: t.Number(),
	/*
	 * The oldest sign-in the path that sent the person here accepts, in seconds (specs/124 FR-021): the callback
	 * refuses a sign-in older than this rather than starting the same sign-in again.
	 */
	maxAge: t.Optional(t.Number()),
	/*
	 * The path asked for a sign-in with a code from an authenticator app (specs/128): the callback refuses one without,
	 * whatever the request to the sign-in said.
	 */
	requireCode: t.Optional(t.Literal(true))
});
export type BehindProxySignInPayload = Static<typeof BehindProxySignInPayload>;
