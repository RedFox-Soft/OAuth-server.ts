import { Type as t, type Static } from '@sinclair/typebox';

/*
 * The model areas of signing in with a passkey (specs/139). TypeBox schemas rather than interfaces, for the reason
 * lib/totp/types.ts gives: the storage-ownership drift guard reads an area's payload fields at runtime. Both are
 * written straight through `adapter(...)`, never through a model class, so these schemas are introspected, not a
 * gate on a write.
 */

/*
 * An add or a removal prepared on the person's own page (data-model "PasskeyCeremony"), keyed `add:<session uid>`
 * or `remove:<session uid>`: one of each per browser session, the newer write replacing the older. Account-owned, so
 * a sign-out everywhere kills a half-done add. Read with `consume` at the act, so it is spent once under concurrency.
 */
export const PasskeyCeremonyPayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	/* `account:<session uid>`: the browser session the ceremony belongs to, compared at the act. */
	holder: t.String(),
	/*
	 * `offer` is the passkey offer after a password sign-in (specs/141), keyed `offer:<interaction uid>`; its holder is
	 * the browser session the sign-in made, as an add's is. `admin_link` is a standalone enrollment link ceremony
	 * prepared on `/account/passkey-setup` (specs/145).
	 */
	purpose: t.Union([
		t.Literal('add'),
		t.Literal('remove'),
		t.Literal('offer'),
		t.Literal('admin_link')
	]),
	/*
	 * The proof the ceremony was prepared under; an add stores it as the passkey's `createdVia`. `password` is an offer
	 * after a password alone, whose passkey is conditional.
	 */
	proof: t.Union([
		t.Literal('passkey'),
		t.Literal('password_code'),
		t.Literal('password_mail'),
		t.Literal('password'),
		t.Literal('admin_link'),
		t.Literal('federated_mail')
	]),
	/* An add: 32 random bytes, base64url, the challenge its options carried. */
	challenge: t.Optional(t.String()),
	/* An add: the `webauthnUserId` its options carried; the account must still hold it at the act. */
	userId: t.Optional(t.String()),
	/* An add: the one RP ID and the one origin its options were made for. */
	rpId: t.Optional(t.String()),
	origin: t.Optional(t.String()),
	/* A removal: the passkey record it is for. */
	passkeyId: t.Optional(t.String()),
	/* An admin enrollment link ceremony: the link digest and whether an enrolled TOTP has been passed in this browser. */
	linkId: t.Optional(t.String()),
	totpVerified: t.Optional(t.Boolean()),
	/* Mirrors the adapter's expiry (epoch seconds): five minutes from the write. */
	exp: t.Number()
});

export type PasskeyCeremonyPayload = Static<typeof PasskeyCeremonyPayload>;

/*
 * Pre-account passkey registration challenge (specs/145 Q2=A, S4): keyed by sha256(token) in link mode or by random id
 * in code / decoy mode. Unowned because no account exists yet; expires after ten minutes.
 */
export const PasskeyRegistrationChallengePayload = t.Object({
	bucketId: t.String(),
	email: t.String(),
	holder: t.String(),
	method: t.Union([t.Literal('link'), t.Literal('code')]),
	exists: t.Boolean(),
	codeHash: t.Optional(t.String()),
	attempts: t.Number(),
	language: t.String(),
	exp: t.Number()
});

export type PasskeyRegistrationChallengePayload = Static<
	typeof PasskeyRegistrationChallengePayload
>;

/*
 * Self-service passkey recovery link (specs/145 S3): keyed by sha256(token), bound to the requesting browser
 * interaction (`holder`). Account-owned so deletion, lock, or deactivation ends it immediately; expires after ten minutes.
 */
export const PasskeyRecoveryChallengePayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	email: t.String(),
	holder: t.String(),
	language: t.String(),
	exp: t.Number()
});

export type PasskeyRecoveryChallengePayload = Static<
	typeof PasskeyRecoveryChallengePayload
>;

/*
 * Administrator-sent passkey enrollment link (specs/145 S14): keyed by sha256(token), usable in any browser for
 * twenty-four hours. Account-owned so deletion, lock, deactivation, or sign-out everywhere ends it.
 */
export const PasskeyAdminLinkPayload = t.Object({
	accountId: t.String(),
	bucketId: t.String(),
	email: t.String(),
	sentBy: t.String(),
	language: t.String(),
	exp: t.Number()
});

export type PasskeyAdminLinkPayload = Static<typeof PasskeyAdminLinkPayload>;

/*
 * Rate-limit window and latest-link pointer for passkey registration, recovery, and admin enrollment links (specs/145).
 * Keyed by `${purpose}:${bucketId}:${emailOrAccountId}`; unowned because registration throttles addresses with no account.
 */
export const PasskeyLinkThrottlePayload = t.Object({
	lastSentAt: t.Number(),
	windowStart: t.Number(),
	dayCount: t.Number(),
	challengeId: t.Optional(t.String()),
	exp: t.Number()
});

export type PasskeyLinkThrottlePayload = Static<
	typeof PasskeyLinkThrottlePayload
>;

/*
 * Failed passkey sign-ins from one caller address in one UTC hour, keyed `${address}:${hourStartEpochSeconds}`, as
 * `MailRequestTally` is (lib/mail_limit/types.ts). Numbers only: no account, no credential. Unowned, since the caller
 * is not a principal; kept an hour past its hour.
 */
export const PasskeyAttemptTallyPayload = t.Object({
	count: t.Number(),
	exp: t.Number()
});

export type PasskeyAttemptTallyPayload = Static<
	typeof PasskeyAttemptTallyPayload
>;
