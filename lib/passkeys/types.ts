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
	 * the browser session the sign-in made, as an add's is.
	 */
	purpose: t.Union([t.Literal('add'), t.Literal('remove'), t.Literal('offer')]),
	/*
	 * The proof the ceremony was prepared under; an add stores it as the passkey's `createdVia`. `password` is an offer
	 * after a password alone, whose passkey is conditional.
	 */
	proof: t.Union([
		t.Literal('passkey'),
		t.Literal('password_code'),
		t.Literal('password_mail'),
		t.Literal('password')
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
	/* Mirrors the adapter's expiry (epoch seconds): five minutes from the write. */
	exp: t.Number()
});

export type PasskeyCeremonyPayload = Static<typeof PasskeyCeremonyPayload>;

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
