import { Type as t, type Static } from '@sinclair/typebox';

/*
 * One process's counts for one project and one UTC day of password sign-ins from addresses on FoxTrust's attacker
 * list (specs/125), keyed `${bucketId}:${day}:${processId}`.
 *
 * Each process writes absolute totals to a record of its own, so a flush is one upsert and two processes never race
 * on a counter; a project's figure is the sum of its records. No address, account or email: the counts are what an
 * administrator decides with, and a field naming who would make this a list of the people on shared addresses.
 *
 * Written straight through `adapter('PasswordGuessingTally')`; the schema is introspected by the ownership drift
 * guard and checks every read, the arrangement lib/login_throttle/types.ts describes.
 */
export const PasswordGuessingTallyPayload = t.Object({
	bucketId: t.String(),
	day: t.String(),
	attempts: t.Number(),
	rightPassword: t.Number(),
	refused: t.Number(),
	/* Mirrors the adapter's expiry (epoch seconds), which TestAdapter.upsert asserts against the TTL. */
	exp: t.Number()
});

export type PasswordGuessingTallyPayload = Static<
	typeof PasswordGuessingTallyPayload
>;
