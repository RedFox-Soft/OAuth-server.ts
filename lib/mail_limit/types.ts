import { Type as t, type Static } from '@sinclair/typebox';

/*
 * How many mail-sending requests one caller address made in one UTC hour, keyed
 * `${address}:${hourStartEpochSeconds}` (specs/115).
 *
 * Written straight through `adapter('MailRequestTally')` and never through a model class, so nothing
 * validates a write against this schema; it exists to be introspected by the ownership drift guard, the
 * arrangement lib/login_throttle/types.ts describes. No recipient, no project, no outcome: the limit
 * counts the asking, and a field naming who was asked for would be a list of the addresses people typed.
 */
export const MailRequestTallyPayload = t.Object({
	count: t.Number(),
	/* Mirrors the adapter's expiry (epoch seconds), which TestAdapter.upsert asserts against the TTL. */
	exp: t.Number()
});

export type MailRequestTallyPayload = Static<typeof MailRequestTallyPayload>;
