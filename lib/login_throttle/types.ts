import { Type as t, type Static } from '@sinclair/typebox';

/*
 * The password door's per-address failure counter, keyed `${bucketId}:${email}` through
 * emailScopedId (lib/helpers/email_scoped_id.ts).
 *
 * Written straight through `adapter('LoginThrottle')` and never through a model class, so nothing
 * validates a write against this schema — it exists to be introspected by the ownership drift guard
 * (test/storage_contract/inventory_drift.spec.ts), which is the arrangement lib/totp/types.ts
 * describes for the same reason.
 *
 * WHAT IS ABSENT IS THE POINT. No `accountId`: the area is unowned because a counter is written for
 * any submitted address, including one with no account, and a record that named a principal could not
 * be. No address and no bucket either — they are the id, and a field carrying them would be a second,
 * indexable way to enumerate the addresses people have typed. No password material, no source
 * address, no attempt history.
 */
export const LoginThrottlePayload = t.Object({
	/* Failed attempts inside the current window. At the cap the door refuses until the window ends. */
	failures: t.Number(),
	/* Epoch seconds the current window opened: the first failure after a clean slate or a reopening. */
	windowStart: t.Number(),
	/*
	 * How many windows this address has already exhausted, which selects the current window's length
	 * from the escalation curve. This field is why the record has to outlive its own window: reap it
	 * when the door reopens and every attacker who waits restarts at step 0, so no escalation ever
	 * happens. See lib/login_throttle/consts.ts for the arithmetic.
	 */
	step: t.Number(),
	/* Mirrors the adapter's expiry (epoch seconds), which TestAdapter.upsert asserts against the TTL. */
	exp: t.Number()
});

export type LoginThrottlePayload = Static<typeof LoginThrottlePayload>;
