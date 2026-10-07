import { Type as t, type Static } from '@sinclair/typebox';

/*
 * One record of a provisioning connection's deprovisioning tally (specs/072 research R9): either the counter
 * that hands out sequence numbers (`${connectionId}:${epoch}:counter`, carrying `n`) or one of the
 * threshold's slots (`${connectionId}:${epoch}:${k}`, carrying nothing but its expiry).
 *
 * Written straight through `adapter('DeprovisionSlot')` and never through a model class — the arrangement
 * lib/login_throttle/types.ts describes — so this schema exists to be introspected by the ownership drift
 * guard and to check reads, not to gate writes.
 *
 * No user, no request, no bucket: a slot says only that *a* deprovisioning was admitted, so the area is
 * unowned and a dump of it reveals nothing about who left.
 */
export const DeprovisionSlotPayload = t.Object({
	/* The counter's last sequence number; absent on a slot. */
	n: t.Optional(t.Number()),
	/* Mirrors the adapter's expiry (epoch seconds): an expired record that is not yet reaped counts as free. */
	exp: t.Number()
});

export type DeprovisionSlotPayload = Static<typeof DeprovisionSlotPayload>;
