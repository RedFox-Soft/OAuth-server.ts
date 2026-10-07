import { Type as t, type Static } from '@sinclair/typebox';

/*
 * One upstream session at one provider of one bucket, and the account it signed in (specs/073 research R4),
 * stored under `sha256("<bucketId>:<providerId>:<sid>")`.
 *
 * It exists because sessions here are reachable only by id, uid and owner, and a back-channel logout token
 * may name the upstream session alone; this record turns that into the account whose sessions are then read.
 * Written straight through `adapter('UpstreamSession')`, never through a model class — the arrangement
 * lib/login_throttle/types.ts describes — so the schema exists to be introspected and to check reads.
 */
export const UpstreamSessionPayload = t.Object({
	accountId: t.String(),
	/* Mirrors the adapter's expiry (epoch seconds), which a lazily reaping datastore may overrun. */
	exp: t.Number()
});

export type UpstreamSessionPayload = Static<typeof UpstreamSessionPayload>;
