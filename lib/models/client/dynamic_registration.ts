import { adapter } from '../../adapters/index.js';
import epochTime from '../../helpers/epoch_time.js';

/*
 * Bounding what dynamic client registration can accumulate.
 *
 * The problem is the one the MCP project gives as its first reason for moving away from dynamic
 * registration: an unauthenticated endpoint that writes a database row produces unbounded growth,
 * because every instance of every application registers its own client and nothing ever removes one.
 *
 * Three mechanisms were considered and two rejected, which is worth recording because the rejected
 * ones look cheaper:
 *
 *  - An expiry index on the whole `Client` area. Rejected by the storage inventory itself, at the
 *    `Client` entry: `MongoAdapter.upsert` never `$unset`s a stale `expiresAt`, so the first
 *    administrator-created client that ever acquired one would be deleted silently. "Inert now,
 *    unrecoverable later" is how that comment puts it.
 *  - A partial index covering only self-registered rows. `IndexSpec` cannot express a
 *    `partialFilterExpression`, and extending it would mean extending provisioning and the two-way
 *    reconciliation with it.
 *
 * What is left is an explicit sweep, expressed as an adapter method the way Principle III requires a
 * new storage requirement to be. It runs opportunistically at registration time — the only moment
 * that both correlates with growth and is already paying for a write — so there is no scheduler and
 * no background job to own.
 */

/* The stored field names. Sourced here so the two call sites cannot disagree about a spelling. */
const MARKER_FIELD = 'registeredDynamically';
const USED_FIELD = 'registrationUsedAt';
/* Recognised metadata, so it is stored snake_case even though the object carries it camelCased. */
const AGE_FIELD = 'client_id_issued_at';

/*
 * Twelve hours. A registration that has not completed an authorization by then is either a client
 * that failed at the next step or a probe, and neither becomes more legitimate with time. Short
 * enough to bound growth, long enough that a developer who registers, goes to lunch, and comes back
 * to finish the flow still has their client.
 */
export const UNUSED_REGISTRATION_TTL_SECONDS = 12 * 60 * 60;

/*
 * Records that a self-registered client got as far as completing an authorization, which is what
 * takes it out of reach of the sweep.
 *
 * A no-op for everything else — an administrator-created client, and one already marked — so the
 * write happens at most once per client and never at all for the ordinary case. That matters because
 * this is called from the token path.
 */
export async function markRegistrationUsed(client: {
	clientId: string;
	registeredDynamically?: boolean;
	registrationUsedAt?: number;
}): Promise<void> {
	if (!client.registeredDynamically || client.registrationUsedAt) return;

	const stored = await adapter('Client').find(client.clientId);
	/*
	 * Re-read rather than written from the in-memory object: the validated client carries derived and
	 * defaulted properties that were never stored, and writing it back would persist them as if an
	 * operator had set them.
	 */
	if (!stored) return;

	await adapter('Client').upsert(client.clientId, {
		...stored,
		[USED_FIELD]: epochTime()
	});
}

/*
 * Removes self-registered clients that never completed an authorization within the window. Returns
 * how many went, so a caller can report it; callers that cannot use the number ignore it.
 *
 * Deliberately swallows a storage failure. This runs alongside a registration that is otherwise
 * succeeding, and housekeeping that could not run is not a reason to refuse a well-formed request —
 * the next registration sweeps again.
 */
export async function reclaimUnusedRegistrations(): Promise<number> {
	const before = epochTime() - UNUSED_REGISTRATION_TTL_SECONDS;
	try {
		return await adapter('Client').destroyUnusedSince(
			MARKER_FIELD,
			USED_FIELD,
			AGE_FIELD,
			before
		);
	} catch {
		return 0;
	}
}
