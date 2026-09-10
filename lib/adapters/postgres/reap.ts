import { sql } from './db.js';
import {
	FIXED_AREAS,
	type StorageArea
} from '../../consts/storage_inventory.js';

/*
 * Reclaiming expired records.
 *
 * PostgreSQL has no TTL index, so what MongoDB gets from the server this backend has to do itself.
 * The important thing is what that does *not* mean: this is housekeeping, not correctness. Expiry is
 * enforced one layer up, in the model's `tryFind`, on both backends — MongoDB's TTL monitor also runs
 * on its own schedule and a just-expired document is readable until it fires. Treating the sweeper as
 * the thing that makes expiry work would invite exactly the mistake of filtering reads here, which
 * would make the two adapters disagree instead of agree.
 *
 * Which areas are swept comes from the inventory's `reaped` field and nowhere else, so an area that
 * grows forever is a declaration somebody has to have written, not an omission. Per-bucket end-user
 * areas are `reaped: null` and are correctly never touched.
 */

/*
 * Matched to MongoDB's TTL monitor, which runs about once a minute. The two cadences are the one
 * observable difference between the backends' reclamation, so the value belongs in the divergence
 * register — declared rather than tuned, because an operator comparing two deployments should be able
 * to read why storage shrinks at different moments.
 */
export const SWEEP_INTERVAL_MS = 60_000;

function reapedAreas(): StorageArea[] {
	return FIXED_AREAS.filter((area) => area.reaped !== null);
}

/*
 * One pass over every expiring area, returning how many records went so a caller can report real work.
 *
 * Deletes in one statement per area rather than one for the lot: the areas are separate tables, and a
 * partial index on `expires_at` makes each of these an index scan over exactly the rows that can
 * match.
 */
export async function sweepOnce(): Promise<number> {
	const handle = sql();
	let removed = 0;

	for (const area of reapedAreas()) {
		const rows = await handle`
			DELETE FROM ${handle(area.name)}
			WHERE expires_at IS NOT NULL AND expires_at < now()
			RETURNING id
		`;
		removed += rows.length;
	}

	return removed;
}

/*
 * Runs the sweep on an interval and returns the way to stop it.
 *
 * A failure is swallowed rather than thrown, for the reason the unused-registration sweep beside it
 * gives: housekeeping that could not run is not a reason to take anything else down, and the next
 * pass sweeps again. What would be worse than a missed pass is an unhandled rejection from a timer,
 * which takes the process with it.
 *
 * The timer is unreferenced so it cannot hold a process open — an operator script that imports a store
 * should still exit when its work is done.
 */
export function startSweeper(
	intervalMs: number = SWEEP_INTERVAL_MS
): () => void {
	const timer = setInterval(() => {
		void sweepOnce().catch((error: unknown) => {
			console.error('expiry sweep failed; the next pass will retry', error);
		});
	}, intervalMs);

	timer.unref?.();

	return () => clearInterval(timer);
}
