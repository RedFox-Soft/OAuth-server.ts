/*
 * Keeping two migration runs apart.
 *
 * A lease row on both backends, rather than a PostgreSQL advisory lock on one and a lease on the
 * other. The contract named an advisory lock, and this deviates from it deliberately:
 *
 *   - An advisory lock is SESSION-scoped, and both backends are reached through a connection pool.
 *     Two consecutive statements are not guaranteed the same connection, so the lock would be taken
 *     on one connection and the migration run on another. That failure appears only under
 *     concurrency, in production, which is the worst place to discover it — and pinning a connection
 *     for the run's duration means the lock mechanism and the pool have to agree about lifetimes.
 *   - The lease has to exist anyway. A crashed holder must not block every future run, so an expiry
 *     is required whichever mechanism is chosen, and an advisory lock would leave that machinery
 *     built and unused on one backend.
 *   - One mechanism means one set of semantics to reason about and one set to verify, instead of two
 *     that are supposed to behave alike.
 *
 * What it costs: a holder that dies mid-run blocks other runs until the lease expires, where an
 * advisory lock would free immediately on disconnect. For an operator command that is the right
 * trade — a stuck lease is visible and waits out, while a lock released mid-migration would let a
 * second run start on top of a half-applied one.
 */

export interface LeaseStore {
	/* Reads the current lease, or null. */
	read(): Promise<{ holder: string; expiresAt: Date } | null>;
	/* Writes the lease only if none is held, or the held one has expired. Returns whether it won. */
	acquire(holder: string, expiresAt: Date): Promise<boolean>;
	/* Releases only a lease this holder owns, so a run that overran cannot free somebody else's. */
	release(holder: string): Promise<void>;
}

/* Long enough that an ordinary migration finishes inside it, short enough that a crashed holder does
 * not block the next operator for an afternoon. Renewed while the run is in progress. */
export const LEASE_SECONDS = 60;
const RENEW_EVERY_MS = (LEASE_SECONDS / 3) * 1000;

export class MigrationLockBusy extends Error {
	constructor(holder: string, expiresAt: Date) {
		super(
			`another migration run holds the lock (${holder}), expiring at ${expiresAt.toISOString()}. ` +
				'Wait for it to finish, or for the lease to expire if that run has died.'
		);
		this.name = 'MigrationLockBusy';
	}
}

/*
 * Runs `inner` under the lease, renewing it while the work is in progress.
 *
 * Renewal is what lets the lease be short. Without it the timeout would have to exceed the slowest
 * migration anybody will ever write, which is a number nobody can pick — too low and a legitimate run
 * loses its own lock halfway through, too high and a crash blocks the next run for that long.
 */
export async function withLease<T>(
	store: LeaseStore,
	holder: string,
	inner: () => Promise<T>
): Promise<T> {
	const until = () => new Date(Date.now() + LEASE_SECONDS * 1000);

	if (!(await store.acquire(holder, until()))) {
		const held = await store.read();
		throw new MigrationLockBusy(
			held?.holder ?? 'unknown',
			held?.expiresAt ?? new Date()
		);
	}

	const renew = setInterval(() => {
		void store.acquire(holder, until()).catch(() => {
			/* A failed renewal is not worth aborting a migration that is otherwise working: the lease
			 * either still stands, or has lapsed and the run finishes without protection it no longer
			 * has. Either way, dying here would leave the effect half-applied. */
		});
	}, RENEW_EVERY_MS);
	renew.unref?.();

	try {
		return await inner();
	} finally {
		clearInterval(renew);
		await store.release(holder);
	}
}
