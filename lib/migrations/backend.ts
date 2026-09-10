import { hostname } from 'node:os';

import type { BackendName } from '../adapters/selectBackend.js';
import { withLease } from './lock.js';
import type { MigrationBackend } from './runner.js';

/*
 * Builds the runner's backend from the selected adapter's stores.
 *
 * Lives here rather than in either script because both need it: `database/migrate.ts` to apply, and
 * `database/postgres.ts` (with its MongoDB sibling) to baseline a freshly provisioned database. Two
 * copies of the same wiring is two places for the lock to be forgotten.
 *
 * Takes the stores as arguments rather than importing `lib/adapters/index.js` itself. That module
 * constructs every store as a side effect of being imported and reaches the configuration, which
 * reads from the datastore — so a provisioning script must import it only after the tables exist, and
 * this module must not force that decision on its callers.
 */

export interface MigrationStores {
	readAll: MigrationBackend['readAll'];
	write: MigrationBackend['write'];
	lease: Parameters<typeof withLease>[0];
}

/* Identifies the holder in a contention message, so an operator can tell their own stuck run from a
 * colleague's. Not a security boundary — nothing authorises on it. */
export function holderId(): string {
	return `${hostname()}:${process.pid}`;
}

export function migrationBackend(
	name: Exclude<BackendName, 'memory'>,
	stores: MigrationStores,
	handle: unknown = undefined
): MigrationBackend {
	const holder = holderId();

	return {
		name,
		handle,
		readAll: stores.readAll,
		write: stores.write,
		withLock: (inner) => withLease(stores.lease, holder, inner)
	};
}
