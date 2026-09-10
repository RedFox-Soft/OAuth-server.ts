import type { MigrationLease, MigrationLeaseStoreInstance } from '../types.js';

/*
 * The in-memory lease. Single-process by construction, so the atomicity the persistent backends have
 * to buy with a conditional write comes free — nothing interleaves between the check and the set.
 */
export class MigrationLeaseStore implements MigrationLeaseStoreInstance {
	private lease: MigrationLease | null = null;

	async read(): Promise<MigrationLease | null> {
		return this.lease;
	}

	async acquire(holder: string, expiresAt: Date): Promise<boolean> {
		const held = this.lease;
		const free =
			held === null ||
			held.holder === holder ||
			held.expiresAt.getTime() <= Date.now();

		if (!free) return false;
		this.lease = { holder, expiresAt };
		return true;
	}

	async release(holder: string): Promise<void> {
		if (this.lease?.holder === holder) this.lease = null;
	}
}
