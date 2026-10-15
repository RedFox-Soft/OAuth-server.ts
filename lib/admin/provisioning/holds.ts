import { Elysia } from 'elysia';

import {
	getProvisioningConnectionStore,
	getProvisioningRefusalStore
} from '../../adapters/index.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { visibleBuckets } from '../buckets/visible.js';
import { isScheduledForDeletion } from '../../consts/bucket_deletion.js';

/*
 * Every connection held by its mass-deprovisioning guard in the buckets this administrator's bucket list
 * shows them (specs/088 R8). A hold means removals are not happening — people who should have lost access
 * still have it — so the console shows the count on every page rather than only inside the right bucket.
 *
 * Over the same set the bucket list shows, read by the same function, so a badge never counts a hold the
 * list cannot lead to. Any administrator may read it; a bucket they cannot see contributes nothing.
 */

export interface HeldConnectionView {
	projectId: string;
	projectName: string;
	connectionId: string;
	displayName: string;
	/* When the hold began. */
	since: string;
	/* How many removals the hold has refused so far — what a release would let through. */
	refused: number;
}

export interface HeldConnectionsView {
	count: number;
	connections: HeldConnectionView[];
}

export const provisioningHoldRoutes = new Elysia({
	name: 'admin-provisioning-holds'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/provisioning-holds',
		async ({ admin }): Promise<HeldConnectionsView> => {
			const ctx = assertAuth(admin);
			const [buckets, held] = await Promise.all([
				visibleBuckets(ctx),
				getProvisioningConnectionStore().listHeld()
			]);
			/*
			 * A scheduled bucket's holds are left out (specs/090 FR-012): its directory reaches nobody while
			 * it is off, and every change to the connection is refused until it is restored, so a hold there
			 * is nothing an administrator can act on.
			 */
			const names = new Map(
				buckets
					.filter((b) => !isScheduledForDeletion(b))
					.map((b) => [b._id, b.name])
			);
			const visible = held
				.filter((c) => names.has(c.bucketId))
				.sort((a, b) => a.hold.since.getTime() - b.hold.since.getTime());
			/* One count per held connection; holds are few, and each is something an administrator must act on. */
			const refused = await Promise.all(
				visible.map(
					async (c) =>
						(
							await getProvisioningRefusalStore().list(
								c._id,
								c.tallyEpoch ?? 0,
								0
							)
						).total
				)
			);
			const connections = visible.map((c, i) => ({
				projectId: c.bucketId,
				projectName: names.get(c.bucketId) ?? c.bucketId,
				connectionId: c._id,
				displayName: c.displayName,
				since: c.hold.since.toISOString(),
				refused: refused[i] ?? 0
			}));
			return { count: connections.length, connections };
		}
	);
