import {
	getProjectStore,
	getBucketStore,
	getGroupStore,
	adapter
} from '../adapters/index.js';
import { Client } from '../models/client.js';
import { ISSUER } from '../configs/env.js';
import {
	ADMIN_PROJECT_ID,
	ADMIN_CLIENT_ID,
	UNASSIGNED_GROUP_ID,
	SYSTEM_GROUP_NAME
} from './consts.js';
import { ADMIN_MCP_CLIENT_ID } from '../mcp/consts.js';
import {
	ADMIN_BUCKET_SEED,
	ADMIN_MCP_CLIENT_SEED,
	ADMIN_PROJECT_SEED,
	DEFAULT_BUCKET_SEED,
	SYSTEM_GROUP_SEED,
	adminConsoleClientSeed
} from '../consts/admin_seed.js';

/*
 * Seeds a fresh instance through the store abstractions, which makes this the backend-agnostic path —
 * it works against whichever datastore `lib/adapters/index.ts` selected, in-memory included.
 *
 * The values it writes come from `lib/consts/admin_seed.ts` and are shared with `database/mongodb.ts`,
 * which writes the same documents through the raw driver because a one-shot script deliberately avoids
 * this module graph. The mechanisms differ on purpose; the values are declared once, so a seed change
 * can no longer land in the copy production never runs.
 */
export async function ensureAdminSeed(): Promise<void> {
	const groups = getGroupStore();
	if (!(await groups.find(UNASSIGNED_GROUP_ID))) {
		await groups.create({
			_id: UNASSIGNED_GROUP_ID,
			name: SYSTEM_GROUP_NAME,
			...SYSTEM_GROUP_SEED,
			members: [...SYSTEM_GROUP_SEED.members]
		});
	}

	const buckets = getBucketStore();
	/*
	 * A reserved bucket's slug is repaired on an existing record, unlike every other seeded field.
	 *
	 * The rest of a seed is a starting value an operator may edit, so re-running must not undo their
	 * work — hence the create-if-absent shape around it. A slug is not that: it is the path component
	 * of an issuer identifier this server addresses itself by and the console authenticates against,
	 * and it is fixed at creation everywhere else. Left alone, a deployment provisioned before
	 * addresses existed would keep two buckets with no address while a fresh one had them — the drift
	 * re-running this exists to prevent.
	 *
	 * `repairReservedSlug` rather than `update`, which has no `slug` to give: it writes only where
	 * there is nothing to overwrite, so re-running this can never turn into a rename.
	 * `database/mongodb.ts` states the same rule beside its own seed.
	 */
	async function ensureReservedBucket(
		seed: typeof ADMIN_BUCKET_SEED | typeof DEFAULT_BUCKET_SEED
	) {
		const existing = await buckets.find(seed._id);
		if (!existing) {
			await buckets.create({
				...seed,
				roles: [...seed.roles],
				federation: [...seed.federation]
			});
			return;
		}
		await buckets.repairReservedSlug(seed._id, seed.slug);
	}

	await ensureReservedBucket(ADMIN_BUCKET_SEED);
	await ensureReservedBucket(DEFAULT_BUCKET_SEED);

	const projects = getProjectStore();
	const existingAdminProject = await projects.find(ADMIN_PROJECT_ID);
	if (!existingAdminProject) {
		await projects.create({
			...ADMIN_PROJECT_SEED,
			clientIds: [...ADMIN_PROJECT_SEED.clientIds]
		});
	} else {
		/*
		 * An existing deployment's admin project predates the MCP agent client. Without adding the id the
		 * client exists but belongs to no project, `resolveBucketForClient` routes it to the default
		 * bucket, and an administrator cannot sign an agent in.
		 */
		const existingClientIds = existingAdminProject.clientIds ?? [];
		const missing = ADMIN_PROJECT_SEED.clientIds.filter(
			(id) => !existingClientIds.includes(id)
		);
		if (missing.length > 0) {
			await projects.update(ADMIN_PROJECT_ID, {
				clientIds: [...existingClientIds, ...missing]
			});
		}
	}

	if (!(await Client.tryFind(ADMIN_MCP_CLIENT_ID))) {
		await adapter('Client').upsert(ADMIN_MCP_CLIENT_ID, {
			...ADMIN_MCP_CLIENT_SEED,
			grantTypes: [...ADMIN_MCP_CLIENT_SEED.grantTypes],
			responseTypes: [...ADMIN_MCP_CLIENT_SEED.responseTypes],
			redirectUris: [...ADMIN_MCP_CLIENT_SEED.redirectUris]
		});
	}

	if (!(await Client.tryFind(ADMIN_CLIENT_ID))) {
		await adapter('Client').upsert(
			ADMIN_CLIENT_ID,
			adminConsoleClientSeed(ISSUER)
		);
	}
}
