import {
	adapter,
	getBucketStore,
	getGroupStore,
	getProtectedResourceStore
} from '../adapters/index.js';
import type { Group, UserBucket } from '../adapters/types.js';
import type { Plan } from '../consts/plans.js';
import { planOf } from './catalogue.js';

/*
 * The applications a bucket holds, as stored (specs/099). `operatorOnly` leaves out the ones that registered
 * themselves: those break nobody's integration that an administrator owns, never block a deletion, and are never
 * counted against a plan.
 */
export async function bucketClients(
	bucketId: string,
	operatorOnly = false
): Promise<{ clientId: string; registeredDynamically: boolean }[]> {
	const stored = await adapter('Client').findByIndexed('bucketId', bucketId);
	return stored
		.map((record) => ({
			clientId: String(record.clientId),
			registeredDynamically: record.registeredDynamically === true
		}))
		.filter((client) => !operatorOnly || !client.registeredDynamically)
		.sort((a, b) => a.clientId.localeCompare(b.clientId));
}

export interface BucketUsage {
	applications: number;
	apis: number;
}

export async function bucketUsage(bucketId: string): Promise<BucketUsage> {
	const [applications, apis] = await Promise.all([
		bucketClients(bucketId, true),
		getProtectedResourceStore().listByBucket(bucketId)
	]);
	return { applications: applications.length, apis: apis.length };
}

export function ownsGroup(group: Group, userId: string): boolean {
	return group.members.some(
		(member) => member.userId === userId && member.role === 'owner'
	);
}

/* A bucket counts toward its owners until it is scheduled for deletion, and again once it is restored. */
export function liveBuckets(buckets: readonly UserBucket[]): UserBucket[] {
	return buckets.filter((bucket) => bucket.deletion === undefined);
}

export interface Holdings {
	/* Buckets per plan id, over every team the administrator owns. */
	projects: Map<string, number>;
	regularTeams: number;
}

/*
 * What one administrator owns, for the per-administrator limits. `excluding` leaves out buckets about to be counted
 * as incoming, so a bucket moving between two teams of the same owner is not counted twice against them.
 */
export async function holdingsOf(
	userId: string,
	plans: readonly Plan[],
	excluding: ReadonlySet<string> = new Set()
): Promise<Holdings> {
	const owned = (await getGroupStore().listByMember(userId)).filter((group) =>
		ownsGroup(group, userId)
	);
	const projects = new Map<string, number>();
	for (const group of owned) {
		for (const bucket of liveBuckets(
			await getBucketStore().listByGroup(group._id)
		)) {
			if (excluding.has(bucket._id)) continue;
			const plan = planOf(bucket, plans);
			if (plan) projects.set(plan.id, (projects.get(plan.id) ?? 0) + 1);
		}
	}
	return {
		projects,
		regularTeams: owned.filter((group) => group.kind === 'regular').length
	};
}
