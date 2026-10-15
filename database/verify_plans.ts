import type {
	PlanCatalogueStoreInstance,
	UserBucketStoreInstance
} from '../lib/adapters/types.js';
import { BUILT_IN_PLANS } from '../lib/consts/plans.js';

/*
 * Plans (specs/102) against a real datastore: the catalogue singleton round-trips through the shared settings area,
 * a bucket's plan is written by `setPlan` and read back, and the migration that records Free on every project
 * outside the System team gives a tenant's bucket Free, leaves a System bucket and an already-recorded plan alone,
 * and changes nothing the second time. Shared by verify_mongodb.ts and verify_postgres.ts.
 */

type Check = (name: string, ok: boolean, detail?: string) => void;

export interface PlanHooks {
	buckets: UserBucketStoreInstance;
	catalogue: PlanCatalogueStoreInstance;
	/* One application of the migration's half for this backend; answers its report lines. */
	apply(): Promise<unknown>;
}

export async function verifyPlans(
	hooks: PlanHooks,
	stamp: string,
	check: Check
): Promise<void> {
	const starter = {
		...BUILT_IN_PLANS[0],
		id: 'starter',
		name: 'Starter',
		default: false,
		limits: { ...BUILT_IN_PLANS[0].limits, monthlyActiveUsers: null }
	};
	await hooks.catalogue.set({ plans: [...BUILT_IN_PLANS, starter] });
	const stored = await hooks.catalogue.get();
	check(
		'the plan catalogue round-trips, an unlimited value as null',
		// Deep equality, not the JSON text: jsonb stores an object's keys in an order of its own.
		Bun.deepEquals(stored, { plans: [...BUILT_IN_PLANS, starter] }),
		JSON.stringify(stored)
	);

	const tenant = await hooks.buckets.create({
		name: `fidelity-plan-tenant-${stamp}`,
		ownerGroupId: `fidelity-team-${stamp}`
	});
	const system = await hooks.buckets.create({
		name: `fidelity-plan-system-${stamp}`,
		ownerGroupId: 'unassigned'
	});
	const recorded = await hooks.buckets.create({
		name: `fidelity-plan-recorded-${stamp}`,
		ownerGroupId: `fidelity-team-${stamp}`,
		planId: 'starter'
	});

	await hooks.apply();
	const second = await hooks.apply();
	const [afterTenant, afterSystem, afterRecorded] = await Promise.all([
		hooks.buckets.find(tenant._id),
		hooks.buckets.find(system._id),
		hooks.buckets.find(recorded._id)
	]);
	check(
		'the record-plan migration gives a team’s project Free and leaves a System project and a recorded plan alone',
		afterTenant?.planId === 'free' &&
			afterSystem?.planId === undefined &&
			afterRecorded?.planId === 'starter',
		JSON.stringify([
			afterTenant?.planId,
			afterSystem?.planId,
			afterRecorded?.planId
		])
	);
	check(
		'a second application of the record-plan migration changes nothing',
		JSON.stringify(second) ===
			JSON.stringify(['projects given the Free plan: 0']),
		JSON.stringify(second)
	);

	const moved = await hooks.buckets.setPlan(tenant._id, 'starter');
	const reread = await hooks.buckets.find(tenant._id);
	check(
		'setPlan writes the plan and only the plan',
		moved?.planId === 'starter' &&
			reread?.planId === 'starter' &&
			reread.name === tenant.name &&
			reread.ownerGroupId === tenant.ownerGroupId,
		JSON.stringify(reread)
	);
}
