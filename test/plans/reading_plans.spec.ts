import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import type { PlanView } from 'lib/plans/view.ts';
import {
	call,
	createProject,
	freshSlug,
	idOf,
	storeCatalogue,
	storeFree,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

interface Summary {
	plan?: PlanView | null;
}

interface Me {
	can: {
		nameSlug?: boolean;
		projects?: { count: number; max: number } | null;
		teams?: { count: number; max: number } | null;
	};
}

interface Usage {
	projects: {
		projectId: string;
		plan?: { id: string; name: string } | null;
		warnings?: unknown[];
	}[];
}

async function summaryOf(caller: Caller, id: string): Promise<Summary> {
	return (await call('GET', `/admin/api/projects/${id}/summary`, caller.cookie))
		.body as Summary;
}

async function applications(caller: Caller, id: string, count: number) {
	for (let i = 0; i < count; i += 1) {
		await call('POST', `/admin/api/projects/${id}/clients`, caller.cookie, {
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
	}
}

async function canOf(caller: Caller): Promise<Me['can']> {
	return ((await call('GET', '/admin/api/me', caller.cookie)).body as Me).can;
}

/**
 * @proves A project's team reads its plan, what it uses of each limit and a warning at 80% and at 100% on the
 * project and on the Usage page while plans are on, and nothing of plans while they are off; a super administrator
 * reads them always; a System project has none; and the caller's stated allowance agrees with what the routes then
 * admit.
 */
describe('reading a project’s plan', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
	});

	beforeEach(async () => {
		forgetBucketAddresses();
		await storeCatalogue([...BUILT_IN_PLANS]);
		await withPlans(operator, true);
	});

	it('warns near a limit at 80% and says it is reached at 100%', async () => {
		await storeFree({ applicationsPerProject: 5 });
		const owner = await tenant();
		const id = idOf(await createProject(owner));
		await applications(owner, id, 4);
		const near = (await summaryOf(owner, id)).plan;
		await applications(owner, id, 1);
		const reached = (await summaryOf(owner, id)).plan;

		expect(near?.usage.applications).toBe(4);
		expect(near?.warnings).toEqual([
			{ limit: 'applicationsPerProject', level: 'near' }
		]);
		expect(reached?.warnings).toEqual([
			{ limit: 'applicationsPerProject', level: 'reached' }
		]);
		expect(reached?.name).toBe('Free');
	});

	it('shows a tenant nothing of plans while they are off, and a super administrator the plan regardless', async () => {
		const owner = await tenant();
		const id = idOf(await createProject(owner));
		await withPlans(operator, false);

		expect('plan' in (await summaryOf(owner, id))).toBe(false);
		expect((await summaryOf(operator, id)).plan?.id).toBe('free');
	});

	it('gives a System project no plan', async () => {
		expect((await summaryOf(operator, DEFAULT_BUCKET_ID)).plan).toBeNull();
	});

	it('puts the plan and its warnings on the Usage page while plans are on, and nothing while off', async () => {
		await storeFree({ applicationsPerProject: 1 });
		const owner = await tenant();
		const id = idOf(await createProject(owner));
		await applications(owner, id, 1);
		const on = (await call('GET', '/admin/api/activity', owner.cookie))
			.body as Usage;
		await withPlans(operator, false);
		const off = (await call('GET', '/admin/api/activity', owner.cookie))
			.body as Usage;

		const row = on.projects.find((r) => r.projectId === id);
		expect(row?.plan).toEqual({ id: 'free', name: 'Free' });
		expect(row?.warnings).toEqual([
			{ limit: 'applicationsPerProject', level: 'reached' }
		]);
		expect(off.projects.find((r) => r.projectId === id)?.plan).toBeUndefined();
	});

	it('states a tenant’s project allowance and slug rule as the routes then apply them', async () => {
		const owner = await tenant();
		const before = await canOf(owner);
		idOf(await createProject(owner));
		idOf(await createProject(owner));
		const after = await canOf(owner);
		const refused = await createProject(owner);

		expect(before.nameSlug).toBe(false);
		expect(before.projects).toMatchObject({ count: 0, max: 2 });
		expect(after.projects).toMatchObject({ count: 2, max: 2 });
		expect(refused.status).toBe(409);
	});

	it('states a tenant’s team allowance as the route then applies it', async () => {
		const owner = await tenant();
		const can = await canOf(owner);
		const refused = await call('POST', '/admin/api/teams', owner.cookie, {
			name: 'Another'
		});

		expect(can.teams).toEqual({ count: 1, max: 1 });
		expect(refused.status).toBe(409);
	});

	it('states no limit while plans are off, and a named slug is accepted', async () => {
		await withPlans(operator, false);
		const owner = await tenant();
		const can = await canOf(owner);

		expect([can.nameSlug, can.projects, can.teams]).toEqual([true, null, null]);
		expect(
			(await createProject(owner, { slug: freshSlug('off') })).status
		).toBe(201);
	});
});
