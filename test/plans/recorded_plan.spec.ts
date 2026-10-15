import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import {
	call,
	createProject,
	freshSlug,
	idOf,
	storeCatalogue,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

async function planIdOf(id: string): Promise<string | undefined> {
	return (await getBucketStore().find(id))?.planId;
}

const [free] = BUILT_IN_PLANS;
const starter = {
	...free,
	id: 'starter',
	name: 'Starter',
	default: true,
	features: { ...free.features, customSlug: true }
};

/**
 * @proves A project records the plan it is on when it is created, so making another plan the default moves no
 * existing project; a System-team project carries no plan, and gets the default once it leaves that team.
 */
describe('the plan a project records', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
	});

	it('records the default plan on a team project whether or not plans are enforced', async () => {
		await withPlans(operator, false);
		const off = idOf(
			await createProject(await tenant(), { slug: freshSlug('off') })
		);
		await withPlans(operator, true);
		const on = idOf(await createProject(await tenant()));
		await withPlans(operator, false);

		expect([await planIdOf(off), await planIdOf(on)]).toEqual(['free', 'free']);
	});

	it('records no plan on a System-team project', async () => {
		const id = idOf(
			await createProject(operator, {
				teamId: UNASSIGNED_GROUP_ID,
				slug: freshSlug('sys')
			})
		);

		expect(await planIdOf(id)).toBeUndefined();
	});

	it('leaves existing projects on their plan when another plan becomes the default', async () => {
		const owner = await tenant();
		const before = idOf(
			await createProject(owner, { slug: freshSlug('before') })
		);
		await storeCatalogue([{ ...free, default: false }, starter]);
		const after = idOf(
			await createProject(owner, { slug: freshSlug('after') })
		);
		await storeCatalogue([...BUILT_IN_PLANS]);

		expect([await planIdOf(before), await planIdOf(after)]).toEqual([
			'free',
			'starter'
		]);
	});

	it('gives a System-team project the default plan when it moves to a team', async () => {
		const owner = await tenant();
		const id = idOf(
			await createProject(operator, {
				teamId: UNASSIGNED_GROUP_ID,
				slug: freshSlug('moving')
			})
		);

		const moved = await call(
			'PUT',
			`/admin/api/projects/${id}/owner`,
			operator.cookie,
			{ teamId: owner.teamId, confirm: true }
		);

		expect(moved.status).toBe(200);
		expect(await planIdOf(id)).toBe('free');
	});
});
