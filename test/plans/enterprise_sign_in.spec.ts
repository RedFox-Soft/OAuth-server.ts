import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import { mock } from '../fetch_mock.ts';
import { microsoftStub } from '../federation/recognised_stubs.ts';
import {
	call,
	createProject,
	idOf,
	refusalOf,
	storeCatalogue,
	storeFree,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

const MS_CLIENT = '00001111-aaaa-2222-bbbb-3333cccc4444';

function connect(caller: Caller, id: string, body: Record<string, unknown>) {
	return call('POST', `/admin/api/projects/${id}/federation`, caller.cookie, {
		clientSecret: 'upstream-secret',
		...body
	});
}

/* Whether the plan, rather than anything else about the request, refused it. */
function refusedByPlan(answer: { status: number; body: unknown }): boolean {
	return (
		answer.status === 409 &&
		(answer.body as { code?: string }).code === 'plan_limit'
	);
}

const SOCIAL: [string, Record<string, unknown>][] = [
	[
		'Google',
		{ catalogueId: 'google', clientId: 'x.apps.googleusercontent.com' }
	],
	['Apple', { catalogueId: 'apple', clientId: 'com.example.web' }],
	['GitHub', { catalogueId: 'github', clientId: 'Iv1.0123456789abcdef' }],
	[
		'Microsoft for every account',
		{ catalogueId: 'microsoft', tenant: 'common', clientId: MS_CLIENT }
	],
	[
		'Microsoft for any organisation',
		{ catalogueId: 'microsoft', tenant: 'organizations', clientId: MS_CLIENT }
	],
	[
		'Microsoft for personal accounts',
		{ catalogueId: 'microsoft', tenant: 'consumers', clientId: MS_CLIENT }
	]
];

const ENTERPRISE: [string, Record<string, unknown>][] = [
	[
		'a generic OpenID Connect provider',
		{
			id: 'corp',
			displayName: 'Corp',
			issuer: 'https://idp.corp.example',
			clientId: 'corp-app'
		}
	],
	[
		'Microsoft for one organisation, by its id',
		{
			catalogueId: 'microsoft',
			tenant: '72f988bf-86f1-41af-91ab-2d7cd011db47',
			clientId: MS_CLIENT
		}
	],
	[
		'Microsoft for one organisation, by its domain',
		{ catalogueId: 'microsoft', tenant: 'contoso.com', clientId: MS_CLIENT }
	],
	[
		'Microsoft for one organisation, by its issuer',
		{
			id: 'ms-corp',
			displayName: 'Contoso',
			issuer: 'https://login.microsoftonline.com/contoso.com/v2.0',
			clientId: MS_CLIENT
		}
	]
];

/**
 * @proves On a plan without enterprise sign-in, a project connects Google, Apple, GitHub and Microsoft open to every
 * account, while a generic OpenID Connect provider and Microsoft bound to one organisation are refused with the plan
 * named, at creation and by changing a provider to one; a super administrator and an instance with plans off are not
 * limited.
 */
describe('which sign-in providers a project’s plan admits', () => {
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

	afterEach(() => {
		mock.restore();
	});

	for (const [label, body] of SOCIAL) {
		it(`does not refuse ${label}`, async () => {
			const owner = await tenant();
			const id = idOf(await createProject(owner));

			expect(refusedByPlan(await connect(owner, id, body))).toBe(false);
		});
	}

	for (const [label, body] of ENTERPRISE) {
		it(`refuses ${label}, naming the plan`, async () => {
			const owner = await tenant();
			const id = idOf(await createProject(owner));

			const refusal = refusalOf(await connect(owner, id, body));

			expect(refusal.limit).toEqual({
				name: 'enterpriseSignIn',
				plan: { id: 'free', name: 'Free' }
			});
			expect((await getBucketStore().find(id))?.federation).toEqual([]);
		});
	}

	it('refuses changing a Microsoft provider from every account to one organisation', async () => {
		const owner = await tenant();
		const id = idOf(await createProject(owner));
		const stub = await microsoftStub('common');
		stub.expectTemplatedDiscovery();
		const created = await connect(owner, id, {
			catalogueId: 'microsoft',
			tenant: 'common',
			clientId: stub.clientId
		});

		const changed = await call(
			'PATCH',
			`/admin/api/projects/${id}/federation/microsoft`,
			owner.cookie,
			{ tenant: 'contoso.com' }
		);

		expect(created.status).toBe(201);
		expect(refusalOf(changed).limit.name).toBe('enterpriseSignIn');
	});

	it('admits enterprise sign-in on a plan that includes it, for a super administrator, and with plans off', async () => {
		const [, generic] = ENTERPRISE[0];
		const owner = await tenant();
		const id = idOf(await createProject(owner));

		const byOperator = await connect(operator, id, generic);
		await storeFree({}, { enterpriseSignIn: true });
		const onLargerPlan = await connect(owner, id, generic);
		await storeCatalogue([...BUILT_IN_PLANS]);
		await withPlans(operator, false);
		const plansOff = await connect(owner, id, generic);

		expect([byOperator, onLargerPlan, plansOff].map(refusedByPlan)).toEqual([
			false,
			false,
			false
		]);
	});
});
