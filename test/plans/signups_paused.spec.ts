import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach,
	spyOn
} from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getActivityStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import { forgetSignUpReadings } from 'lib/plans/signups.ts';
import { elysia } from 'lib/index.ts';
import { mock } from '../fetch_mock.ts';
import { idpStub } from '../federation/idp_stub.ts';
import {
	get,
	provider,
	seedBucket,
	startInteraction,
	walk
} from '../federation/harness.ts';
import { atDay, startCounting } from '../activity/fixtures.ts';
import {
	call,
	storeCatalogue,
	storeFree,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

const CLIENT = 'plans-app';
const CLOSED = 'Not accepting new accounts';

let operator: Caller;
let owner: Caller;
let idpCount = 0;

/* A Free project of a tenant's team, open for registration and federated with a stub provider. */
async function project(): Promise<{
	bucketId: string;
	idp: Awaited<ReturnType<typeof idpStub>>;
}> {
	idpCount += 1;
	const idp = await idpStub(`https://idp-plans-${String(idpCount)}.test`);
	const bucketId = await seedBucket(CLIENT, {
		ownerGroupId: owner.teamId,
		planId: 'free',
		registrationOpen: true,
		federation: [provider(idp.origin, { emailTrusted: true })]
	});
	return { bucketId, idp };
}

async function activeUsers(bucketId: string, count: number): Promise<void> {
	for (let i = 0; i < count; i += 1) {
		await getActivityStore().mark({
			bucketId,
			accountId: `active-${String(i)}`,
			kind: 'local',
			provisioned: false,
			at: new Date()
		});
	}
}

async function postForm(
	path: string,
	cookie: string,
	fields: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			redirect: 'manual',
			headers: {
				cookie,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams(fields).toString()
		})
	);
	return { status: res.status, text: await res.text() };
}

/**
 * @proves At or over its plan's monthly-active-user cap a project stops creating accounts for people who sign
 * themselves up — registration and a federated first sign-in answer a page that names no plan or figure — and
 * keeps signing in everyone who has an account, keeps admitting users its administrators create, reopens when its
 * plan or the month changes, and stays open when the figure cannot be read.
 */
describe('a project at its monthly-active-user cap', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
		owner = await tenant();
	});

	beforeEach(async () => {
		await startCounting();
		forgetSignUpReadings();
		await storeFree({ monthlyActiveUsers: 2 });
		await withPlans(operator, true);
	});

	afterEach(() => {
		mock.restore();
	});

	it('answers registration, both ways, with the closed page and hides the register link', async () => {
		const { bucketId } = await project();
		await activeUsers(bucketId, 2);
		const { uid, cookie } = await startInteraction(CLIENT);

		const form = await get(`/ui/${uid}/registration`, cookie);
		const submitted = await postForm(`/ui/${uid}/registration`, cookie, {
			email: 'new@plans.test',
			password: 'a-long-password',
			confirmPassword: 'a-long-password'
		});
		const login = await get(`/ui/${uid}/login`, cookie);

		expect([form.status, submitted.status]).toEqual([403, 403]);
		expect(form.text).toContain(CLOSED);
		expect(form.text).not.toMatch(/Free|100,000|plan/);
		expect(login.text).not.toContain(`/ui/${uid}/registration`);
		expect(await getUserStore(bucketId).list()).toHaveLength(0);
	});

	it('refuses a federated first sign-in that would create an account, with the same page', async () => {
		const { bucketId, idp } = await project();
		await activeUsers(bucketId, 2);
		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction(CLIENT);

		const { callback, complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'stranger@plans.test', email_verified: true }
		});
		const page = complete ?? callback;

		expect(page.status).toBe(403);
		expect(page.text).toContain(CLOSED);
		expect(await getUserStore(bucketId).list()).toHaveLength(0);
	});

	it('signs in a person who has an account, by password and through the provider', async () => {
		const { bucketId, idp } = await project();
		await activeUsers(bucketId, 2);
		await getUserStore(bucketId).create(
			'member@plans.test',
			await Bun.password.hash('correct-horse'),
			true
		);

		const first = await startInteraction(CLIENT);
		const byPassword = await postForm(`/ui/${first.uid}/login`, first.cookie, {
			username: 'member@plans.test',
			password: 'correct-horse'
		});
		idp.expectDiscovery();
		const second = await startInteraction(CLIENT);
		const { complete } = await walk(second.uid, second.cookie, {
			idp,
			claims: { email: 'member@plans.test', email_verified: true }
		});

		expect(byPassword.status).toBe(303);
		expect(complete?.status).toBe(303);
		expect(await getUserStore(bucketId).list()).toHaveLength(1);
	});

	it('admits an end user an administrator creates', async () => {
		const { bucketId } = await project();
		await activeUsers(bucketId, 2);

		const created = await call(
			'POST',
			`/admin/api/projects/${bucketId}/users`,
			owner.cookie,
			{ email: 'made@plans.test', password: 'a-long-password' }
		);

		expect(created.status).toBe(201);
	});

	it('reopens when the project moves to a plan without the cap', async () => {
		const { bucketId } = await project();
		await activeUsers(bucketId, 2);
		const closed = await startInteraction(CLIENT);
		const before = await get(`/ui/${closed.uid}/registration`, closed.cookie);
		await storeCatalogue([
			...BUILT_IN_PLANS.map((plan) => ({
				...plan,
				limits: { ...plan.limits, monthlyActiveUsers: 2 }
			})),
			{
				...BUILT_IN_PLANS[0],
				id: 'big',
				name: 'Big',
				default: false,
				limits: { ...BUILT_IN_PLANS[0].limits, monthlyActiveUsers: null }
			}
		]);
		await getBucketStore().setPlan(bucketId, 'big');

		const open = await startInteraction(CLIENT);
		const after = await get(`/ui/${open.uid}/registration`, open.cookie);

		expect([before.status, after.status]).toEqual([403, 200]);
	});

	it('reopens when a new month begins', async () => {
		const { bucketId } = await project();
		await activeUsers(bucketId, 2);
		const next = new Date();
		next.setUTCMonth(next.getUTCMonth() + 1, 2);
		const restore = atDay(next.toISOString());
		try {
			const { uid, cookie } = await startInteraction(CLIENT);
			expect((await get(`/ui/${uid}/registration`, cookie)).status).toBe(200);
		} finally {
			restore();
		}
	});

	it('stays open when the figure cannot be read', async () => {
		await project();
		spyOn(getActivityStore(), 'count').mockRejectedValue(
			new Error('store down')
		);
		spyOn(console, 'error').mockImplementation(() => {});
		const { uid, cookie } = await startInteraction(CLIENT);

		expect((await get(`/ui/${uid}/registration`, cookie)).status).toBe(200);
	});

	it('closes nothing while plans are off', async () => {
		const { bucketId } = await project();
		await activeUsers(bucketId, 2);
		await withPlans(operator, false);
		const { uid, cookie } = await startInteraction(CLIENT);

		expect((await get(`/ui/${uid}/registration`, cookie)).status).toBe(200);
	});

	it('tells an administrator trying a sign-in that it would be refused because sign-ups are paused', async () => {
		const { bucketId, idp } = await project();
		await activeUsers(bucketId, 2);
		idp.expectDiscovery();
		const tryPath = `/admin/api/projects/${bucketId}/federation/acme-sso/try`;

		const started = await call('POST', tryPath, operator.cookie);
		const { tryRef, authorizationUrl } = started.body as {
			tryRef: string;
			authorizationUrl: string;
		};
		await idp.answerToken(new URL(authorizationUrl), {
			email: 'stranger@plans.test',
			email_verified: true
		});
		const state = new URL(authorizationUrl).searchParams.get('state') ?? '';
		await get(
			`/federation/callback?${new URLSearchParams({ code: 'upstream-code', state }).toString()}`
		);
		const read = await call('GET', `${tryPath}/${tryRef}`, operator.cookie);

		expect(started.status).toBe(201);
		expect(
			(read.body as { result?: { outcome?: unknown } }).result?.outcome
		).toEqual({ kind: 'refuse', reason: 'signups_paused' });
		expect(await getUserStore(bucketId).list()).toHaveLength(0);
	});
});
