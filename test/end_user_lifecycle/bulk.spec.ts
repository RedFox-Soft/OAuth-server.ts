import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import type { EndUserPatch } from 'lib/adapters/types.ts';
import { ADMIN_SESSION_COOKIE, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import { createAdministrator } from '../administrators.ts';
import { sessionFor } from '../admin_session.ts';
import { shaped } from '../shape.ts';
import { adminCall } from './admin_call.ts';
import {
	adminCookie,
	defaultBucket,
	refresh,
	signIn,
	type SignedIn
} from './fixtures.ts';

const Results = Type.Object({
	results: Type.Array(
		Type.Object({
			id: Type.String(),
			outcome: Type.Union([
				Type.Literal('changed'),
				Type.Literal('skipped'),
				Type.Literal('failed')
			]),
			reason: Type.Optional(Type.String())
		})
	)
});

type Act = 'deactivate' | 'activate' | 'sign-out' | 'delete';

let setup: Setup;
let cookie: string;

function bulk(act: Act, userIds: string[], asCookie = cookie) {
	return adminCall(
		asCookie,
		'POST',
		`/admin/api/buckets/${DEFAULT_BUCKET_ID}/users/bulk/${act}`,
		{ userIds }
	);
}

async function resultsOf(
	act: Act,
	userIds: string[]
): Promise<Array<{ id: string; outcome: string; reason?: string }>> {
	const res = await bulk(act, userIds);
	expect(res.status).toBe(200);
	return shaped(Results, res.body).results.map(({ id, outcome, reason }) =>
		reason === undefined ? { id, outcome } : { id, outcome, reason }
	);
}

/* Every relying party in the session is told; each answers. */
function acceptLogouts(times: number): void {
	for (let i = 0; i < times; i++) {
		for (const host of [
			'https://client.example.com',
			'https://second-client.example.com'
		]) {
			mockHttp(host)
				.intercept({ path: '/backchannel_logout', method: 'POST' })
				.reply(200);
		}
	}
}

async function provisioned(): Promise<string> {
	const user = await createEndUser(
		await defaultBucket(),
		{ kind: 'connection', connectionId: 'conn-a' },
		{ id: nanoid(), email: `managed-${nanoid()}@x.io` },
		async () => {}
	);
	return user._id;
}

async function local(): Promise<string> {
	return (await getUserStore(DEFAULT_BUCKET_ID).create(`${nanoid()}@x.io`, 'h'))
		._id;
}

/* What the token endpoint answers the person's refresh token with now. */
async function refreshAnswer(user: SignedIn): Promise<unknown> {
	return (await refresh(user.refreshToken)).error?.value;
}

async function entriesFor(action: string, targetId: string) {
	return (await adminAuditStore.list({ action, targetId })).entries;
}

beforeAll(async () => {
	setup = await bootstrap(import.meta.url);
	await defaultBucket();
	cookie = await adminCookie();
});

afterEach(() => {
	try {
		mock.restore();
	} finally {
		assertNoPendingInterceptors();
	}
});

/**
 * @proves An administrator applies one act to a selection of people: each person is handled exactly as the
 * single act would handle them, with their own audit entry, people the act does not apply to are skipped with
 * the reason, one person's failure is theirs alone, and a repeat changes nothing already done.
 */
describe('acting on many people at once', () => {
	it('deactivates each local person, ending their access, and skips a directory’s person', async () => {
		const people = [
			await signIn(setup),
			await signIn(setup),
			await signIn(setup)
		];
		const managed = await provisioned();
		acceptLogouts(people.length);

		const results = await resultsOf('deactivate', [
			...people.map((p) => p.accountId),
			managed
		]);

		expect(results).toEqual([
			...people.map((p) => ({ id: p.accountId, outcome: 'changed' })),
			{ id: managed, outcome: 'skipped', reason: 'provisioned' }
		]);
		for (const person of people) {
			expect(await refreshAnswer(person)).toHaveProperty(
				'error',
				'invalid_grant'
			);
		}
	});

	it('records one entry per person changed, and none for a person skipped', async () => {
		const [a, b] = [await local(), await local()];
		const managed = await provisioned();

		await resultsOf('deactivate', [a, b, managed]);

		expect(
			(await entriesFor('enduser.bulk.deactivate', a)).map((e) => e.targetScope)
		).toEqual([DEFAULT_BUCKET_ID]);
		expect(
			(await entriesFor('enduser.bulk.deactivate', b)).map((e) => e.targetId)
		).toEqual([b]);
		expect(await entriesFor('enduser.bulk.deactivate', managed)).toEqual([]);
	});

	it('activates a deactivated person but leaves a locked one locked, and skips one already active', async () => {
		const [inactive, locked, active] = [
			await local(),
			await local(),
			await local()
		];
		await getUserStore(DEFAULT_BUCKET_ID).update(inactive, { active: false });
		await getUserStore(DEFAULT_BUCKET_ID).update(locked, {
			active: false,
			lockedLocally: { at: new Date(), by: 'someone', reason: 'compromise' }
		});

		const results = await resultsOf('activate', [inactive, locked, active]);

		expect(results).toEqual([
			{ id: inactive, outcome: 'changed' },
			{ id: locked, outcome: 'changed' },
			{ id: active, outcome: 'skipped', reason: 'already_active' }
		]);
		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(locked))?.lockedLocally
		).toBeDefined();
	});

	it('signs out a directory’s person along with local ones', async () => {
		const person = await signIn(setup);
		const managed = await provisioned();
		acceptLogouts(1);

		const results = await resultsOf('sign-out', [person.accountId, managed]);

		expect(results).toEqual([
			{ id: person.accountId, outcome: 'changed' },
			{ id: managed, outcome: 'changed' }
		]);
		expect(await refreshAnswer(person)).toHaveProperty(
			'error',
			'invalid_grant'
		);
	});

	it('deletes each person with everything issued to them', async () => {
		const person = await signIn(setup);
		acceptLogouts(1);

		const results = await resultsOf('delete', [person.accountId]);

		expect(results).toEqual([{ id: person.accountId, outcome: 'changed' }]);
		expect(await getUserStore(DEFAULT_BUCKET_ID).find(person.accountId)).toBe(
			null
		);
		expect(await refreshAnswer(person)).toHaveProperty(
			'error',
			'invalid_grant'
		);
	});

	it('skips an id the bucket does not hold', async () => {
		const absent = `absent-${nanoid()}`;

		expect(await resultsOf('delete', [absent])).toEqual([
			{ id: absent, outcome: 'skipped', reason: 'not_found' }
		]);
	});

	it('refuses more than a hundred people in one request', async () => {
		const ids = Array.from({ length: 101 }, () => nanoid());

		const res = await bulk('deactivate', ids);

		expect(res.status).toBe(422);
	});

	it('reports one person’s failure as theirs and changes the others', async () => {
		const [a, broken, c] = [await local(), await local(), await local()];
		const store = getUserStore(DEFAULT_BUCKET_ID);
		const update = store.update.bind(store);
		spyOn(store, 'update').mockImplementation(
			(id: string, patch: EndUserPatch) =>
				id === broken
					? Promise.reject(new Error('the datastore is unavailable'))
					: update(id, patch)
		);

		const results = await resultsOf('deactivate', [a, broken, c]);

		expect(results).toEqual([
			{ id: a, outcome: 'changed' },
			{
				id: broken,
				outcome: 'failed',
				reason: 'the datastore is unavailable'
			},
			{ id: c, outcome: 'changed' }
		]);
	});

	it('changes nothing already done when repeated', async () => {
		const [a, b] = [await local(), await local()];
		await resultsOf('deactivate', [a, b]);

		const again = await resultsOf('deactivate', [a, b]);

		expect(again).toEqual([
			{ id: a, outcome: 'skipped', reason: 'already_inactive' },
			{ id: b, outcome: 'skipped', reason: 'already_inactive' }
		]);
		expect(
			(await entriesFor('enduser.bulk.deactivate', a)).map((e) => e.targetId)
		).toEqual([a]);
	});

	it('refuses an administrator who may not manage the bucket’s people', async () => {
		const target = await local();
		const outsider = await createAdministrator();
		const outsiderCookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(outsider))._id}`;

		const res = await bulk('delete', [target], outsiderCookie);

		expect(res.status).toBe(403);
		expect(await getUserStore(DEFAULT_BUCKET_ID).find(target)).not.toBeNull();
	});
});
