import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { disconnect } from 'lib/connected_services/accounts.ts';
import {
	clearConnectionDeclined,
	recordConnectionDeclined
} from 'lib/end_users/service.ts';
import { eventBus } from 'lib/event_bus.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import {
	admin,
	postDisconnect,
	seededAccount,
	signedInPerson
} from '../connected_services/harness.ts';
import { signedInAccountIds } from '../federation/harness.ts';
import {
	keptAccounts,
	linkedProject,
	project,
	signInThrough,
	upstreamPerson,
	type Linked
} from './harness.ts';

/* A sign-in that kept an account, then the person's own disconnect of it as the account page makes it. */
async function keptThenDisconnectedByThePerson(linked: Linked) {
	const claims = upstreamPerson();
	const { accountId } = await signInThrough(linked, claims);
	const person = present(accountId, 'the person');
	const [account] = await keptAccounts(person);
	const result = await disconnect({
		bucket: await project(),
		accountId: person,
		connectedAccountId: present(account, 'the account')._id,
		by: 'person'
	});
	await recordConnectionDeclined(
		DEFAULT_BUCKET_ID,
		person,
		present(result.account, 'what was disconnected')
	);
	return { claims, person };
}

/**
 * @proves A person who disconnects an account a sign-in kept stays disconnected through any number of later sign-ins
 * until they connect it again themselves, while an administrator's removal is not taken as the person's choice.
 */
describe('a person who disconnected an account kept from sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('is remembered as declining that account when they disconnect it on their account page', async () => {
		const linked = await linkedProject();
		const person = await signedInPerson();
		const account = await seededAccount(person, linked.service);

		await postDisconnect(person.browser, account._id);

		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(person.accountId);
		expect(stored?.connectionsDeclined).toEqual([
			{ serviceId: linked.service.id, upstreamId: account.upstreamId }
		]);
	});

	it('is not connected again by later sign-ins, and still signs in', async () => {
		const linked = await linkedProject();
		const { claims, person } = await keptThenDisconnectedByThePerson(linked);
		const reasons: string[] = [];
		const listen = (event: { reason: string }) => reasons.push(event.reason);
		eventBus.on('connected_account.refused', listen);

		try {
			await signInThrough(linked, claims);
			await signInThrough(linked, claims);
		} finally {
			eventBus.off('connected_account.refused', listen);
		}

		expect(signedInAccountIds()).toContain(person);
		expect(await keptAccounts(person)).toEqual([]);
		expect(reasons).toEqual(['declined', 'declined']);
	});

	it('is connected by sign-ins again once they connect that account themselves', async () => {
		const linked = await linkedProject();
		const { claims, person } = await keptThenDisconnectedByThePerson(linked);

		await clearConnectionDeclined(DEFAULT_BUCKET_ID, person, {
			serviceId: linked.service.id,
			upstreamId: String(claims.sub)
		});
		await signInThrough(linked, claims);

		expect((await keptAccounts(person)).map((a) => a.upstreamId)).toEqual([
			String(claims.sub)
		]);
	});

	it('is connected again by the next sign-in after an administrator removed the account', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const { accountId } = await signInThrough(linked, claims);
		const person = present(accountId, 'the person');
		const [account] = await keptAccounts(person);
		const result = await disconnect({
			bucket: await project(),
			accountId: person,
			connectedAccountId: present(account, 'the account')._id,
			by: 'administrator'
		});

		await signInThrough(linked, claims);

		expect(result.account).toBeUndefined();
		expect(await keptAccounts(person)).toHaveLength(1);
	});

	it('never shows the list to an administrator reading the person', async () => {
		const linked = await linkedProject();
		const { person } = await keptThenDisconnectedByThePerson(linked);
		const cookie = await cookieFor(await createAdministrator('super'));

		const answer = await admin(
			cookie,
			'GET',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/users/${person}`
		);

		expect(answer.status).toBe(200);
		expect(JSON.stringify(answer.json)).not.toContain('connectionsDeclined');
	});

	it('remembers at most fifty declined accounts, dropping the oldest', async () => {
		const linked = await linkedProject();
		const { person } = await keptThenDisconnectedByThePerson(linked);

		for (let index = 0; index < 50; index += 1) {
			await recordConnectionDeclined(DEFAULT_BUCKET_ID, person, {
				serviceId: linked.service.id,
				upstreamId: `later-${index}`
			});
		}

		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(person);
		const list = stored?.connectionsDeclined ?? [];
		expect(list).toHaveLength(50);
		expect(list[0]?.upstreamId).toBe('later-0');
		expect(list.at(-1)?.upstreamId).toBe('later-49');
	});
});
