import { beforeAll, beforeEach, describe, expect, it, spyOn } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	getBucketStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { UserStore as MemoryUserStore } from 'lib/adapters/memory/userStore.ts';
import {
	CODE_CLIENT,
	PersonBrowser,
	WRONG,
	activityOf,
	from,
	only,
	person,
	project,
	typeCode,
	typePassword
} from './helpers.ts';

let cookie: string;
let bucketId: string;

/**
 * @proves A person's failed and stopped sign-ins are kept where the account was found, with a reason true later and
 * what the person was shown; an attempt on an unknown address keeps nothing and costs what any attempt costs.
 */
describe("a person's failed sign-ins", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
		from('203.0.113.9');
	});

	it('shows a wrong password for a known account as a refusal with what the person saw', async () => {
		const anna = await person(bucketId);
		await typePassword(new PersonBrowser(), anna.email, WRONG);
		await typePassword(new PersonBrowser(), anna.email, WRONG);

		const row = only(
			(await activityOf(cookie, bucketId, anna.accountId)).rows,
			'row'
		);
		expect({
			outcome: row.words.outcome,
			reason: row.words.reason,
			saw: row.words.sawText,
			count: row.count,
			address: row.address
		}).toEqual({
			outcome: 'Refused',
			reason: 'Wrong password',
			saw: 'Invalid username or password',
			count: 2,
			address: '203.0.113.9'
		});
	});

	it('writes nothing to the store until the minute’s write', async () => {
		const anna = await person(bucketId);
		await typePassword(new PersonBrowser(), anna.email, WRONG);

		const held = await getPersonActivityStore().listForPerson(
			bucketId,
			anna.accountId,
			{
				limit: 10,
				now: new Date()
			}
		);
		expect(held.rows).toEqual([]);
	});

	it('shows the right password into a locked account as refused for the lock', async () => {
		const anna = await person(bucketId);
		const locked = await admin(
			'POST',
			`/admin/api/projects/${bucketId}/users/${anna.accountId}/lock`,
			cookie,
			{ reason: 'Laptop stolen' }
		);
		expect(locked.status).toBe(200);
		await typePassword(new PersonBrowser(), anna.email);

		const row = only(
			(await activityOf(cookie, bucketId, anna.accountId)).rows,
			'row'
		);
		expect([row.reason, row.words.reason, row.words.sawText]).toEqual([
			'locked',
			'Right password, but the account is locked',
			'Invalid username or password'
		]);
	});

	it('shows the right password into a deactivated account as refused for the deactivation', async () => {
		const anna = await person(bucketId);
		await getUserStore(bucketId).update(anna.accountId, { active: false });
		await typePassword(new PersonBrowser(), anna.email);

		const row = only(
			(await activityOf(cookie, bucketId, anna.accountId)).rows,
			'row'
		);
		expect(row.words.reason).toBe(
			'Right password, but the account is deactivated'
		);
	});

	it('shows a wrong code as a refusal', async () => {
		const anna = await person(bucketId, { code: true });
		const browser = new PersonBrowser();
		const codePage = await typePassword(browser, anna.email);
		await typeCode(browser, codePage.url, '000000');

		const row = only(
			(await activityOf(cookie, bucketId, anna.accountId)).rows,
			'row'
		);
		expect([row.words.reason, row.words.sawText]).toEqual([
			'Wrong code from the authenticator app',
			'Invalid code'
		]);
	});

	it('shows a sign-in stopped because the app asks for a code', async () => {
		const anna = await person(bucketId);
		await typePassword(new PersonBrowser(), anna.email, undefined, CODE_CLIENT);

		const rows = (await activityOf(cookie, bucketId, anna.accountId)).rows;
		const stopped = only(
			rows.filter((row) => row.outcome === 'refused'),
			'stop'
		);
		expect(stopped.words.reason).toBe(
			'Billing asks for a code; this sign-in gave none'
		);
	});

	it('shows a sign-in stopped because the address is not verified', async () => {
		await getBucketStore().update(bucketId, {
			emailVerificationRequired: true
		});
		const anna = await person(bucketId);
		await getUserStore(bucketId).update(anna.accountId, { verified: false });
		await typePassword(new PersonBrowser(), anna.email);

		const row = only(
			(await activityOf(cookie, bucketId, anna.accountId)).rows,
			'row'
		);
		expect(row.words.reason).toBe(
			'Right password, but the email address isn’t verified'
		);
	});
});

/**
 * @proves An attempt with an address nobody holds records nothing, and costs the datastore exactly what a wrong
 * password for a real account costs: recording does not tell an outsider which addresses exist.
 */
describe('a sign-in attempt on an unknown address', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
		from('203.0.113.9');
	});

	it('records nothing and costs the same reads as a known one', async () => {
		const anna = await person(bucketId);
		const reads = (['find', 'findByEmail', 'findMany'] as const).map((method) =>
			spyOn(MemoryUserStore.prototype, method)
		);
		const count = () =>
			reads.reduce((sum, spy) => sum + spy.mock.calls.length, 0);
		try {
			await typePassword(new PersonBrowser(), anna.email, WRONG);
			const known = count();
			for (const spy of reads) spy.mockClear();
			await typePassword(new PersonBrowser(), 'nobody@acme.test', WRONG);
			expect(count()).toBe(known);
		} finally {
			for (const spy of reads) spy.mockRestore();
		}

		const page = await activityOf(cookie, bucketId, anna.accountId);
		expect(page.rows.map((row) => row.reason)).toEqual(['wrong_password']);
	});
});
