import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { getPersonActivityStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import {
	PASSWORD,
	PersonBrowser,
	activityOf,
	from,
	only,
	person,
	project,
	signIn,
	typeCode,
	typePassword
} from './helpers.ts';

let cookie: string;
let bucketId: string;

async function signInRows(accountId: string) {
	const page = await activityOf(cookie, bucketId, accountId, {
		kind: 'signIn',
		outcome: 'let_in'
	});
	return page.rows;
}

/**
 * @proves Every successful sign-in is kept on the person's activity with the application, how they signed in, the
 * full network address this server attributed the caller to, and the browser and system family; "New address" marks
 * a sign-in from an address none of at least five earlier ones used.
 */
describe("a person's sign-ins", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
		from('203.0.113.9');
	});

	it('shows a successful sign-in with its application, method, address and device', async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);

		const row = only(await signInRows(anna.accountId), 'sign-in');
		expect({
			outcome: row.words.outcome,
			place: row.place.name,
			method: row.words.method,
			address: row.address,
			device: row.words.device,
			facts: row.facts
		}).toEqual({
			outcome: 'Let in',
			place: 'Acme web',
			method: 'Password',
			address: '203.0.113.9',
			device: 'Chrome on Windows',
			facts: null
		});
	});

	it('shows a sign-in with a code as a password and a code', async () => {
		const anna = await person(bucketId, { code: true });
		const browser = new PersonBrowser();
		const codePage = await typePassword(browser, anna.email);
		const landed = await typeCode(browser, codePage.url);
		expect(landed.url).toStartWith('http://e.ly/activity/callback');

		const row = only(await signInRows(anna.accountId), 'sign-in');
		expect(row.words.method).toBe(
			'Password and a code from an authenticator app'
		);
	});

	it('marks a sign-in from a new address only after five earlier ones', async () => {
		const anna = await person(bucketId);
		for (let i = 0; i < 5; i += 1) await signIn(anna.email);
		from('198.51.100.77');
		await signIn(anna.email);

		const rows = await signInRows(anna.accountId);
		expect(rows.map((row) => [row.address, row.newAddress])).toEqual([
			['198.51.100.77', true],
			...Array.from({ length: 5 }, () => ['203.0.113.9', false])
		]);
	});

	it('does not mark a new address with fewer than five earlier sign-ins', async () => {
		const anna = await person(bucketId);
		await signIn(anna.email);
		from('198.51.100.77');
		await signIn(anna.email);

		const rows = await signInRows(anna.accountId);
		expect(rows.map((row) => row.newAddress)).toEqual([false, false]);
	});
});

/**
 * @proves The address a sign-in keeps is the person's as this server attributes the caller, never one that is not
 * on the public Internet, never a request with no connection, never the hop of a proxy this server trusts; an IPv4
 * address written in its IPv6-mapped form is kept as the IPv4 address.
 */
describe("the address of a person's sign-in", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
	});

	afterEach(() => {
		ApplicationConfig['clientAddress.source'] = 'direct';
		ApplicationConfig['clientAddress.trustedProxies'] = [];
		settingsApplied(['clientAddress.source', 'clientAddress.trustedProxies']);
	});

	async function addressAfterSignIn(): Promise<string | null> {
		const anna = await person(bucketId);
		await signIn(anna.email);
		return only(await signInRows(anna.accountId), 'sign-in').address;
	}

	it('keeps an IPv4-mapped address as its IPv4 address', async () => {
		from('::ffff:203.0.113.7');
		expect(await addressAfterSignIn()).toBe('203.0.113.7');
	});

	it('keeps no address that is not on the public Internet', async () => {
		from('10.0.0.5');
		expect(await addressAfterSignIn()).toBeNull();
	});

	it('keeps no address for a request with no connection', async () => {
		from(undefined);
		expect(await addressAfterSignIn()).toBeNull();
	});

	it("never keeps a trusted proxy's own address as the person's", async () => {
		ApplicationConfig['clientAddress.source'] = 'listed';
		ApplicationConfig['clientAddress.trustedProxies'] = ['198.51.100.0/24'];
		settingsApplied(['clientAddress.source', 'clientAddress.trustedProxies']);
		from('198.51.100.7');
		expect(await addressAfterSignIn()).toBeNull();
	});
});

/**
 * @proves Nothing is kept for the administrators' project: an administrator's sign-in to the console leaves no
 * activity anywhere.
 */
describe("the administrators' project", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
		from('203.0.113.9');
	});

	it("keeps nothing for an administrator's sign-in to the console", async () => {
		hashAdmin ??= await Bun.password.hash(PASSWORD);
		const administrator = await getUserStore(ADMIN_BUCKET_ID).create(
			`admin-${Math.random().toString(36).slice(2)}@acme.test`,
			hashAdmin,
			true
		);
		const landed = await typePassword(
			new PersonBrowser(),
			administrator.email,
			PASSWORD,
			'admin-panel'
		);
		expect(landed.url).toStartWith('http://e.ly/admin/callback');

		await flushPersonActivityNow();
		const kept = await getPersonActivityStore().listForPerson(
			ADMIN_BUCKET_ID,
			administrator._id,
			{ limit: 10, now: new Date() }
		);
		expect(kept.rows).toEqual([]);
	});
});

let hashAdmin: string | undefined;
