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
import { getUserStore } from 'lib/adapters/index.ts';
import { activityOf, type PageView } from '../person_activity/helpers.ts';
import {
	clockAt,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer,
	iso,
	type ListLine,
	type Signer
} from './helper.ts';
import {
	attempt,
	REFUSAL_TITLE,
	PASSWORD,
	person,
	seedProject,
	setGuessing,
	WRONG
} from './door.ts';

let cookie: string;
let bucketId: string;
let foxtrust: Signer;
let undoClock: () => void = () => {};

async function listing(...lines: ListLine[]): Promise<void> {
	const published = publication();
	await published.publish({
		version: `a${String(seconds(0))}`,
		builtAt: iso(0),
		validUntil: iso(3),
		lines,
		by: foxtrust
	});
	expect(await pass(foxtrust)).toBe('accepted');
}

async function accountOf(email: string): Promise<string> {
	const user = await getUserStore(bucketId).findByEmail(email);
	if (!user) throw new Error(`no account for ${email}`);
	return user._id;
}

function failures(page: PageView): number {
	return page.rows
		.filter((row) => row.kind === 'signIn')
		.reduce((sum, row) => sum + row.count, 0);
}

/**
 * @proves Where the password door turns a caller away without reading the account — the per-address throttle and
 * FoxTrust's attacker list — nothing is kept on any person's activity: recording there would need the account read
 * the door exists to avoid, and would put an attacker's address on a person's page.
 */
describe("a person's activity at the password door's early refusals", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
		bucketId = await seedProject();
		await setGuessing(bucketId, { mode: 'refuse', exempt: [] });
	});

	beforeEach(async () => {
		resetAttackerList();
		foxtrust = await signer();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
	});

	it('keeps only the attempts that reached the account when the throttle turns the rest away', async () => {
		const email = await person(bucketId);
		for (let i = 0; i < 9; i += 1) {
			await attempt(email, WRONG, '198.51.100.40');
		}

		const page = await activityOf(cookie, bucketId, await accountOf(email));
		expect(failures(page)).toBeLessThan(9);
		expect(page.rows.every((row) => row.reason === 'wrong_password')).toBe(
			true
		);
	});

	it('keeps nothing for a sign-in the attacker list refused', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing({ network: from, lastSeen: seconds(-1), corroborated: true });

		const answer = await attempt(email, PASSWORD, from);
		expect(answer.text).toContain(REFUSAL_TITLE);

		const page = await activityOf(cookie, bucketId, await accountOf(email));
		expect(page.rows).toEqual([]);
	});
});
