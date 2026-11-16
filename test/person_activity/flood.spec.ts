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
import {
	resetPersonActivityForTests,
	setActivityBudgetsForTests
} from 'lib/person_activity/buffer.ts';
import {
	PersonBrowser,
	WRONG,
	activityOf,
	from,
	person,
	project,
	signIn,
	typePassword
} from './helpers.ts';

let cookie: string;

/*
 * The budgets lowered to two notes per kind and per project, so a flood is a handful of wrong passwords instead of
 * tens of thousands; what is proved is what a full budget does, not how large it is.
 */
const SMALL = { signInRefusals: 2, app: 2, api: 2, perProject: 2 };

async function flood(bucketId: string, people: number): Promise<string[]> {
	const ids: string[] = [];
	for (let i = 0; i < people; i += 1) {
		const someone = await person(bucketId);
		ids.push(someone.accountId);
		await typePassword(new PersonBrowser(), someone.email, WRONG);
	}
	return ids;
}

/**
 * @proves A flood of wrong passwords cannot hide a sign-in: past its budget it is counted, not dropped, a successful
 * sign-in is kept whatever the flood, and one project's flood never takes another project's records.
 */
describe("a person's activity under a flood", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(() => {
		setActivityBudgetsForTests(SMALL);
		from('203.0.113.9');
	});

	afterEach(() => {
		resetPersonActivityForTests();
	});

	it('keeps a successful sign-in while failures overflow every budget', async () => {
		const bucketId = await project();
		const victims = await flood(bucketId, 5);
		const anna = await person(bucketId);
		await signIn(anna.email);

		const signedIn = await activityOf(cookie, bucketId, anna.accountId);
		const flooded = await activityOf(cookie, bucketId, victims[4]);
		expect({
			annaSignedIn: signedIn.rows.map((row) => row.outcome),
			lastVictimRows: flooded.rows.length,
			busy: signedIn.busyDays.length > 0 || flooded.busyDays.length > 0
		}).toEqual({ annaSignedIn: ['let_in'], lastVictimRows: 0, busy: true });
	});

	it("keeps another project's refusal while one project floods", async () => {
		/* Room in the instance's budget, so only the flooding project's own quota is spent. */
		setActivityBudgetsForTests({ ...SMALL, signInRefusals: 10 });
		const flooded = await project();
		await flood(flooded, 4);
		const quiet = await project();
		const bob = await person(quiet);
		await typePassword(new PersonBrowser(), bob.email, WRONG);

		const page = await activityOf(cookie, quiet, bob.accountId);
		expect(page.rows.map((row) => row.reason)).toEqual(['wrong_password']);
	});
});
