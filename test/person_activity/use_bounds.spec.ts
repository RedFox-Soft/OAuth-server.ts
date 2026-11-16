import { afterEach, beforeAll, describe, expect, it, spyOn } from 'bun:test';

import bootstrap from '../test_helper.ts';
import * as adapters from 'lib/adapters/index.ts';
import { getPersonActivityStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { markActivityOf } from 'lib/activity/note.ts';
import {
	resetPersonActivityForTests,
	setActivityBudgetsForTests,
	takeAll,
	takeUse
} from 'lib/person_activity/buffer.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import {
	noteApiCheck,
	noteAppUse,
	noteSignedIn
} from 'lib/person_activity/record.ts';
import { person, project } from './helpers.ts';

async function rowsOf(bucketId: string, accountId: string) {
	const page = await getPersonActivityStore().listForPerson(
		bucketId,
		accountId,
		{ limit: 50, now: new Date() }
	);
	return page.rows;
}

/**
 * @proves What people use can never crowd out what an incident needs: a flood of use in one project leaves every
 * sign-in and refusal of every project kept; nothing is noted or marked for the administrators' project; and noting
 * use, or marking a person active, reads nothing before the proxy's answer is given.
 */
describe('what people use, bounded', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		resetPersonActivityForTests();
	});

	it('keeps every sign-in and refusal of every project while one project floods with use', async () => {
		setActivityBudgetsForTests({ use: 2, perProjectUse: 2 });
		const busy = await project();
		const quiet = await project();
		const users = await Promise.all(
			Array.from({ length: 6 }, () => person(busy))
		);
		for (const user of users) {
			noteAppUse({
				app: { _id: 'wiki', bucketId: busy },
				accountId: user.accountId
			});
		}
		const anna = users[5];
		noteSignedIn({
			bucketId: busy,
			accountId: anna.accountId,
			clientId: 'activity-app',
			redirectUri: undefined,
			login: { accountId: anna.accountId },
			request: new Request('http://e.ly/ui/x/resume')
		});
		const bob = await person(quiet);
		noteApiCheck({
			api: { bucketId: quiet, identifier: 'https://files.acme.test/mcp' },
			accountId: bob.accountId,
			clientId: 'agent-1',
			outcome: 'refused',
			reason: 'no_person',
			tool: null
		});
		await flushPersonActivityNow();

		expect({
			annaSignedIn: (await rowsOf(busy, anna.accountId)).map(
				(row) => row.reason
			),
			bobRefused: (await rowsOf(quiet, bob.accountId)).map((row) => row.reason),
			usedKept: (
				await Promise.all(users.map((user) => rowsOf(busy, user.accountId)))
			).filter((rows) => rows.some((row) => row.reason === 'used')).length,
			busyDay: (
				await getPersonActivityStore().overflowDays(
					busy,
					[new Date().toISOString().slice(0, 10)],
					new Date()
				)
			).length
		}).toEqual({
			annaSignedIn: ['signed_in'],
			bobRefused: ['no_person'],
			usedKept: 2,
			busyDay: 1
		});
	});

	it("notes and marks nothing for the administrators' project", async () => {
		const reads = spyOn(adapters, 'getUserStore');
		noteAppUse({
			app: { _id: 'console', bucketId: ADMIN_BUCKET_ID },
			accountId: 'an-administrator'
		});
		markActivityOf(ADMIN_BUCKET_ID, 'an-administrator', {
			route: '/proxy/check',
			method: 'GET',
			clientId: null
		});
		await Promise.resolve();
		expect([takeAll(), takeUse(), reads.mock.calls.length]).toEqual([
			[],
			[],
			0
		]);
		reads.mockRestore();
	});

	it('reads nothing before the answer when noting use and marking a person active', async () => {
		const bucketId = await project();
		const anna = await person(bucketId);
		const reads = spyOn(adapters, 'getUserStore');
		const activity = spyOn(adapters, 'getActivityStore');
		const store = spyOn(adapters, 'getPersonActivityStore');

		noteAppUse({ app: { _id: 'wiki', bucketId }, accountId: anna.accountId });
		markActivityOf(bucketId, anna.accountId, {
			route: '/proxy/check',
			method: 'GET',
			clientId: null
		});
		const before = [
			reads.mock.calls.length,
			activity.mock.calls.length,
			store.mock.calls.length
		];
		await new Promise((resolve) => setTimeout(resolve, 0));
		const after = reads.mock.calls.length;
		reads.mockRestore();
		activity.mockRestore();
		store.mockRestore();

		expect({ before, readAfterwards: after > 0 }).toEqual({
			before: [0, 0, 0],
			readAfterwards: true
		});
	});
});
