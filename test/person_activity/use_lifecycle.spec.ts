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
import { admin } from '../provisioning/helpers.ts';
import {
	getActivityStore,
	getPersonActivityStore
} from 'lib/adapters/index.ts';
import { dayOf } from 'lib/activity/periods.ts';
import { markActivityOf } from 'lib/activity/note.ts';
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { noteAppUse } from 'lib/person_activity/record.ts';
import { person, project } from './helpers.ts';

let cookie: string;
let bucketId: string;

async function usedRows(accountId: string): Promise<number> {
	await flushPersonActivityNow();
	const page = await getPersonActivityStore().listForPerson(
		bucketId,
		accountId,
		{ outcome: 'let_in', kind: 'app', limit: 50, now: new Date() }
	);
	return page.rows.length;
}

/**
 * @proves What a person used goes with the person, the five minutes it waits to be written included; with recording
 * off nothing they use is kept, while they still count as active.
 */
describe('keeping what a person used', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
	});

	afterEach(() => {
		ApplicationConfig['personActivity.enabled'] = true;
		settingsApplied(['personActivity.enabled']);
	});

	it('does not bring back what a deleted person used after the next write', async () => {
		const anna = await person(bucketId);
		noteAppUse({ app: { _id: 'wiki', bucketId }, accountId: anna.accountId });

		const deleted = await admin(
			'DELETE',
			`/admin/api/projects/${bucketId}/users/${anna.accountId}`,
			cookie
		);
		expect(deleted.status).toBeLessThan(300);
		/* Another process's note for them, written after the deletion. */
		noteAppUse({ app: { _id: 'wiki', bucketId }, accountId: anna.accountId });

		expect(await usedRows(anna.accountId)).toBe(0);
	});

	it('records nothing new while recording is turned off, and Last active still moves', async () => {
		const anna = await person(bucketId);
		ApplicationConfig['personActivity.enabled'] = false;
		settingsApplied(['personActivity.enabled']);

		noteAppUse({ app: { _id: 'wiki', bucketId }, accountId: anna.accountId });
		markActivityOf(bucketId, anna.accountId, {
			route: '/proxy/check',
			method: 'GET',
			clientId: null
		});
		await new Promise((resolve) => setTimeout(resolve, 20));

		const marked = await getActivityStore().lastMarkedMany(
			bucketId,
			[anna.accountId],
			new Date()
		);
		expect({
			used: await usedRows(anna.accountId),
			lastActive: marked.get(anna.accountId)
		}).toEqual({ used: 0, lastActive: { day: dayOf(new Date()) } });
	});
});
