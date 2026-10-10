import {
	describe,
	it,
	expect,
	beforeAll,
	afterAll,
	afterEach,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	errorStore,
	getActivityStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import {
	seedBucket,
	seedUser,
	settled,
	signInAndRedeem,
	startCounting
} from './fixtures.ts';

let bucketId: string;
const recording = ApplicationConfig['errorStore.enabled'];
let restores: Array<() => void> = [];

function failRecording() {
	const mark = spyOn(getActivityStore(), 'mark').mockRejectedValue(
		new Error('the activity datastore is unavailable')
	);
	const log = spyOn(console, 'error').mockImplementation(() => undefined);
	restores.push(
		() => mark.mockRestore(),
		() => log.mockRestore()
	);
}

/**
 * @proves Recording an end user's activity can never cost them their sign-in: when the record cannot be
 * written the tokens are still issued, and the failure is recorded for the operator to see.
 */
describe('a sign-in whose activity cannot be recorded', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'activity' });
		resetAdminMemoryStores();
		await startCounting();
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
		bucketId = await seedBucket('Activity never blocks', ['act-app']);
	});

	afterEach(() => {
		for (const restore of restores) restore();
		restores = [];
	});

	afterAll(() => {
		ApplicationConfig['errorStore.enabled'] = recording;
	});

	it('issues the tokens when recording the activity fails', async () => {
		const email = await seedUser(bucketId);
		failRecording();

		const tokens = await signInAndRedeem('act-app', email);

		expect(tokens.response.status).toBe(200);
	});

	it('lists a failure to record activity among the recorded faults', async () => {
		const email = await seedUser(bucketId);
		failRecording();

		await signInAndRedeem('act-app', email);
		await settled();
		await flushForTest();

		const { groups } = await errorStore.list({ route: '/token' });
		expect(groups.map((group) => group.errorCode)).toContain(
			'activity_not_recorded'
		);
	});
});
