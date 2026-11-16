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
import { scheduleDeletion } from '../behind_proxy/helpers.ts';
import { present } from '../shape.ts';
import { getBucketStore, getPersonActivityStore } from 'lib/adapters/index.ts';
import { destroyBucket } from 'lib/admin/buckets/destroy.ts';
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { noteSignInRefused } from 'lib/person_activity/record.ts';
import {
	PersonBrowser,
	WRONG,
	activityOf,
	from,
	person,
	project,
	readActivity,
	typePassword
} from './helpers.ts';

let cookie: string;
let bucketId: string;

function usersPath(accountId?: string): string {
	return `/admin/api/projects/${bucketId}/users${accountId ? `/${accountId}` : ''}`;
}

async function kept(accountId: string, at = bucketId): Promise<number> {
	await flushPersonActivityNow();
	const page = await getPersonActivityStore().listForPerson(at, accountId, {
		limit: 50,
		now: new Date()
	});
	return page.rows.length;
}

async function failOnce(email: string): Promise<void> {
	await typePassword(new PersonBrowser(), email, WRONG);
}

/**
 * @proves A person's activity outlives every end of their access — a lock, a deactivation, a sign-out everywhere —
 * and goes with the person and with the project, what was still waiting to be written included; a row past its 90
 * days is never shown; with recording off nothing new is kept.
 */
describe("keeping a person's activity", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		bucketId = await project();
		from('203.0.113.9');
	});

	afterEach(() => {
		ApplicationConfig['personActivity.enabled'] = true;
		settingsApplied(['personActivity.enabled']);
	});

	it('keeps it through a lock, a deactivation and a sign-out everywhere', async () => {
		const anna = await person(bucketId);
		await failOnce(anna.email);
		await flushPersonActivityNow();

		const acts = [
			await admin('POST', `${usersPath(anna.accountId)}/lock`, cookie, {
				reason: 'Incident'
			}),
			await admin('POST', `${usersPath(anna.accountId)}/sign-out`, cookie, {}),
			await admin('PATCH', usersPath(anna.accountId), cookie, { active: false })
		];
		expect(acts.map((act) => act.status)).toEqual([200, 200, 200]);

		const page = await activityOf(cookie, bucketId, anna.accountId);
		expect(page.rows.map((row) => row.reason)).toEqual(['wrong_password']);
	});

	it('deletes it with the person, what was waiting to be written included', async () => {
		const anna = await person(bucketId);
		await failOnce(anna.email);
		await flushPersonActivityNow();
		await failOnce(anna.email);

		const deleted = await admin('DELETE', usersPath(anna.accountId), cookie);
		expect(deleted.status).toBeLessThan(300);

		expect(await kept(anna.accountId)).toBe(0);
	});

	it('deletes it with people deleted in bulk', async () => {
		const anna = await person(bucketId);
		await failOnce(anna.email);

		const deleted = await admin('POST', `${usersPath()}/bulk/delete`, cookie, {
			userIds: [anna.accountId]
		});
		expect(deleted.status).toBe(200);

		expect(await kept(anna.accountId)).toBe(0);
	});

	it('does not bring a deleted person back from a note written after their deletion', async () => {
		const anna = await person(bucketId);
		const deleted = await admin('DELETE', usersPath(anna.accountId), cookie);
		expect(deleted.status).toBeLessThan(300);
		/* A note another process held for them, written after the deletion. */
		noteSignInRefused({
			bucketId,
			accountId: anna.accountId,
			reason: 'wrong_password',
			clientId: 'activity-app',
			request: new Request('http://e.ly/ui/x/login')
		});

		expect(await kept(anna.accountId)).toBe(0);
	});

	it('never shows a row past its 90 days', async () => {
		const anna = await person(bucketId);
		const long = new Date(Date.now() - 91 * 86_400_000);
		await getPersonActivityStore().write([
			{
				_id: 'old-refusal',
				bucketId,
				accountId: anna.accountId,
				day: long.toISOString().slice(0, 10),
				kind: 'signIn',
				outcome: 'refused',
				reason: 'wrong_password',
				place: {},
				count: 1,
				firstAt: long,
				lastAt: long,
				expiresAt: new Date(long.getTime() + 90 * 86_400_000)
			}
		]);

		expect((await activityOf(cookie, bucketId, anna.accountId)).rows).toEqual(
			[]
		);
	});

	it('records nothing new while recording is turned off', async () => {
		const anna = await person(bucketId);
		ApplicationConfig['personActivity.enabled'] = false;
		settingsApplied(['personActivity.enabled']);
		await failOnce(anna.email);

		const page = await activityOf(cookie, bucketId, anna.accountId);
		expect([page.rows, page.recording]).toEqual([[], false]);
	});

	it('still shows it on a project scheduled for deletion', async () => {
		const anna = await person(bucketId);
		await failOnce(anna.email);
		await flushPersonActivityNow();
		await scheduleDeletion(bucketId);

		const reply = await readActivity(cookie, bucketId, anna.accountId);
		expect(reply.status).toBe(200);
		expect((reply.json.rows as unknown[]).length).toBe(1);
	});
});

/**
 * @proves A destroyed project leaves none of its people's activity behind. Its own file section, because destroying
 * the project takes its applications with it.
 */
describe("a destroyed project's activity", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
		bucketId = await project();
		from('203.0.113.9');
	});

	it('leaves nothing of it', async () => {
		const anna = await person(bucketId);
		await failOnce(anna.email);
		await flushPersonActivityNow();
		await scheduleDeletion(bucketId);
		const scheduled = present(
			await getBucketStore().find(bucketId),
			'the project'
		);

		const outcome = await destroyBucket(
			scheduled,
			{ kind: 'server' },
			{ due: false }
		);
		expect(outcome.claimed).toBe(true);

		expect(await kept(anna.accountId)).toBe(0);
	});
});
