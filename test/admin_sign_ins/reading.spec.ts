import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	PASSWORD,
	PersonBrowser,
	WRONG,
	from,
	only,
	typePassword
} from '../person_activity/helpers.ts';
import { CONSOLE, WIKI, administrator, signInsOf } from './helpers.ts';
import {
	getPersonActivityStore,
	getSchemaMigrationStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import {
	ADMIN_SIGN_IN_LOG_FENCE_ID,
	PERSON_ACTIVITY_FENCE_ID
} from 'lib/consts/migrations.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { forgetRecordingBeganForTests } from 'lib/person_activity/read.ts';
import { noteSignedIn } from 'lib/person_activity/record.ts';

const CHROME =
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

let reader: Awaited<ReturnType<typeof administrator>>;

/**
 * @proves A super administrator reads where and how an administrator signed in: to the console, to an application of
 * the administrators' project or through an agent, by password or a provider, with the address and the browser, and
 * the refused sign-ins of the administrator with their reason; the rows outlive a deactivation.
 */
describe("a super administrator reading an administrator's sign-ins", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		reader = await administrator('super');
		from('203.0.113.9');
	});

	it('shows a console sign-in as Console, with its method, browser and address', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);

		const row = only(
			(await signInsOf(reader.cookie, max.user._id)).rows,
			'sign-in'
		);
		expect({
			outcome: row.words.outcome,
			place: row.place.name,
			method: row.words.method,
			device: row.words.device,
			address: row.address
		}).toEqual({
			outcome: 'Let in',
			place: 'Console',
			method: 'Password',
			device: 'Chrome on Windows',
			address: '203.0.113.9'
		});
	});

	it('shows a wrong password with its reason', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);

		const row = only(
			(await signInsOf(reader.cookie, max.user._id)).rows,
			'refusal'
		);
		expect([row.words.outcome, row.words.reason]).toEqual([
			'Refused',
			'Wrong password'
		]);
	});

	it("names an application of the administrators' project", async () => {
		const max = await administrator();
		const landed = await typePassword(
			new PersonBrowser(),
			max.email,
			PASSWORD,
			WIKI
		);
		expect(landed.url).toStartWith('http://e.ly/wiki/callback');

		const row = only(
			(await signInsOf(reader.cookie, max.user._id)).rows,
			'sign-in'
		);
		expect(row.place.name).toBe('Ops wiki');
	});

	it("names an agent's sign-in through the reserved MCP client", async () => {
		const max = await administrator();
		noteSignedIn({
			bucketId: ADMIN_BUCKET_ID,
			accountId: max.user._id,
			clientId: ADMIN_MCP_CLIENT_ID,
			redirectUri: undefined,
			login: { accountId: max.user._id },
			request: new Request('http://e.ly/ui/x/resume')
		});

		const row = only(
			(await signInsOf(reader.cookie, max.user._id)).rows,
			'sign-in'
		);
		expect(row.place.name).toBe('Admin MCP (reserved client)');
	});

	it('shows a sign-in through a provider as one', async () => {
		const max = await administrator();
		noteSignedIn({
			bucketId: ADMIN_BUCKET_ID,
			accountId: max.user._id,
			clientId: CONSOLE,
			redirectUri: undefined,
			login: { accountId: max.user._id, upstream: { providerId: 'corp-sso' } },
			request: new Request('http://e.ly/ui/x/resume')
		});

		const row = only(
			(await signInsOf(reader.cookie, max.user._id)).rows,
			'sign-in'
		);
		expect([row.place.name, row.place.providerId]).toEqual([
			'Console',
			'corp-sso'
		]);
		expect(row.words.method).toStartWith('Through');
	});

	it("still lists a deactivated administrator's earlier sign-ins", async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await flushPersonActivityNow();
		await getUserStore(ADMIN_BUCKET_ID).update(max.user._id, {
			active: false
		});

		const rows = (await signInsOf(reader.cookie, max.user._id)).rows;
		expect(rows.map((row) => row.reason)).toEqual(['signed_in']);
	});

	it('keeps the browser family, never the raw browser string nor the email typed', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(CHROME), max.email, WRONG, CONSOLE);
		await typePassword(new PersonBrowser(CHROME), max.email, PASSWORD, CONSOLE);
		await flushPersonActivityNow();

		const { rows } = await getPersonActivityStore().listForPerson(
			ADMIN_BUCKET_ID,
			max.user._id,
			{ limit: 10, now: new Date() }
		);
		const stored = JSON.stringify(rows);
		expect(rows).toHaveLength(2);
		expect(stored.includes('Mozilla')).toBe(false);
		expect(stored.includes(max.email)).toBe(false);
	});
});

/**
 * @proves An administrator with nothing recorded reads the day keeping administrators' sign-ins began, not the day
 * keeping people's began, and the list says when recording is off for the server.
 */
describe("an administrator's sign-ins when there is nothing to show", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		reader = await administrator('super');
		forgetRecordingBeganForTests();
	});

	afterEach(() => {
		ApplicationConfig['personActivity.enabled'] = true;
		forgetRecordingBeganForTests();
	});

	it('reads the day keeping administrators began as when recording began', async () => {
		const store = getSchemaMigrationStore();
		const people = new Date('2026-11-16T09:00:00.000Z');
		const administrators = new Date('2026-11-18T09:00:00.000Z');
		await store.record({
			id: PERSON_ACTIVITY_FENCE_ID,
			appliedAt: people,
			checksum: 'test'
		});
		await store.record({
			id: ADMIN_SIGN_IN_LOG_FENCE_ID,
			appliedAt: administrators,
			checksum: 'test'
		});
		const max = await administrator();

		const page = await signInsOf(reader.cookie, max.user._id);
		expect([page.rows, page.recordingBegan]).toEqual([
			[],
			administrators.toISOString()
		]);
	});

	it('says recording is off for the server', async () => {
		ApplicationConfig['personActivity.enabled'] = false;
		const max = await administrator();

		const page = await signInsOf(reader.cookie, max.user._id);
		expect([page.recording, page.rows]).toEqual([false, []]);
	});
});
