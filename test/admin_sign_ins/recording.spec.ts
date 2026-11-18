import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	PASSWORD,
	PersonBrowser,
	SECRET,
	WRONG,
	from,
	typeCode,
	typePassword
} from '../person_activity/helpers.ts';
import { CONSOLE, administrator } from './helpers.ts';
import {
	adminAuditStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { PersonActivityRow } from 'lib/adapters/types.ts';
import { UserStore as MemoryUserStore } from 'lib/adapters/memory/userStore.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { takeAll, takeUse } from 'lib/person_activity/buffer.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import {
	noteApiCheck,
	noteApiUse,
	noteAppCheck,
	noteAppUse
} from 'lib/person_activity/record.ts';

async function keptFor(accountId: string): Promise<PersonActivityRow[]> {
	await flushPersonActivityNow();
	const page = await getPersonActivityStore().listForPerson(
		ADMIN_BUCKET_ID,
		accountId,
		{ limit: 20, now: new Date() }
	);
	return page.rows;
}

/**
 * @proves An administrator's sign-in to the console is kept like a person's, with how they signed in, the address and
 * the browser; a refused sign-in of a known administrator is kept with its reason; and with recording turned off for
 * the server nothing is kept for administrators either.
 */
describe("an administrator's sign-ins", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		from('203.0.113.9');
	});

	afterEach(() => {
		ApplicationConfig['personActivity.enabled'] = true;
	});

	it('keeps a console sign-in with its method, address and browser', async () => {
		const max = await administrator();
		const landed = await typePassword(
			new PersonBrowser(),
			max.email,
			PASSWORD,
			CONSOLE
		);
		expect(landed.url).toStartWith('http://e.ly/admin/callback');

		const rows = await keptFor(max.user._id);
		expect(
			rows.map((row) => ({
				kind: row.kind,
				reason: row.reason,
				clientId: row.place.clientId,
				method: row.method,
				address: row.address,
				browser: row.device?.browser
			}))
		).toEqual([
			{
				kind: 'signIn',
				reason: 'signed_in',
				clientId: CONSOLE,
				method: 'password',
				address: '203.0.113.9',
				browser: 'chrome'
			}
		]);
	});

	it('keeps a wrong password of a known administrator as a refusal', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);

		const rows = await keptFor(max.user._id);
		expect(rows.map((row) => [row.outcome, row.reason])).toEqual([
			['refused', 'wrong_password']
		]);
	});

	it('keeps a wrong code of a known administrator as a refusal', async () => {
		const max = await administrator();
		await getUserStore(ADMIN_BUCKET_ID).update(max.user._id, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});
		const browser = new PersonBrowser();
		const codePage = await typePassword(browser, max.email, PASSWORD, CONSOLE);
		await typeCode(browser, codePage.url, '000000');

		const rows = await keptFor(max.user._id);
		expect(rows.map((row) => [row.outcome, row.reason])).toEqual([
			['refused', 'wrong_code']
		]);
	});

	it('keeps nothing while recording is off for the server', async () => {
		ApplicationConfig['personActivity.enabled'] = false;
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);

		expect(await keptFor(max.user._id)).toEqual([]);
	});
});

/**
 * @proves Only sign-ins are kept for the administrators' project: what an app or an API behind the proxy decided, and
 * what was used there, is never noted for it.
 */
describe("what is kept for the administrators' project", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('notes nothing but sign-ins', () => {
		const flags = {
			keyPresent: true,
			keyValid: true,
			addressPresent: true,
			single: true,
			isPublic: true,
			cloudflare: false,
			probe: false
		};
		const api = {
			bucketId: ADMIN_BUCKET_ID,
			identifier: 'https://admin.test/mcp'
		};
		noteAppCheck({
			app: { _id: 'console-app', bucketId: ADMIN_BUCKET_ID },
			accountId: 'an-administrator',
			decision: { outcome: 'deny', reason: 'not_in_group', rule: null },
			believed: { address: '203.0.113.9', reported: '203.0.113.9', flags }
		});
		noteApiCheck({
			api,
			accountId: 'an-administrator',
			clientId: 'agent',
			outcome: 'refused',
			reason: 'not_in_group',
			tool: null
		});
		noteAppUse({
			app: { _id: 'console-app', bucketId: ADMIN_BUCKET_ID },
			accountId: 'an-administrator'
		});
		noteApiUse({
			api,
			accountId: 'an-administrator',
			clientId: 'agent',
			tool: null
		});

		expect([...takeAll(), ...takeUse()]).toEqual([]);
	});
});

/**
 * @proves An attempt at the console with an address no administrator holds records nothing, and costs the datastore
 * what a wrong password for a real administrator costs; a sign-in, kept or refused, writes nothing to the audit
 * trail.
 */
describe("the administrators' door", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		from('203.0.113.9');
	});

	it('records nothing for an unknown address and costs the same reads as a known one', async () => {
		const max = await administrator();
		const reads = (['find', 'findByEmail', 'findMany'] as const).map((method) =>
			spyOn(MemoryUserStore.prototype, method)
		);
		const count = () =>
			reads.reduce((sum, spy) => sum + spy.mock.calls.length, 0);
		try {
			await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);
			const known = count();
			for (const spy of reads) spy.mockClear();
			await typePassword(
				new PersonBrowser(),
				'nobody@acme.test',
				WRONG,
				CONSOLE
			);
			expect(count()).toBe(known);
		} finally {
			for (const spy of reads) spy.mockRestore();
		}

		const rows = await keptFor(max.user._id);
		expect(rows.map((row) => row.reason)).toEqual(['wrong_password']);
	});

	it('writes nothing to the audit trail for a sign-in', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await flushPersonActivityNow();

		const { entries } = await adminAuditStore.list({ actor: max.user._id });
		expect(entries).toEqual([]);
	});
});
