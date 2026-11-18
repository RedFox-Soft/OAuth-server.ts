import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { shaped } from '../shape.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	PASSWORD,
	PageView,
	PersonBrowser,
	RowView,
	WRONG,
	from,
	typePassword
} from '../person_activity/helpers.ts';
import { CONSOLE, administrator } from './helpers.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';

const ADDRESS = '203.0.113.9';

const FeedView = Type.Composite([
	Type.Omit(PageView, ['rows']),
	Type.Object({
		rows: Type.Array(
			Type.Composite([
				RowView,
				Type.Object({
					accountId: Type.String(),
					email: Type.Union([Type.String(), Type.Null()])
				})
			])
		)
	})
]);

async function feed(cookie: string, body: Record<string, unknown> = {}) {
	await flushPersonActivityNow();
	return admin('POST', '/admin/api/admins/activity', cookie, body);
}

async function feedOf(cookie: string, body: Record<string, unknown> = {}) {
	const reply = await feed(cookie, body);
	expect(reply.status).toBe(200);
	return shaped(FeedView, reply.body);
}

const AdminRow = Type.Object({
	_id: Type.String(),
	email: Type.String(),
	signIns: Type.Object({
		lastSignIn: Type.Union([
			Type.Null(),
			Type.Object({
				at: Type.String(),
				clientId: Type.Union([Type.String(), Type.Null()]),
				name: Type.Union([Type.String(), Type.Null()]),
				method: Type.Union([Type.String(), Type.Null()])
			})
		]),
		notLetInSince: Type.Union([
			Type.Null(),
			Type.Object({
				at: Type.String(),
				count: Type.Number(),
				reason: Type.String(),
				kind: Type.String()
			})
		])
	})
});

let reader: Awaited<ReturnType<typeof administrator>>;

/**
 * @proves A super administrator who does not yet know whose password is in use sees every administrator's sign-ins
 * and refused sign-ins on one page, newest first, each naming the administrator, and pages through them without a
 * row dropped or repeated; only a super administrator reads it, and each reader's read is kept once a day, without
 * what was read.
 */
describe("every administrator's sign-ins on one page", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		from(ADDRESS);
	});

	beforeEach(async () => {
		reader = await administrator('super');
	});

	it('lists each administrator’s sign-ins and refusals, newest first, naming them', async () => {
		const max = await administrator();
		const ann = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await typePassword(new PersonBrowser(), ann.email, WRONG, CONSOLE);

		const page = await feedOf(reader.cookie);
		const mine = page.rows.filter((row) =>
			[max.user._id, ann.user._id].includes(row.accountId)
		);
		expect(
			mine.map((row) => [row.email, row.words.outcome, row.address]).sort()
		).toEqual(
			[
				[ann.email, 'Refused', ADDRESS],
				[max.email, 'Let in', ADDRESS]
			].sort()
		);
		const times = page.rows.map((row) => row.lastAt);
		expect([...times].sort().reverse()).toEqual(times);
	});

	it('pages through every row once', async () => {
		for (let i = 0; i < 3; i += 1) {
			const someone = await administrator();
			await typePassword(new PersonBrowser(), someone.email, PASSWORD, CONSOLE);
		}
		const whole = await feedOf(reader.cookie, { limit: 100 });

		const seen: string[] = [];
		let before: string | null = null;
		do {
			const page = await feedOf(reader.cookie, {
				limit: 2,
				...(before ? { before } : {})
			});
			seen.push(...page.rows.map((row) => row.id));
			before = page.next;
		} while (before);
		expect(seen).toEqual(whole.rows.map((row) => row.id));
	});

	it('is refused to an administrator who is not a super administrator, with nothing audited', async () => {
		const colleague = await administrator();
		const before = (
			await adminAuditStore.list({ action: 'admins.activity.read' })
		).entries.length;

		expect((await feed(colleague.cookie)).status).toBe(403);
		const { entries } = await adminAuditStore.list({
			action: 'admins.activity.read'
		});
		expect(entries.length).toBe(before);
	});

	it('is audited once per reader and day, without what was read', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await feedOf(reader.cookie);
		await feedOf(reader.cookie);

		const { entries } = await adminAuditStore.list({
			action: 'admins.activity.read',
			actor: reader.user._id
		});
		expect(entries.map((entry) => entry.targetId)).toEqual([ADMIN_BUCKET_ID]);
		const kept = JSON.stringify(entries);
		for (const read of [ADDRESS, max.email, 'Chrome']) {
			expect(kept.includes(read)).toBe(false);
		}
	});
});

/**
 * @proves The list of administrators says when each last signed in and how, and how often they were refused since,
 * so a password being tried shows without opening anyone's sign-ins; it carries no address or country, so reading it
 * is not audited.
 */
describe('the list of administrators', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		from(ADDRESS);
	});

	beforeEach(async () => {
		reader = await administrator('super');
	});

	it('shows the last sign-in and the refusals since, without an address', async () => {
		const max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
		await flushPersonActivityNow();
		await new Promise((resolve) => setTimeout(resolve, 5));
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);
		await typePassword(new PersonBrowser(), max.email, WRONG, CONSOLE);
		await flushPersonActivityNow();

		const reply = await admin('GET', '/admin/api/admins', reader.cookie);
		expect(reply.status).toBe(200);
		const row = shaped(Type.Array(AdminRow), reply.body).find(
			(account) => account._id === max.user._id
		);
		expect(row?.signIns).toEqual({
			lastSignIn: {
				at: row?.signIns.lastSignIn?.at ?? '',
				clientId: CONSOLE,
				name: 'Console',
				method: 'Password'
			},
			notLetInSince: {
				at: row?.signIns.notLetInSince?.at ?? '',
				count: 2,
				reason: 'Wrong password',
				kind: 'signIn'
			}
		});
		expect(JSON.stringify(reply.body).includes(ADDRESS)).toBe(false);
	});

	it('shows nothing for an administrator who never signed in', async () => {
		const ann = await administrator();

		const reply = await admin('GET', '/admin/api/admins', reader.cookie);
		const row = shaped(Type.Array(AdminRow), reply.body).find(
			(account) => account._id === ann.user._id
		);
		expect(row?.signIns).toEqual({ lastSignIn: null, notLetInSince: null });
	});
});
