import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import { agentFor, editor, tool } from '../behind_proxy/helpers.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import {
	PersonBrowser,
	WRONG,
	from,
	person,
	readActivity,
	typePassword
} from './helpers.ts';

let reader: { user: User; cookie: string; project: { id: string } };
let anna: { email: string; accountId: string };

async function reads(accountId: string) {
	const { entries } = await adminAuditStore.list({
		action: 'enduser.activity.read',
		targetId: accountId
	});
	return entries;
}

/**
 * @proves Who read a person's activity is kept in the audit trail, once per reader, person and day, an agent's read as
 * the agent's; the reads are not mixed into the person's changes; and an administrator of another project cannot
 * read it at all.
 */
describe("reading a person's activity", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		from('203.0.113.9');
	});

	beforeEach(async () => {
		reader = await editor();
		anna = await person(reader.project.id);
		await typePassword(new PersonBrowser(), anna.email, WRONG);
	});

	afterEach(() => {
		setSystemTime();
	});

	it('is audited once per reader, person and day', async () => {
		/* Two minutes before midnight UTC, so the next day is a short step inside one console session. */
		const today = new Date();
		const midnight = Date.UTC(
			today.getUTCFullYear(),
			today.getUTCMonth(),
			today.getUTCDate() + 1
		);
		setSystemTime(new Date(midnight - 2 * 60_000));
		const late = await editor();
		const bob = await person(late.project.id);
		for (let i = 0; i < 10; i += 1) {
			const reply = await readActivity(
				late.cookie,
				late.project.id,
				bob.accountId
			);
			expect(reply.status).toBe(200);
		}
		const sameDay = (await reads(bob.accountId)).length;
		setSystemTime(new Date(midnight + 60_000));
		const nextDay = await readActivity(
			late.cookie,
			late.project.id,
			bob.accountId
		);
		expect(nextDay.status).toBe(200);

		expect([sameDay, (await reads(bob.accountId)).length]).toEqual([1, 2]);
	});

	it("audits an agent's read as the agent's", async () => {
		const token = await agentFor(reader.user);
		const answer = await tool(token, 'project_user_activity_list', {
			id: reader.project.id,
			uid: anna.accountId
		});
		expect(answer.result?.isError ?? false).toBe(false);

		const entries = await reads(anna.accountId);
		expect(entries.map((entry) => entry.viaClientId !== undefined)).toEqual([
			true
		]);
	});

	it("leaves the reads out of the person's changes", async () => {
		await readActivity(reader.cookie, reader.project.id, anna.accountId);
		const changes = await admin(
			'GET',
			`/admin/api/audit?targetId=${anna.accountId}&targetScope=${reader.project.id}&changesOnly=true`,
			reader.cookie
		);
		expect(changes.status).toBe(200);
		const actions = (changes.json.entries as { action: string }[]).map(
			(e) => e.action
		);
		expect(actions).not.toContain('enduser.activity.read');
	});

	it('refuses an administrator of another project', async () => {
		const stranger = await editor();
		const reply = await readActivity(
			stranger.cookie,
			reader.project.id,
			anna.accountId
		);

		expect([403, 404]).toContain(reply.status);
		expect(await reads(anna.accountId)).toEqual([]);
	});
});
