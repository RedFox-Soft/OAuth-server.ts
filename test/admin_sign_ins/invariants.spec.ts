import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { shaped } from '../shape.ts';
import { agentFor, tool } from '../behind_proxy/helpers.ts';
import {
	PASSWORD,
	PageView,
	PersonBrowser,
	from,
	readActivity,
	typePassword
} from '../person_activity/helpers.ts';
import { CONSOLE, administrator, readSignIns } from './helpers.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';

const ADDRESS = '203.0.113.9';

async function readsOf(adminId: string) {
	const { entries } = await adminAuditStore.list({
		action: 'admin.activity.read',
		targetId: adminId
	});
	return entries;
}

let max: Awaited<ReturnType<typeof administrator>>;

/**
 * @proves Another administrator's sign-ins are given only to a super administrator, by console and by agent, and
 * every such read is kept in the audit trail once per reader, administrator and day, an agent apart, without the
 * address or anything else that was read; no project route reaches the administrators' rows.
 */
describe("reading an administrator's sign-ins", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		from(ADDRESS);
	});

	beforeEach(async () => {
		max = await administrator();
		await typePassword(new PersonBrowser(), max.email, PASSWORD, CONSOLE);
	});

	it('is refused to an administrator who is not a super administrator, with nothing audited', async () => {
		const colleague = await administrator();
		const reply = await readSignIns(colleague.cookie, max.user._id);
		const agent = await tool(
			await agentFor(colleague.user),
			'admin_activity_list',
			{ id: max.user._id }
		);

		expect([reply.status, agent.result?.isError]).toEqual([403, true]);
		expect(await readsOf(max.user._id)).toEqual([]);
	});

	it('is audited once per reader, administrator and day, an agent apart, without what was read', async () => {
		const reader = await administrator('super');
		for (let i = 0; i < 3; i += 1) {
			expect((await readSignIns(reader.cookie, max.user._id)).status).toBe(200);
		}
		const agent = await tool(
			await agentFor(reader.user),
			'admin_activity_list',
			{ id: max.user._id }
		);
		expect(agent.result?.isError ?? false).toBe(false);

		const entries = await readsOf(max.user._id);
		expect(
			entries.map((entry) => entry.viaClientId !== undefined).sort()
		).toEqual([false, true]);
		const kept = JSON.stringify(entries);
		for (const read of [ADDRESS, 'Chrome', 'Windows', max.email]) {
			expect(kept.includes(read)).toBe(false);
		}
	});

	it('is what an agent acting for a super administrator reads', async () => {
		const reader = await administrator('super');
		await flushPersonActivityNow();
		const answer = await tool(
			await agentFor(reader.user),
			'admin_activity_list',
			{ id: max.user._id }
		);

		const page = shaped(PageView, answer.result?.structuredContent?.result);
		expect(page.rows.map((row) => [row.place.name, row.address])).toEqual([
			['Console', ADDRESS]
		]);
	});

	it("is not reached through a project's activity route", async () => {
		const reader = await administrator('super');
		const reply = await readActivity(
			reader.cookie,
			ADMIN_BUCKET_ID,
			max.user._id
		);

		expect([403, 404]).toContain(reply.status);
	});
});
