import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { call, membersOf, superAdmin, tenant } from './admin.ts';

const REFUSAL = 'add people to a team by inviting them';

function addMember(cookie: string, teamId: string, userId: string) {
	return call('POST', `/admin/api/teams/${teamId}/members`, cookie, {
		userId,
		role: 'owner'
	});
}

async function memberAdds(): Promise<number> {
	return (await adminAuditStore.list({ action: 'group.member.add' })).total;
}

/**
 * @proves A team's membership changes only by an invitation its invitee accepts, or by a super administrator: a
 * team owner cannot put another administrator into their team by id — as owner or otherwise — and the refusal is
 * the same whether or not the id names anybody. An agent reaches this through the same route (lib/mcp/dispatch.ts),
 * so it is refused alike.
 */
describe('adding an administrator to a team directly', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
	});

	it('is refused to a team owner who is not a super administrator, and nothing is recorded', async () => {
		const owner = await tenant();
		const victim = await tenant();
		const before = await memberAdds();

		const answer = await addMember(owner.cookie, owner.teamId, victim.user._id);

		expect(answer.status).toBe(403);
		expect((answer.body as { message: string }).message).toBe(REFUSAL);
		expect(await membersOf(owner.teamId)).not.toContain(
			`${victim.user._id}:owner`
		);
		expect(await memberAdds()).toBe(before);
	});

	it('answers an id that names nobody exactly as one that names somebody', async () => {
		const owner = await tenant();

		const answer = await addMember(owner.cookie, owner.teamId, 'no-such-admin');

		expect(answer.status).toBe(403);
		expect((answer.body as { message: string }).message).toBe(REFUSAL);
	});

	it('is accepted from a super administrator', async () => {
		const operator = await superAdmin();
		const colleague = await tenant();

		const answer = await addMember(
			operator.cookie,
			operator.teamId,
			colleague.user._id
		);

		expect(answer.status).toBe(200);
		expect(await membersOf(operator.teamId)).toContain(
			`${colleague.user._id}:owner`
		);
	});
});
