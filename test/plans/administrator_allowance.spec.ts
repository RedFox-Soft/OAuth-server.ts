import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	INVITATION_TTL_SECONDS,
	invitationTokenHash
} from 'lib/admin/groups/invite.ts';
import {
	getBucketStore,
	getGroupInvitationStore,
	getGroupStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import { createAdministrator } from '../administrators.ts';
import { regularGroup } from '../admin/ownership_fixtures.ts';
import {
	call,
	cookieOf,
	createProject,
	idOf,
	refusalOf,
	storeCatalogue,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

async function twoProjects(owner: Caller): Promise<string[]> {
	return [idOf(await createProject(owner)), idOf(await createProject(owner))];
}

/* An administrator who owns no regular team yet. */
async function newcomer(): Promise<Caller> {
	const user = await createAdministrator('plain');
	const personal = await ensurePersonalGroup(user._id, user.email);
	return { user, cookie: await cookieOf(user), teamId: personal._id };
}

function move(caller: Caller, id: string, teamId: string) {
	return call('PUT', `/admin/api/projects/${id}/owner`, caller.cookie, {
		teamId,
		confirm: true
	});
}

/**
 * @proves An administrator owns at most two Free projects across every team they own and at most one regular
 * team, and neither count is got around by creating, moving in, restoring, or being made an owner by member add,
 * role change or invitation; a refusal about another owner names neither them nor their count; a super
 * administrator is not limited.
 */
describe('what one administrator may own on Free', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
	});

	beforeEach(async () => {
		forgetBucketAddresses();
		await storeCatalogue([...BUILT_IN_PLANS]);
		await withPlans(operator, true);
	});

	it('refuses a third Free project, counted across the personal team and a regular one', async () => {
		const owner = await tenant();
		const personal = await ensurePersonalGroup(
			owner.user._id,
			owner.user.email
		);
		idOf(await createProject(owner, { teamId: personal._id }));
		idOf(await createProject(owner));

		const refusal = refusalOf(await createProject(owner));

		expect(refusal.limit).toEqual({
			name: 'projectsPerAdministrator',
			plan: { id: 'free', name: 'Free' },
			count: 2,
			max: 2
		});
	});

	it('admits a move between two teams of the same owner', async () => {
		const owner = await tenant();
		const personal = await ensurePersonalGroup(
			owner.user._id,
			owner.user.email
		);
		const id = idOf(await createProject(owner, { teamId: personal._id }));
		idOf(await createProject(owner));

		expect((await move(owner, id, owner.teamId)).status).toBe(200);
	});

	it('refuses a move into a team whose owner is at the limit, naming neither them nor their count', async () => {
		const full = await tenant();
		await twoProjects(full);
		const mover = await tenant();
		const team = await getGroupStore().find(full.teamId);
		await getGroupStore().update(full.teamId, {
			members: [
				...(team?.members ?? []),
				{ userId: mover.user._id, role: 'member' }
			]
		});
		const id = idOf(await createProject(mover));

		const answered = await move(mover, id, full.teamId);
		const refusal = refusalOf(answered);

		expect(refusal.limit).toEqual({
			name: 'projectsPerAdministrator',
			plan: { id: 'free', name: 'Free' },
			max: 2
		});
		expect(JSON.stringify(answered.body)).not.toContain(full.user.email);
		expect(JSON.stringify(answered.body)).not.toContain(full.user._id);
		expect((await getBucketStore().find(id))?.ownerGroupId).toBe(mover.teamId);
	});

	it('refuses to restore a project that would put its owner over the limit', async () => {
		const owner = await tenant();
		const [scheduled] = await twoProjects(owner);
		await getBucketStore().scheduleDeletion(scheduled, {
			scheduledAt: new Date(),
			purgeAt: new Date(Date.now() + 86_400_000),
			scheduledBy: { userId: owner.user._id }
		});
		idOf(await createProject(owner));

		const refusal = refusalOf(
			await call(
				'POST',
				`/admin/api/projects/${scheduled}/restore`,
				owner.cookie
			)
		);

		expect(refusal.limit.name).toBe('projectsPerAdministrator');
		expect((await getBucketStore().find(scheduled))?.deletion).toBeDefined();
	});

	it('refuses a second regular team', async () => {
		const owner = await tenant();

		const refusal = refusalOf(
			await call('POST', '/admin/api/teams', owner.cookie, { name: 'Second' })
		);

		expect(refusal.limit).toEqual({
			name: 'regularTeamsPerAdministrator',
			count: 1,
			max: 1
		});
	});

	/*
	 * Promotion is the way a tenant makes somebody an owner directly: only a super administrator adds anybody by id,
	 * and is not limited (specs/103). The member is put in through the store, as an accepted invitation would.
	 */
	async function asMemberOf(teamId: string, userId: string): Promise<void> {
		const team = await getGroupStore().find(teamId);
		await getGroupStore().update(teamId, {
			members: [...(team?.members ?? []), { userId, role: 'member' }]
		});
	}

	it('refuses to promote an administrator at the team limit to owner', async () => {
		const owner = await tenant();
		const full = await tenant();
		await asMemberOf(owner.teamId, full.user._id);

		const promoted = await call(
			'PATCH',
			`/admin/api/teams/${owner.teamId}/members/${full.user._id}`,
			owner.cookie,
			{ role: 'owner' }
		);

		expect(refusalOf(promoted).limit.name).toBe('regularTeamsPerAdministrator');
	});

	it('refuses to promote an administrator who would then own too many Free projects', async () => {
		const owner = await tenant();
		idOf(await createProject(owner));
		const busy = await newcomer();
		await twoProjects(busy);
		await storeCatalogue([...BUILT_IN_PLANS]);
		await asMemberOf(owner.teamId, busy.user._id);

		const promoted = await call(
			'PATCH',
			`/admin/api/teams/${owner.teamId}/members/${busy.user._id}`,
			owner.cookie,
			{ role: 'owner' }
		);

		expect(refusalOf(promoted).limit.name).toBe('projectsPerAdministrator');
	});

	/*
	 * Sent whatever the invitee owns — a refusal here would tell the inviter whether the address is an administrator
	 * who owns projects (specs/103) — and judged when accepted, leaving it usable once they have room.
	 */
	it('sends an owner invitation to an administrator at the limit, and refuses its acceptance', async () => {
		const owner = await tenant();
		const full = await tenant();
		const invited = await call(
			'POST',
			`/admin/api/teams/${owner.teamId}/invitations`,
			owner.cookie,
			{ email: full.user.email, role: 'owner' }
		);

		const later = await newcomer();
		const token = `tok-${Math.random().toString(36).slice(2)}`;
		await getGroupInvitationStore().create({
			groupId: owner.teamId,
			email: later.user.email,
			role: 'owner',
			invitedBy: owner.user._id,
			tokenHash: invitationTokenHash(token),
			ttlSeconds: INVITATION_TTL_SECONDS
		});
		await regularGroup([later.user]);
		const accepted = await call('POST', '/admin/api/invitations/accept', '', {
			token
		});
		const team = await getGroupStore().find(owner.teamId);

		expect(invited.status).toBe(201);
		expect(refusalOf(accepted).limit.name).toBe('regularTeamsPerAdministrator');
		expect(team?.members.some((m) => m.userId === later.user._id)).toBe(false);
	});

	it('does not limit a super administrator, whose project still counts for the team’s owners', async () => {
		const owner = await tenant();
		await twoProjects(owner);

		const byOperator = await createProject(operator, {
			teamId: owner.teamId,
			slug: `op-${Math.random().toString(36).slice(2, 10)}`
		});
		const byOwner = await createProject(owner);

		expect([byOperator.status, byOwner.status]).toEqual([201, 409]);
	});
});
