import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { invitationAcceptRoutes } from 'lib/admin/groups/accept.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { getGroupInvitationStore, getGroupStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import {
	INVITATION_TTL_SECONDS,
	invitationTokenHash,
	newInvitationToken
} from 'lib/admin/groups/invite.ts';
import { resetSentEmails, emailsTo } from '../mail_capture.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(groupRoutes)
	.use(invitationAcceptRoutes);
const client = treaty(app);

function admin(kind: AdminKind = 'plain'): Promise<User> {
	return createAdministrator(
		kind,
		`share-${Math.random().toString(36).slice(2)}@x.io`
	);
}

async function membersOf(groupId: string) {
	return (await getGroupStore().find(groupId))?.members ?? [];
}

const REFUSAL =
	'a personal group cannot be shared; create a regular group and move the work there';

/**
 * @proves A personal group never gains a member — not by direct addition, not by invitation, and not by
 * accepting an invitation issued before personal groups stopped being shareable — whoever asks, while a
 * regular group is shared as before.
 */
describe('sharing a personal group', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		resetSentEmails();
	});

	it('refuses its owner adding a colleague, and the membership is unchanged', async () => {
		const owner = await admin();
		const colleague = await admin();
		const personal = await ensurePersonalGroup(owner._id, owner.email);

		const res = await client.admin.api
			.groups({ id: personal._id })
			.members.post(
				{ userId: colleague._id, role: 'member' },
				{ headers: { cookie: await cookieFor(owner) } }
			);

		expect(res.status).toBe(403);
		expect(res.error?.value).toMatchObject({ message: REFUSAL });
		expect(await membersOf(personal._id)).toEqual([
			{ userId: owner._id, role: 'owner' }
		]);
	});

	it('refuses a super administrator adding someone to another administrator’s personal group', async () => {
		const owner = await admin();
		const superAdmin = await admin('super');
		const personal = await ensurePersonalGroup(owner._id, owner.email);

		const res = await client.admin.api
			.groups({ id: personal._id })
			.members.post(
				{ userId: superAdmin._id, role: 'owner' },
				{ headers: { cookie: await cookieFor(superAdmin) } }
			);

		expect(res.status).toBe(403);
		expect(await membersOf(personal._id)).toHaveLength(1);
	});

	it('refuses an invitation into it, storing none and sending no email', async () => {
		const owner = await admin();
		const personal = await ensurePersonalGroup(owner._id, owner.email);
		const invitee = `invitee-${Math.random().toString(36).slice(2)}@x.io`;

		const res = await client.admin.api
			.groups({ id: personal._id })
			.invitations.post(
				{ email: invitee, role: 'member' },
				{ headers: { cookie: await cookieFor(owner) } }
			);

		expect(res.status).toBe(403);
		expect(await getGroupInvitationStore().listByGroup(personal._id)).toEqual(
			[]
		);
		expect(emailsTo(invitee)).toEqual([]);
	});

	it('refuses accepting an invitation into it issued before the rule, adding nobody', async () => {
		const owner = await admin();
		const invitee = await admin();
		const personal = await ensurePersonalGroup(owner._id, owner.email);
		const token = newInvitationToken();
		await getGroupInvitationStore().create({
			groupId: personal._id,
			email: invitee.email,
			role: 'member',
			invitedBy: owner._id,
			tokenHash: invitationTokenHash(token),
			ttlSeconds: INVITATION_TTL_SECONDS
		});

		const res = await client.admin.api.invitations.accept.post({ token });

		expect(res.status).toBe(400);
		expect(res.error?.value).toMatchObject({
			message: 'invitation is not valid'
		});
		expect(await membersOf(personal._id)).toEqual([
			{ userId: owner._id, role: 'owner' }
		]);
	});

	it('leaves it personal when a rename carries a kind', async () => {
		const owner = await admin();
		const personal = await ensurePersonalGroup(owner._id, owner.email);

		await client.admin.api.groups({ id: personal._id }).patch(
			// @ts-expect-error -- `kind` is off-schema on purpose: the body declares only `name`.
			{ name: 'Mine', kind: 'regular' },
			{ headers: { cookie: await cookieFor(owner) } }
		);

		expect((await getGroupStore().find(personal._id))?.kind).toBe('personal');
	});

	it('still adds a member to a regular group its caller owns', async () => {
		const owner = await admin();
		const colleague = await admin();
		const team = await regularGroup([owner]);

		const res = await client.admin.api
			.groups({ id: team._id })
			.members.post(
				{ userId: colleague._id, role: 'member' },
				{ headers: { cookie: await cookieFor(owner) } }
			);

		expect(res.status).toBe(200);
		expect(await membersOf(team._id)).toContainEqual({
			userId: colleague._id,
			role: 'member'
		});
	});

	it('still invites into a regular group its caller owns', async () => {
		const owner = await admin();
		const team = await regularGroup([owner]);
		const invitee = `invitee-${Math.random().toString(36).slice(2)}@x.io`;

		const res = await client.admin.api
			.groups({ id: team._id })
			.invitations.post(
				{ email: invitee, role: 'member' },
				{ headers: { cookie: await cookieFor(owner) } }
			);

		expect(res.status).toBe(201);
		expect(emailsTo(invitee)).toHaveLength(1);
	});
});
