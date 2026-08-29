import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { invitationAcceptRoutes } from 'lib/admin/groups/accept.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, getGroupStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { Group } from 'lib/adapters/types.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import {
	resetSentEmails,
	emailsTo,
	extractInvitationToken
} from '../mail_capture.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(groupRoutes)
	.use(invitationAcceptRoutes);
const client = treaty(app);

const unique = () => Math.random().toString(36).slice(2);

async function admin(roles: string[] = ['project_admin']) {
	const email = `inv-${unique()}@x.io`;
	const user = await getUserStore(ADMIN_BUCKET_ID).create(email, 'hash', roles);
	const session = await sessionFor(user);
	return {
		userId: user._id,
		email,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`
	};
}

async function groupOwnedBy(cookie: string, name = 'Acme') {
	const res = await client.admin.api.groups.post(
		{ name },
		{ headers: { cookie } }
	);
	return res.data as Group;
}

async function invite(cookie: string, groupId: string, email: string) {
	return client.admin.api
		.groups({ id: groupId })
		.invitations.post({ email, role: 'member' }, { headers: { cookie } });
}

function tokenFor(email: string): string {
	const [mail] = emailsTo(email);
	const token = mail && extractInvitationToken(mail);
	if (!token) throw new Error(`no invitation mailed to ${email}`);
	return token;
}

describe('group invitations', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		resetSentEmails();
	});

	it('creates an account and a personal group for a new email', async () => {
		const owner = await admin();
		const group = await groupOwnedBy(owner.cookie);
		const invitee = `new-${unique()}@x.io`;

		const sent = await invite(owner.cookie, group._id, invitee);
		expect(sent.status).toBe(201);
		// The token is mailed and never returned: a caller who can read the API response must not come
		// away holding the secret.
		expect(JSON.stringify(sent.data)).not.toContain('tokenHash');

		const accepted = await client.admin.api.invitations.accept.post({
			token: tokenFor(invitee),
			password: 'a-long-enough-password'
		});
		expect(accepted.status).toBe(200);

		const account = await getUserStore(ADMIN_BUCKET_ID).findByEmail(invitee);
		expect(account).not.toBeNull();
		// Exactly one instance role, and never the super one.
		expect(account!.roles).toEqual(['project_admin']);

		const joined = await getGroupStore().find(group._id);
		expect(joined!.members.map((m) => m.userId)).toContain(account!._id);
		// Their own scope exists too, so they land somewhere usable on first sign-in.
		expect(await personalGroupId(account!._id)).toBeString();
	});

	it('adds an existing administrator without creating a second account', async () => {
		const owner = await admin();
		const existing = await admin();
		const group = await groupOwnedBy(owner.cookie);

		await invite(owner.cookie, group._id, existing.email);
		const accepted = await client.admin.api.invitations.accept.post({
			token: tokenFor(existing.email)
		});
		expect(accepted.status).toBe(200);

		const joined = await getGroupStore().find(group._id);
		expect(joined!.members.map((m) => m.userId)).toContain(existing.userId);
		// The same account, not a second one wearing the same address.
		const account = await getUserStore(ADMIN_BUCKET_ID).findByEmail(
			existing.email
		);
		expect(account!._id).toBe(existing.userId);
	});

	it('accepts once and no more', async () => {
		const owner = await admin();
		const group = await groupOwnedBy(owner.cookie);
		const invitee = `once-${unique()}@x.io`;
		await invite(owner.cookie, group._id, invitee);
		const token = tokenFor(invitee);

		expect(
			(
				await client.admin.api.invitations.accept.post({
					token,
					password: 'a-long-enough-password'
				})
			).status
		).toBe(200);
		expect(
			(
				await client.admin.api.invitations.accept.post({
					token,
					password: 'a-long-enough-password'
				})
			).status
		).toBe(400);
	});

	it('refuses an unknown token exactly as it refuses a spent one', async () => {
		const res = await client.admin.api.invitations.accept.post({
			token: 'not-a-real-token',
			password: 'a-long-enough-password'
		});
		// Distinguishing "never existed" from "already used" would confirm a token was once real.
		expect(res.status).toBe(400);
	});

	it('refuses after the group is deleted', async () => {
		const owner = await admin();
		const group = await groupOwnedBy(owner.cookie);
		const invitee = `gone-${unique()}@x.io`;
		await invite(owner.cookie, group._id, invitee);
		const token = tokenFor(invitee);

		await client.admin.api
			.groups({ id: group._id })
			.delete(undefined, { headers: { cookie: owner.cookie } });

		const res = await client.admin.api.invitations.accept.post({
			token,
			password: 'a-long-enough-password'
		});
		expect(res.status).toBe(400);
	});

	/*
	 * An invitation issued by somebody who has since lost ownership is an authority that no longer
	 * exists. Honouring it would let a departed owner keep adding people to a group after the fact.
	 */
	it('refuses once the inviting owner is no longer an owner', async () => {
		const founder = await admin();
		const second = await admin();
		const group = await groupOwnedBy(founder.cookie);
		await client.admin.api
			.groups({ id: group._id })
			.members.post(
				{ userId: second.userId, role: 'owner' },
				{ headers: { cookie: founder.cookie } }
			);

		const invitee = `stale-${unique()}@x.io`;
		await invite(second.cookie, group._id, invitee);
		const token = tokenFor(invitee);

		// The founder demotes the inviter, so their outstanding invitation stops working.
		await client.admin.api
			.groups({ id: group._id })
			.members({ userId: second.userId })
			.patch({ role: 'member' }, { headers: { cookie: founder.cookie } });

		const res = await client.admin.api.invitations.accept.post({
			token,
			password: 'a-long-enough-password'
		});
		expect(res.status).toBe(400);
	});

	it('lets only an owner invite, and only into their own group', async () => {
		const owner = await admin();
		const member = await admin();
		const outsider = await admin();
		const group = await groupOwnedBy(owner.cookie);
		await client.admin.api
			.groups({ id: group._id })
			.members.post(
				{ userId: member.userId, role: 'member' },
				{ headers: { cookie: owner.cookie } }
			);

		expect(
			(await invite(member.cookie, group._id, `x-${unique()}@x.io`)).status
		).toBe(403);
		expect(
			(await invite(outsider.cookie, group._id, `y-${unique()}@x.io`)).status
		).toBe(403);
	});

	it('withdraws a pending invitation before it is accepted', async () => {
		const owner = await admin();
		const group = await groupOwnedBy(owner.cookie);
		const invitee = `revoked-${unique()}@x.io`;
		const sent = await invite(owner.cookie, group._id, invitee);
		const token = tokenFor(invitee);
		const inviteId = (sent.data as { _id: string })._id;

		const revoked = await client.admin.api
			.groups({ id: group._id })
			.invitations({ inviteId })
			.delete(undefined, { headers: { cookie: owner.cookie } });
		expect(revoked.status).toBe(200);

		const res = await client.admin.api.invitations.accept.post({
			token,
			password: 'a-long-enough-password'
		});
		expect(res.status).toBe(400);
	});
});
