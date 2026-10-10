import { Elysia } from 'elysia';
import {
	getGroupStore,
	getGroupInvitationStore,
	getProjectStore,
	getBucketStore,
	getUserStore
} from '../../adapters/index.js';
import type { Group, GroupMember } from '../../adapters/types.js';
import {
	assertAuth,
	assertGroupMember,
	assertGroupOwner,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { isSuperAdminsGroup } from '../super_admins.js';
import { recordAdminAudit } from '../audit/record.js';
import nanoid from '../../helpers/nanoid.js';
import {
	CreateGroupBody,
	UpdateGroupBody,
	AddMemberBody,
	UpdateMemberBody,
	CreateInvitationBody
} from './schema.js';
import {
	INVITATION_TTL_SECONDS,
	invitationTokenHash,
	invitationUrlFor,
	newInvitationToken
} from './invite.js';
import { sendGroupInvitationEmail } from '../../mail/send.js';

/*
 * Loads a group the caller may see, refusing identically whether it is missing or another tenant's.
 *
 * Same rule the project and bucket loaders follow, and for the same reason: a status that differs
 * between "does not exist" and "exists but is not yours" is an oracle for enumerating group ids.
 */
async function loadGroup(admin: AdminContext, id: string): Promise<Group> {
	/*
	 * Super administrators is not a group anyone works in or manages through these routes: its membership is
	 * the instance privilege, changed only by the grant and withdraw operations. To this surface it does not
	 * exist, for every caller.
	 */
	if (isSuperAdminsGroup(id)) throw new AdminError(404, 'group not found');
	const group = await getGroupStore().find(id);
	if (!group) {
		if (admin.superAdmin) {
			throw new AdminError(404, 'group not found');
		}
		throw new AdminError(403, 'no access to this group');
	}
	assertGroupMember(admin, id);
	return group;
}

/*
 * The one group that is not a tenant: the reserved holding group, which has no members and exists only
 * to own containers no administrator managed.
 */
function assertMutableMembership(group: Group): void {
	if (group.kind === 'system') {
		throw new AdminError(403, 'the System group is not a tenant');
	}
}

/*
 * A personal group is one administrator's own workspace and nobody else's (specs/075), so nobody joins it
 * — by addition or by invitation, whoever asks.
 *
 * It was shareable until then, and sharing it is what made "their personal group" ambiguous: an
 * administrator added to a colleague's personal group had two, and the console could pick the wrong one as
 * their default scope. Work meant for several people belongs in a regular group, and the move routes carry
 * a bucket and its projects there from a personal one.
 *
 * Checked after the owner check, so a non-owner still gets the refusal that says nothing about the group.
 */
function assertShareable(group: Group): void {
	if (group.kind === 'personal') {
		throw new AdminError(
			403,
			'a personal group cannot be shared; create a regular group and move the work there'
		);
	}
}

function assertDeletable(group: Group): void {
	if (group.kind !== 'regular') {
		throw new AdminError(
			403,
			group.kind === 'personal'
				? 'a personal group cannot be deleted'
				: 'the System group cannot be deleted'
		);
	}
}

/* How many containers a group still owns. Drives the refusal to delete one that is not empty. */
async function ownedContainerCount(groupId: string): Promise<{
	projects: number;
	buckets: number;
}> {
	const [projects, buckets] = await Promise.all([
		getProjectStore().listByGroup(groupId),
		getBucketStore().listByGroup(groupId)
	]);
	return { projects: projects.length, buckets: buckets.length };
}

/*
 * Applies a membership change and refuses the one that cannot be undone: a group with no owner owns
 * containers nobody can grant access to, and only a super administrator could ever reach them again.
 *
 * Checked on the *prospective* list rather than the current one, so demoting the last owner and
 * removing them are the same check rather than two that can drift.
 */
function assertOwnerRemains(members: GroupMember[]): void {
	if (!members.some((m) => m.role === 'owner')) {
		throw new AdminError(409, 'a group must keep at least one owner');
	}
}

export const groupRoutes = new Elysia({ name: 'admin-groups' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/groups', async ({ admin }) => {
		const ctx = assertAuth(admin);
		/*
		 * Scope-filtered, not role-gated. Unlike projects and buckets this is NOT restricted to the active
		 * scope: the list is what the scope switcher is built from, so restricting it to the current scope
		 * would leave an administrator no way to reach their other groups.
		 */
		const groups = ctx.superAdmin
			? await getGroupStore().list()
			: await getGroupStore().listByMember(ctx.userId);
		return groups.filter((g) => !isSuperAdminsGroup(g._id));
	})
	.post(
		'/admin/api/groups',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			// Allocated here so the audit entry can name the group that is about to exist.
			const groupId = nanoid();
			await recordAdminAudit(ctx, 'group.create', groupId, {
				ownerGroupId: groupId
			});
			const group = await getGroupStore().create({
				_id: groupId,
				name: body.name,
				kind: 'regular',
				// The creator is the first owner. Nothing else could be: a group created with no owner
				// would be unreachable the instant it existed.
				members: [{ userId: ctx.userId, role: 'owner' }]
			});
			set.status = 201;
			return group;
		},
		{ body: CreateGroupBody }
	)
	.get('/admin/api/groups/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		// A plain member may read the membership list; only an owner may change it.
		return loadGroup(ctx, params.id);
	})
	.patch(
		'/admin/api/groups/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const group = await loadGroup(ctx, params.id);
			assertGroupOwner(ctx, params.id);
			/* A system group's name is the console's label for a reserved purpose; the seed sets it. */
			if (group.kind === 'system') {
				throw new AdminError(403, 'a system group cannot be renamed');
			}
			await recordAdminAudit(ctx, 'group.update', params.id, {
				attributes: Object.keys(body),
				ownerGroupId: params.id
			});
			const updated = await getGroupStore().update(params.id, body);
			if (!updated) throw new AdminError(404, 'group not found');
			return updated;
		},
		{ body: UpdateGroupBody }
	)
	.delete('/admin/api/groups/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const group = await loadGroup(ctx, params.id);
		assertGroupOwner(ctx, params.id);
		assertDeletable(group);
		/*
		 * Guarded rather than cascaded, like a project or a bucket. Destroying a group would orphan every
		 * container pointing at it — reachable by nobody, listed by nothing — so the refusal names what is
		 * in the way and the operator empties it deliberately.
		 */
		const held = await ownedContainerCount(params.id);
		if (held.projects > 0 || held.buckets > 0) {
			throw new AdminError(409, 'group still owns projects or buckets', {
				blockers: [
					...(held.projects > 0
						? [{ kind: 'client' as const, count: held.projects }]
						: []),
					...(held.buckets > 0
						? [{ kind: 'enduser' as const, count: held.buckets }]
						: [])
				]
			});
		}
		await recordAdminAudit(ctx, 'group.delete', params.id, {
			ownerGroupId: params.id
		});
		await getGroupStore().destroy(params.id);
		return { ok: true };
	})
	.post(
		'/admin/api/groups/:id/members',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const group = await loadGroup(ctx, params.id);
			assertGroupOwner(ctx, params.id);
			assertMutableMembership(group);
			assertShareable(group);

			// Only an existing administrator can be added. Bringing somebody in who has no account is an
			// invitation, which is a different operation with a different audit action.
			const user = await getUserStore(ADMIN_BUCKET_ID).find(body.userId);
			if (!user) throw new AdminError(404, 'administrator not found');
			if (group.members.some((m) => m.userId === body.userId)) {
				throw new AdminError(409, 'already a member of this group');
			}

			const members = [
				...group.members,
				{ userId: body.userId, role: body.role }
			];
			await recordAdminAudit(ctx, 'group.member.add', params.id, {
				attributes: [body.role],
				ownerGroupId: params.id
			});
			return getGroupStore().update(params.id, { members });
		},
		{ body: AddMemberBody }
	)
	.patch(
		'/admin/api/groups/:id/members/:userId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const group = await loadGroup(ctx, params.id);
			assertGroupOwner(ctx, params.id);
			assertMutableMembership(group);
			if (!group.members.some((m) => m.userId === params.userId)) {
				throw new AdminError(404, 'not a member of this group');
			}
			const members = group.members.map((m) =>
				m.userId === params.userId ? { ...m, role: body.role } : m
			);
			// Applies to demoting yourself as much as anyone else: the invariant is about the group, not
			// about who is asking.
			assertOwnerRemains(members);
			await recordAdminAudit(ctx, 'group.member.update', params.id, {
				attributes: [body.role],
				ownerGroupId: params.id
			});
			return getGroupStore().update(params.id, { members });
		},
		{ body: UpdateMemberBody }
	)
	.delete(
		'/admin/api/groups/:id/members/:userId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const group = await loadGroup(ctx, params.id);
			assertGroupOwner(ctx, params.id);
			assertMutableMembership(group);
			if (!group.members.some((m) => m.userId === params.userId)) {
				throw new AdminError(404, 'not a member of this group');
			}
			const members = group.members.filter((m) => m.userId !== params.userId);
			assertOwnerRemains(members);
			/*
			 * The removed member loses access to everything the group owns on their next request: nothing
			 * here touches their session, because `contextFor` re-reads memberships per request rather than
			 * trusting anything cached at sign-in.
			 */
			await recordAdminAudit(ctx, 'group.member.remove', params.id, {
				ownerGroupId: params.id
			});
			return getGroupStore().update(params.id, { members });
		}
	)
	.get('/admin/api/groups/:id/invitations', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		await loadGroup(ctx, params.id);
		// A plain member may see who has been invited, as they may see who is already in the group. The
		// token is never part of an invitation record's readable shape, so nothing is masked here.
		const pending = await getGroupInvitationStore().listByGroup(params.id);
		return pending.map(({ tokenHash: _tokenHash, ...rest }) => rest);
	})
	.post(
		'/admin/api/groups/:id/invitations',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const group = await loadGroup(ctx, params.id);
			assertGroupOwner(ctx, params.id);
			assertMutableMembership(group);
			assertShareable(group);

			const email = body.email.trim().toLowerCase();
			const existing = await getUserStore(ADMIN_BUCKET_ID).findByEmail(email);
			if (existing && group.members.some((m) => m.userId === existing._id)) {
				throw new AdminError(409, 'already a member of this group');
			}

			/*
			 * The token exists only in this scope and in the mail. What is stored is its digest, so a
			 * database read yields nothing usable — an invitation is an offer of access to everything the
			 * group owns.
			 */
			const token = newInvitationToken();
			const invitation = await getGroupInvitationStore().create({
				groupId: params.id,
				email,
				role: body.role,
				invitedBy: ctx.userId,
				tokenHash: invitationTokenHash(token),
				ttlSeconds: INVITATION_TTL_SECONDS
			});

			await recordAdminAudit(ctx, 'invitation.create', params.id, {
				attributes: [body.role],
				ownerGroupId: params.id
			});

			/*
			 * Sent after the record exists, and the throw is NOT swallowed. The password-reset flow hides a
			 * delivery failure because a visible one would only ever be visible for an address that has an
			 * account; here the sender is an owner who chose the address deliberately and needs to know the
			 * mail did not go.
			 */
			await sendGroupInvitationEmail({
				email,
				// The console's own name, as the reset and verification mails take theirs from the bucket.
				appName: 'the admin console',
				groupName: group.name,
				invitedByEmail: ctx.email,
				acceptUrl: invitationUrlFor(token),
				createsAccount: !existing
			});

			set.status = 201;
			const { tokenHash: _tokenHash, ...safe } = invitation;
			return safe;
		},
		{ body: CreateInvitationBody }
	)
	.delete(
		'/admin/api/groups/:id/invitations/:inviteId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			await loadGroup(ctx, params.id);
			assertGroupOwner(ctx, params.id);
			const invitation = await getGroupInvitationStore().find(params.inviteId);
			// Checked against the group in the path, so an owner of one group cannot revoke another's
			// invitation by guessing its id.
			if (!invitation || invitation.groupId !== params.id) {
				throw new AdminError(404, 'invitation not found');
			}
			await recordAdminAudit(ctx, 'invitation.revoke', params.id, {
				ownerGroupId: params.id
			});
			await getGroupInvitationStore().destroy(params.inviteId);
			return { ok: true };
		}
	);
