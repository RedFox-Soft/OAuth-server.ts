import { Elysia } from 'elysia';
import {
	getGroupInvitationStore,
	getGroupStore,
	getUserStore
} from '../../adapters/index.js';
import { AdminError, adminErrorBody } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { recordBootstrapAudit } from '../audit/record.js';
import { ensurePersonalGroup } from './personal.js';
import { invitationTokenHash } from './invite.js';
import { AcceptInvitationBody } from './schema.js';

/*
 * Accepting an invitation into a group.
 *
 * Its own plugin, and deliberately outside `groupRoutes`, because it is the one route here that must
 * work with no session at all — the whole point is that the invitee does not have an account yet. It
 * mounts without `resolveAdmin` so there is no path on which an authenticated context could be
 * mistaken for authority: the token is the only credential, and it authorizes exactly one thing.
 *
 * Classified `strict` in lib/consts/route_classification.ts for the reason `POST /admin/api/setup` is:
 * unauthenticated, and it performs an account write.
 */
export const invitationAcceptRoutes = new Elysia({ name: 'admin-invitations' })
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.post(
		'/admin/api/invitations/accept',
		async ({ body }) => {
			/*
			 * One refusal for every reason an invitation is not usable — unknown token, expired, already
			 * accepted, group since deleted. Which one it was is not something an unauthenticated caller
			 * gets to probe for: distinguishing "expired" from "never existed" would confirm that a token
			 * was once real.
			 */
			const invalid = () => new AdminError(400, 'invitation is not valid');

			const invitation = await getGroupInvitationStore().findByTokenHash(
				invitationTokenHash(body.token)
			);
			if (!invitation || invitation.acceptedAt) throw invalid();

			/*
			 * Claimed in one insert-if-absent before anything is written. Checking `acceptedAt` and marking it
			 * last let two acceptances arriving together both go through, one of them writing the group's
			 * membership from a copy read before the other's change. The claim lives as long as the
			 * invitation does; `acceptedAt` keeps refusing it after that.
			 *
			 * Imported here rather than at the top: the model graph must not be entered cold from a module
			 * the admin routes load (wiki/concepts/model-graph-import-order.md).
			 */
			const { ReplayDetection } =
				await import('../../models/replay_detection.js');
			if (
				!(await ReplayDetection.unique(
					'group-invitation',
					invitation._id,
					Math.floor(invitation.expiresAt.getTime() / 1000)
				))
			) {
				throw invalid();
			}

			const group = await getGroupStore().find(invitation.groupId);
			if (!group) throw invalid();
			/*
			 * An invitation into a personal group may predate the rule that nobody joins one (specs/075); it
			 * must not complete now. The same refusal as every other unusable invitation, for its reason.
			 */
			if (group.kind === 'personal') throw invalid();

			/*
			 * The inviting owner must still be one. An invitation issued by somebody who has since been
			 * removed from the group, or demoted, is an authority that no longer exists — honouring it
			 * would let a departed owner keep adding people after the fact.
			 */
			const inviterStillOwner = group.members.some(
				(m) => m.userId === invitation.invitedBy && m.role === 'owner'
			);
			if (!inviterStillOwner) throw invalid();

			const users = getUserStore(ADMIN_BUCKET_ID);
			const existing = await users.findByEmail(invitation.email);

			let userId: string;
			if (existing) {
				// Already an administrator: they join the group and nothing else about the account changes.
				// Asking them for a password here would be a credential change nobody requested.
				userId = existing._id;
			} else {
				if (!body.password) {
					throw new AdminError(
						400,
						'a password is required to create your administrator account'
					);
				}
				const created = await users.create(
					invitation.email,
					await Bun.password.hash(body.password),
					// An invitation grants membership of the inviting group and nothing else — never the
					// instance privilege, which only a super administrator grants, by its own operation.
					true
				);
				userId = created._id;
				// Their own scope, created with the account exactly as it is for an administrator a super
				// administrator creates directly.
				await ensurePersonalGroup(userId, invitation.email);
			}

			if (!group.members.some((m) => m.userId === userId)) {
				await getGroupStore().update(group._id, {
					members: [...group.members, { userId, role: invitation.role }]
				});
			}
			await getGroupInvitationStore().markAccepted(invitation._id);

			/*
			 * The bootstrap actor, for the reason first-run setup uses it: there is no signed-in
			 * administrator to attribute this to. The entry names the group so it lands in that group's
			 * trail, where the owners who issued the invitation can see it was taken up.
			 */
			await recordBootstrapAudit('invitation.accept', group._id, {
				ownerGroupId: group._id
			});

			return { ok: true, groupId: group._id };
		},
		{ body: AcceptInvitationBody }
	);
