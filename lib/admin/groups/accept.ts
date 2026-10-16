import { Elysia } from 'elysia';
import {
	getBucketStore,
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
import { assertMayBecomeOwner } from '../../plans/enforce.js';
import { signOutAdministrator } from '../users/sign_out.js';
import { clearAttempts } from '../../totp/verify.js';

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
			 * Whether a password is needed is settled before the claim below. Claiming first meant a new
			 * invitee who submitted without one spent the invitation on the refusal, and every retry was then
			 * refused as not valid.
			 */
			const users = getUserStore(ADMIN_BUCKET_ID);
			const existing = await users.findByEmail(invitation.email);
			// A deactivated account is not one an invitation may bring back, by joining it or by reclaiming it.
			if (existing && !existing.active) throw invalid();
			if (!existing && !body.password) {
				throw new AdminError(
					400,
					'a password is required to create your administrator account'
				);
			}
			/*
			 * An account under this address whose address nobody has proven may belong to somebody else: anyone may
			 * register an administrator account under any address while sign-up is open, and joining it here
			 * handed them the team, even as an owner (specs/103). Holding the token proves the mailbox, as a
			 * password reset relies on, so the invitee takes the account over — with a password of their own,
			 * chosen here, before the claim below spends the invitation.
			 *
			 * Only while this bucket requires verification. That is the only state sign-up can be open in, so the
			 * only one a stranger's account can come from; and an unproven account cannot sign in then anyway, so
			 * its real owner loses nothing by the reset. With verification off, sign-up is closed, every account
			 * was made by an operator, and most are unproven simply because nobody was ever asked to prove one —
			 * resetting those would sign a colleague out of everything for accepting an invitation.
			 */
			const adminBucket = await getBucketStore().find(ADMIN_BUCKET_ID);
			const reclaiming =
				existing !== null &&
				!existing.verified &&
				adminBucket?.emailVerificationRequired === true;
			if (reclaiming && !body.password) {
				throw new AdminError(
					400,
					'choose a password to finish joining: it becomes the password of the administrator account for this address'
				);
			}

			/*
			 * Before the claim, so a refusal leaves the invitation usable once the invitee has room (specs/102).
			 * Their allowance as it is now, not as it was when they were invited: the plan judges what they would
			 * own on accepting.
			 */
			if (invitation.role === 'owner') {
				const inviting = await getGroupStore().find(invitation.groupId);
				if (inviting) {
					await assertMayBecomeOwner(
						{ superAdmin: false, userId: existing?._id },
						existing?._id,
						inviting
					);
				}
			}

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

			let userId: string;
			if (existing && reclaiming) {
				/*
				 * Nothing the earlier registrant set up may survive: their password, a second factor they enrolled
				 * (the invitee would be stopped by it), an upstream identity they linked (a way back in), and every
				 * session and token they hold.
				 */
				await users.update(existing._id, {
					password: await Bun.password.hash(body.password ?? ''),
					passwordSet: true,
					verified: true,
					totp: undefined,
					federated: []
				});
				// So the invitee's own enrolment does not begin inside a lockout the earlier registrant earned.
				await clearAttempts(ADMIN_BUCKET_ID, existing._id);
				await signOutAdministrator(existing._id);
				userId = existing._id;
			} else if (existing) {
				// Already an administrator: they join the group and nothing else about the account changes.
				// Asking them for a password here would be a credential change nobody requested.
				userId = existing._id;
			} else {
				const created = await users.create(
					invitation.email,
					await Bun.password.hash(body.password ?? ''),
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
				ownerGroupId: group._id,
				// So the owners can see that joining reset an account rather than adding one as it was.
				...(reclaiming ? { attributes: ['address-reclaimed'] } : {})
			});

			return { ok: true, teamId: group._id };
		},
		{ body: AcceptInvitationBody }
	);
