import { t } from 'elysia';

/*
 * `ownerGroupId` appears in none of these bodies, and that is the point: a container's group is taken
 * from the caller's active scope, never from the request. A settable owner would be a way to place a
 * container in a tenant by asserting an id.
 */

const MembershipRole = t.Union([t.Literal('owner'), t.Literal('member')]);

export const CreateGroupBody = t.Object({
	name: t.String({ minLength: 1, maxLength: 100 })
});

export const UpdateGroupBody = t.Object({
	name: t.Optional(t.String({ minLength: 1, maxLength: 100 })),
	/*
	 * Clearing the migration's review flag. Settable but never *un*settable by a caller — a group is
	 * flagged only by the migration, and letting a request re-raise the flag would let one group claim
	 * an operator's attention indefinitely.
	 */
	needsReview: t.Optional(t.Literal(false))
});

export const AddMemberBody = t.Object({
	userId: t.String({ minLength: 1 }),
	role: MembershipRole
});

export const UpdateMemberBody = t.Object({
	role: MembershipRole
});

export const CreateInvitationBody = t.Object({
	email: t.String({ format: 'email', maxLength: 320 }),
	role: MembershipRole
});

/*
 * Acceptance carries the token and, when the invitation creates an account, the password that account
 * will have. The password is optional because an invitee who already has an administrator account is
 * only joining a group — asking them to set a new password would be a credential change nobody
 * requested.
 */
export const AcceptInvitationBody = t.Object({
	token: t.String({ minLength: 1 }),
	password: t.Optional(t.String({ minLength: 8, maxLength: 200 }))
});
