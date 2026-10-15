import type { AdminContext } from './auth/rbac.js';

/*
 * The caller as the edge names them (specs/100): the administrators' project and the teams they belong
 * to. The context itself keeps the stored names it is resolved from; this is what `/admin/api/me` answers
 * and what the console shell is seeded with, so both say the same thing.
 */
export interface AdminMeView {
	userId: string;
	email: string;
	superAdmin: boolean;
	projectId: string;
	memberships: { teamId: string; role: 'owner' | 'member' }[];
	activeTeamId: string;
	viaClientId?: string;
	signedInWith: string | null;
}

export function meView(ctx: AdminContext): AdminMeView {
	return {
		userId: ctx.userId,
		email: ctx.email,
		superAdmin: ctx.superAdmin,
		projectId: ctx.bucketId,
		memberships: ctx.memberships.map((m) => ({
			teamId: m.groupId,
			role: m.role
		})),
		activeTeamId: ctx.activeGroupId,
		...(ctx.viaClientId === undefined ? {} : { viaClientId: ctx.viaClientId }),
		signedInWith: ctx.signedInWith
	};
}
