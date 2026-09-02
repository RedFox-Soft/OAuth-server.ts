import { Elysia } from 'elysia';
import { adminSessionStore, getGroupStore } from '../../adapters/index.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_SESSION_COOKIE } from '../consts.js';
import { SwitchScopeBody } from './schema.js';

/*
 * Membership as the switcher asks it: by group id, without the super-administrator bypass the `rbac`
 * helpers apply. Both routes below need the plain fact — a super administrator is not a member of every
 * group, and the personal-group carve-out is exactly the case where that difference decides the answer.
 */
function isMember(ctx: AdminContext, groupId: string): boolean {
	return ctx.memberships.some((m) => m.groupId === groupId);
}

/*
 * The console's active scope: which group is being administered right now.
 *
 * Its own route group rather than part of `me.ts`, for two reasons. `me.ts` is re-dispatched by the
 * MCP `whoami` tool and must stay a pure read, while switching writes to the session. And an agent has
 * no session to switch, so it names its group per call instead — keeping the two on separate routes is
 * what stops the agent surface growing a session it does not have.
 *
 * Switching writes no audit entry, and is one of the two routes `excludedAdminRoutes` names for it: the
 * session is the only thing it changes, and which scope a change was made from is already recorded as
 * `ownerGroupId` on that change's own entry.
 */
export const scopeRoutes = new Elysia({ name: 'admin-scope' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/scope', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		/*
		 * Returns the groups themselves, not just their ids: the switcher needs names to render, and a
		 * second round trip per group to fetch them would make the console's first paint depend on how
		 * many tenants somebody belongs to.
		 *
		 * A super administrator is offered every group except another administrator's personal group — the
		 * same carve-out the switch below enforces, so the control never offers a scope the switch would
		 * refuse.
		 */
		const available = ctx.roles.includes('super_admin')
			? (await getGroupStore().list()).filter(
					(g) => g.kind !== 'personal' || isMember(ctx, g._id)
				)
			: await getGroupStore().listByMember(ctx.userId);
		return {
			activeGroupId: ctx.activeGroupId,
			available: available.map((g) => ({
				id: g._id,
				name: g.name,
				kind: g.kind,
				role: ctx.memberships.find((m) => m.groupId === g._id)?.role ?? null,
				/*
				 * Whether a personal group is the caller's own, which decides whether the console labels it
				 * "Personal" or names its owner. Resolved here rather than in the client because the client
				 * cannot: `role` does not answer it — a shared personal group may promote a second owner —
				 * and `members` is not part of this response.
				 */
				own: g.kind === 'personal' && g.members[0]?.userId === ctx.userId
			}))
		};
	})
	.put(
		'/admin/api/scope',
		async ({ admin, body, cookie }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			/*
			 * Validated against live membership, not against whatever the caller sends. This is the one
			 * place a client names a group directly, so it is the one place a stale or invented id could
			 * point a console at a tenant the caller has no business in.
			 *
			 * A super administrator may switch to any group that exists *except* an administrator's own
			 * personal group. The permission is there so instance-wide authority can create into a scope
			 * and support a group whose owners have gone — a personal group is neither: it is one person's
			 * own workspace, and pointing somebody else's console at it is not support. Reading it is still
			 * possible, as every other super-administrator bypass is; acting *as* it is not.
			 *
			 * All three refusals say the same thing, so a switch cannot be used to discover which group
			 * ids are real or which of them are personal.
			 */
			const group = await getGroupStore().find(body.groupId);
			if (!group) throw new AdminError(403, 'no access to this group');
			if (group.kind === 'personal' && !isMember(ctx, group._id)) {
				throw new AdminError(403, 'no access to this group');
			}
			if (!ctx.roles.includes('super_admin') && !isMember(ctx, body.groupId)) {
				throw new AdminError(403, 'no access to this group');
			}

			const sessionId = cookie[ADMIN_SESSION_COOKIE]?.value as
				string | undefined;
			if (!sessionId) {
				/*
				 * Reachable only by a bearer-token caller, which has no session to write the choice to. No
				 * MCP tool dispatches here — `PUT /admin/api/scope` is named in `excludedConsoleOperations`
				 * as inapplicable — but the admin API resolves both credential types, so a token holder can
				 * still call the route directly. Said plainly rather than answering 200 to a switch that did
				 * not happen; an agent names its group per call instead.
				 */
				throw new AdminError(
					400,
					'the active scope is a console session setting; name the group per call instead'
				);
			}

			await adminSessionStore.setActiveGroup(sessionId, body.groupId);
			return { activeGroupId: body.groupId };
		},
		{ body: SwitchScopeBody }
	);
