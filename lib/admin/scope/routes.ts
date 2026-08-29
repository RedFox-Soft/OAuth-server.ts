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
import { recordAdminAudit } from '../audit/record.js';
import { SwitchScopeBody } from './schema.js';

/*
 * The console's active scope: which group is being administered right now.
 *
 * Its own route group rather than part of `me.ts`, for two reasons. `me.ts` is re-dispatched by the
 * MCP `whoami` tool and must stay a pure read, while switching is a state change that is audited. And
 * an agent has no session to switch, so it names its group per call instead — keeping the two on
 * separate routes is what stops the agent surface growing a session it does not have.
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
		 */
		const available = ctx.roles.includes('super_admin')
			? await getGroupStore().list()
			: await getGroupStore().listByMember(ctx.userId);
		return {
			activeGroupId: ctx.activeGroupId,
			available: available.map((g) => ({
				id: g._id,
				name: g.name,
				kind: g.kind,
				role: ctx.memberships.find((m) => m.groupId === g._id)?.role ?? null
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
			 * A super administrator may switch to any group that exists: they can already reach every
			 * container, and refusing them a scope would leave them unable to create into one.
			 */
			const group = await getGroupStore().find(body.groupId);
			if (!group) throw new AdminError(403, 'no access to this group');
			if (
				!ctx.roles.includes('super_admin') &&
				!ctx.memberships.some((m) => m.groupId === body.groupId)
			) {
				throw new AdminError(403, 'no access to this group');
			}

			const sessionId = cookie[ADMIN_SESSION_COOKIE]?.value as
				string | undefined;
			if (!sessionId) {
				/*
				 * Reachable only through the agent surface, which authenticates with a bearer token and has
				 * no session to write the choice to. Said plainly rather than answering 200 to a switch that
				 * did not happen — an agent names its group per call instead.
				 */
				throw new AdminError(
					400,
					'the active scope is a console session setting; name the group per call instead'
				);
			}

			await recordAdminAudit(ctx, 'scope.switch', body.groupId, {
				ownerGroupId: body.groupId
			});
			await adminSessionStore.setActiveGroup(sessionId, body.groupId);
			return { activeGroupId: body.groupId };
		},
		{ body: SwitchScopeBody }
	);
