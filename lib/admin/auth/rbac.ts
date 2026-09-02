import { Elysia } from 'elysia';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore,
	getGroupStore
} from '../../adapters/index.js';
import type { Group, Project, UserBucket } from '../../adapters/types.js';
import { ApplicationConfig } from '../../configs/application.js';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	ADMIN_SESSION_TTL_SECONDS,
	UNASSIGNED_GROUP_ID
} from '../consts.js';

export interface AdminContext {
	userId: string;
	email: string;
	roles: string[];
	bucketId: string;
	/*
	 * Every group this administrator belongs to, and how. Replaces `managedProjectIds`, which named
	 * containers rather than the thing that grants access to them — and so could not answer "may this
	 * person add somebody to this tenant", which is not a question about any one container.
	 *
	 * Re-read on every request rather than cached at sign-in, so removing somebody from a group takes
	 * effect on their next call rather than at their next sign-in.
	 */
	memberships: { groupId: string; role: 'owner' | 'member' }[];
	/*
	 * The group this request acts in: what is listed, and where a new container is created. Resolved
	 * from the session and validated against `memberships` above, so it always names a group the caller
	 * still belongs to.
	 */
	activeGroupId: string;
	/*
	 * Set only when the request arrived through the MCP control plane rather than the console, and
	 * carries the agent's OAuth client id. Read by `recordAdminAudit`, which records it alongside the
	 * administrator so the trail names both the agent and the principal that authorized it.
	 *
	 * Absent means the console. That asymmetry is deliberate: it needs no backfill for the entries
	 * written before agents existed.
	 */
	viaClientId?: string;
}

/*
 * What a refused container deletion reports. Machine-readable on purpose: the console's confirmation
 * dialog and an MCP agent both need to list the consequences without parsing prose.
 *
 * `ids` is present for clients and absent for end-users, which is a privacy decision rather than an
 * omission — a project's clients are objects the operator administers, while a bucket may hold thousands
 * of accounts whose identities are not the caller's business.
 */
export interface DeletionBlocker {
	readonly kind: 'client' | 'enduser';
	readonly count: number;
	readonly ids?: readonly string[];
}

export class AdminError extends Error {
	/*
	 * Read by the root error handler (lib/shared/authorization_error_handler.ts) to stand aside and let
	 * the admin plane answer in its own shape. A marker on the error, not a path check, so an admin error
	 * raised from anywhere is still an admin error.
	 */
	readonly adminPlane = true;
	status: number;
	blockers?: readonly DeletionBlocker[];
	/* Areas whose sweep failed after the principal was already destroyed. Drives the 500 body. */
	failedAreas?: readonly string[];
	constructor(
		status: number,
		message: string,
		extra?: {
			blockers?: readonly DeletionBlocker[];
			failedAreas?: readonly string[];
		}
	) {
		super(message);
		this.status = status;
		this.blockers = extra?.blockers;
		this.failedAreas = extra?.failedAreas;
	}
}

/*
 * The response body for an AdminError. One place, because the eight admin route groups each own an
 * onError and a field added to only some of them is a contract that differs by URL.
 */
export function adminErrorBody(error: AdminError): {
	error: 'admin_error';
	message: string;
	blockers?: readonly DeletionBlocker[];
	failedAreas?: readonly string[];
} {
	return {
		error: 'admin_error',
		message: error.message,
		...(error.blockers ? { blockers: error.blockers } : {}),
		...(error.failedAreas ? { failedAreas: error.failedAreas } : {})
	};
}

export function assertAuth(admin: AdminContext | null): AdminContext {
	if (!admin) throw new AdminError(401, 'authentication required');
	return admin;
}

export function assertRole(admin: AdminContext, role: string): void {
	if (!admin.roles.includes(role)) {
		throw new AdminError(403, `role ${role} required`);
	}
}

/*
 * Does the caller belong to this group at all? The single question every container access resolves to
 * — a container is reached through the group that owns it, never by being named on the container.
 *
 * A super administrator bypasses, as they did before: their authority is instance-wide and is what
 * makes support and recovery possible for a group whose last owner has gone.
 */
export function assertGroupMember(admin: AdminContext, groupId: string): void {
	if (admin.roles.includes('super_admin')) return;
	if (!admin.memberships.some((m) => m.groupId === groupId)) {
		throw new AdminError(403, 'no access to this group');
	}
}

/*
 * Owner-only operations: who is in the group, and whether the group may be deleted. Deliberately
 * refuses by *membership kind* rather than by instance role — the same administrator owns one group
 * and is a plain member of another, so this can never be expressed as a role on the account.
 */
export function assertGroupOwner(admin: AdminContext, groupId: string): void {
	if (admin.roles.includes('super_admin')) return;
	const membership = admin.memberships.find((m) => m.groupId === groupId);
	if (!membership || membership.role !== 'owner') {
		throw new AdminError(403, 'group owner required');
	}
}

/*
 * The group a creation lands in.
 *
 * A super administrator belongs to no group by virtue of the role, so they arrive with an empty active
 * scope. Rather than refuse them, their containers go to the reserved `unassigned` group — which is
 * exactly what `managedBy: []` already meant: reachable by super administrators and nobody else. That
 * keeps instance-level provisioning working as it always did, and keeps the migration's rule for an
 * empty manager list and this rule the same rule.
 *
 * A project administrator always has one, because a personal group is created with the account. The
 * refusal below is therefore a broken deployment rather than a caller's mistake, and says so instead
 * of silently dropping the container somewhere.
 */
export function assertActiveGroup(admin: AdminContext): string {
	if (admin.activeGroupId) return admin.activeGroupId;
	if (admin.roles.includes('super_admin')) return UNASSIGNED_GROUP_ID;
	throw new AdminError(
		500,
		'no active group: this administrator has no personal group'
	);
}

export function assertProjectAccess(
	admin: AdminContext,
	project: Project
): void {
	if (admin.roles.includes('super_admin')) return;
	// Checked before ownership: the reserved admin project is outside the group model entirely, so a
	// membership can never be the thing that grants access to it.
	if (project.type === 'admin') {
		throw new AdminError(403, 'no access to this project');
	}
	if (!admin.memberships.some((m) => m.groupId === project.ownerGroupId)) {
		throw new AdminError(403, 'no access to this project');
	}
}

export function assertBucketAccess(
	admin: AdminContext,
	bucket: UserBucket
): void {
	if (admin.roles.includes('super_admin')) return;
	if (!admin.memberships.some((m) => m.groupId === bucket.ownerGroupId)) {
		throw new AdminError(403, 'no access to this bucket');
	}
}

/*
 * Broader than assertBucketAccess: also grants access when the caller's group owns a project whose
 * bucketId is this bucket, so an administrator can manage the end-users of a bucket backing their
 * project without their group owning the bucket itself. Used for reading a bucket's detail and
 * managing its end-users — NOT for editing the bucket entity.
 *
 * The distinction survives the move to groups unchanged; only what "the caller's" means has changed.
 */
export async function assertBucketUserAccess(
	admin: AdminContext,
	bucket: UserBucket
): Promise<void> {
	if (admin.roles.includes('super_admin')) return;
	if (admin.memberships.some((m) => m.groupId === bucket.ownerGroupId)) return;
	const store = getProjectStore();
	for (const membership of admin.memberships) {
		const projects = await store.listByGroup(membership.groupId);
		if (projects.some((p) => p.bucketId === bucket._id)) return;
	}
	throw new AdminError(403, 'no access to this bucket');
}

/*
 * Builds the context from an account, re-reading roles and group memberships. Shared by both
 * credential types below so neither can resolve a different authority from the same account — the
 * whole point of the MCP surface being an additional front door rather than a second, more permissive
 * one.
 *
 * One indexed lookup, as before: `listByMember` replaces the `listByManager` project scan it used to
 * run here, so the per-request cost is unchanged.
 */
async function contextFor(
	userId: string,
	bucketId: string,
	viaClientId?: string,
	sessionGroupId?: string
): Promise<AdminContext | null> {
	const user = await getUserStore(bucketId).find(userId);
	if (!user || !user.active) return null;
	const groups = await getGroupStore().listByMember(user._id);
	const memberships = groups.map((g) => ({
		groupId: g._id,
		role: (g.members.find((m) => m.userId === user._id)?.role ?? 'member') as
			'owner' | 'member'
	}));
	return {
		userId: user._id,
		email: user.email,
		roles: user.roles,
		bucketId,
		memberships,
		activeGroupId: await resolveActiveGroup(
			user.roles,
			memberships,
			groups,
			sessionGroupId
		),
		...(viaClientId ? { viaClientId } : {})
	};
}

/*
 * Which group this request acts in.
 *
 * The session's choice wins only while the caller still belongs to it. When it does not — removed from
 * the group a moment ago, or an agent that named nothing — the answer is the personal group rather
 * than an error: an administrator whose membership was revoked mid-session should find their console
 * showing their own work, not a broken scope they cannot navigate out of.
 *
 * A super administrator is the exception, because for them "belongs to it" is not the question the
 * switch asked: `PUT /admin/api/scope` lets them into any group except an administrator's personal one,
 * and a choice it accepted has to survive the next request. Without this, their switch was accepted and
 * then quietly discarded, and everything they created afterwards landed in the holding group instead of
 * the scope the console was showing them. Re-checked rather than trusted: the group may have been
 * deleted, or have been a personal group when the session was older than this rule.
 *
 * The final fallback covers a super administrator with no choice made, who belongs to no group by virtue
 * of the role and so has no personal group in `groups` unless they are a member of one.
 */
async function resolveActiveGroup(
	roles: string[],
	memberships: { groupId: string; role: 'owner' | 'member' }[],
	groups: Group[],
	sessionGroupId?: string
): Promise<string> {
	if (sessionGroupId && memberships.some((m) => m.groupId === sessionGroupId)) {
		return sessionGroupId;
	}
	// One indexed read, and only for a super administrator whose scope is a group they are not in.
	if (sessionGroupId && roles.includes('super_admin')) {
		const chosen = await getGroupStore().find(sessionGroupId);
		if (chosen && chosen.kind !== 'personal') return chosen._id;
	}
	const personal = groups.find((g) => g.kind === 'personal');
	return personal?._id ?? memberships[0]?.groupId ?? '';
}

export const resolveAdmin = new Elysia({ name: 'admin-resolve' }).derive(
	{ as: 'scoped' },
	async ({
		cookie,
		headers,
		request
	}): Promise<{ admin: AdminContext | null }> => {
		const sessionId = cookie[ADMIN_SESSION_COOKIE]?.value as string | undefined;
		if (sessionId) {
			const session = await adminSessionStore.find(sessionId);
			if (!session) return { admin: null };
			const admin = await contextFor(
				session.userId,
				session.bucketId,
				undefined,
				session.activeGroupId
			);
			if (!admin) return { admin: null };
			await adminSessionStore.touch(sessionId, ADMIN_SESSION_TTL_SECONDS);
			return { admin };
		}

		/*
		 * The second credential type: an access token issued for the MCP control plane, which the agent
		 * surface re-dispatches with. It resolves to the SAME context a cookie does, by the same lookups,
		 * so an agent gets exactly the permissions its authorizing administrator has — and role changes
		 * and deactivations take effect on the next call rather than at the next reconnection.
		 *
		 * Not a back door, and worth being precise about why. The token is validated in full — signature-
		 * bearing storage lookup, expiry, revocation, DPoP binding, and above all `aud === MCP_RESOURCE`
		 * — so the only credential that authenticates here is one this server minted for this purpose,
		 * to an administrator who completed an interactive sign-in. There is no marker header and no
		 * caller-asserted identity.
		 *
		 * Gated on the capability being switched on, so a deployment running with `mcp.enabled` off
		 * accepts no bearer credential on the admin plane at all.
		 */
		// Bound to a local so the narrowing survives into the call below: `headers` is a bag of
		// `string | undefined`, and `resolveMcpPrincipal` asks for a credential it can count on.
		const authorization = headers.authorization;
		if (!authorization || !ApplicationConfig['mcp.enabled']) {
			return { admin: null };
		}
		/*
		 * Imported lazily, and this is load-bearing rather than tidiness. `lib/mcp/principal.ts`
		 * reaches `lib/models/access_token.ts`, and `lib/models/` contains an import cycle that dies
		 * with `Cannot access 'BaseTokenPayload' before initialization` when the graph is entered
		 * cold (see wiki/concepts/model-graph-import-order.md). A static import here would put that
		 * cycle in the import chain of every admin route group — rbac.ts is imported by all ten — so
		 * merely loading `projectRoutes` would crash. Measured: it took the whole admin suite down.
		 *
		 * By the time a request is served the graph is warm, and the module cache makes this a map
		 * lookup after the first call. Same remedy, for the same reason, as the lazy import in
		 * test/preload.ts. Outside the try, so a module that fails to load is a fault and not a
		 * silent refusal.
		 */
		const { resolveMcpPrincipal, McpUnauthorized } =
			await import('../../mcp/principal.js');

		/*
		 * A DPoP proof binds to one method, and the client only ever made one for its `/mcp` request.
		 * The admin plane resolves the same credential on verbs no proof exists for — PUT, PATCH,
		 * DELETE — so they are presented as the POST they were proved against, and a GET stays a GET.
		 *
		 * The collapse lives here rather than inside the resolver because this is the only caller that
		 * has an arbitrary verb to collapse: `/mcp` passes the literal its route registered.
		 */
		const proofMethod = request.method === 'GET' ? 'GET' : 'POST';

		try {
			const principal = await resolveMcpPrincipal(
				{ authorization, dpop: headers.dpop },
				proofMethod
			);
			return {
				admin: await contextFor(
					principal.accountId,
					ADMIN_BUCKET_ID,
					principal.clientId
				)
			};
		} catch (err) {
			/*
			 * One answer for every *authorization* cause. Which check failed is not something a caller
			 * gets to probe for, and the MCP entry point reports the reason on the event bus instead.
			 *
			 * Only for that class, though. A bare `catch` here also turned a storage outage into "not
			 * authenticated", which sends an operator to debug their credential while the database is
			 * down — and the cookie arm above, whose lookups are not wrapped at all, would have answered
			 * 500 for the same fault. Anything that is not a refusal is rethrown, so both credential
			 * types report an outage the same way.
			 *
			 * That includes a DPoP nonce challenge, which `resolveMcpPrincipal` raises deliberately: it is
			 * a protocol step telling the caller to retry with a nonce, and flattening it here would leave
			 * a compliant client no way to proceed. Rethrown, so the server's error handler renders it as
			 * it does for every other DPoP-protected endpoint. `UseDpopNonce` is not named explicitly
			 * because `validate_dpop.ts` reaches the model graph — importing it here is exactly the cold
			 * cycle the lazy import above exists to avoid — and "not a refusal, so rethrow" covers it.
			 */
			if (err instanceof McpUnauthorized) {
				return { admin: null };
			}
			throw err;
		}
	}
);
