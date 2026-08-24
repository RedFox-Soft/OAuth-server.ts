import { Elysia } from 'elysia';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from '../../adapters/index.js';
import type { Project, UserBucket } from '../../adapters/types.js';
import { ApplicationConfig } from '../../configs/application.js';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	ADMIN_SESSION_TTL_SECONDS
} from '../consts.js';

export interface AdminContext {
	userId: string;
	email: string;
	roles: string[];
	bucketId: string;
	managedProjectIds: string[];
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

export function assertProjectAccess(
	admin: AdminContext,
	project: Project
): void {
	if (admin.roles.includes('super_admin')) return;
	if (project.type === 'admin' || !project.managedBy.includes(admin.userId)) {
		throw new AdminError(403, 'no access to this project');
	}
}

export function assertBucketAccess(
	admin: AdminContext,
	bucket: UserBucket
): void {
	if (admin.roles.includes('super_admin')) return;
	if (!bucket.managedBy.includes(admin.userId)) {
		throw new AdminError(403, 'no access to this bucket');
	}
}

// Broader than assertBucketAccess: also grants access when the caller manages a
// project whose bucketId is this bucket (so a project_admin can manage the users of
// a bucket backing their project without owning the bucket). Used for reading a
// bucket's detail and managing its end-users — NOT for editing the bucket entity.
export async function assertBucketUserAccess(
	admin: AdminContext,
	bucket: UserBucket
): Promise<void> {
	if (admin.roles.includes('super_admin')) return;
	if (bucket.managedBy.includes(admin.userId)) return;
	const managed = await getProjectStore().listByManager(admin.userId);
	if (managed.some((p) => p.bucketId === bucket._id)) return;
	throw new AdminError(403, 'no access to this bucket');
}

/*
 * Builds the context from an account, re-reading roles and managed projects. Shared by both credential
 * types below so neither can resolve a different authority from the same account — the whole point of
 * the MCP surface being an additional front door rather than a second, more permissive one.
 */
async function contextFor(
	userId: string,
	bucketId: string,
	viaClientId?: string
): Promise<AdminContext | null> {
	const user = await getUserStore(bucketId).find(userId);
	if (!user || !user.active) return null;
	const managed = await getProjectStore().listByManager(user._id);
	return {
		userId: user._id,
		email: user.email,
		roles: user.roles,
		bucketId,
		managedProjectIds: managed.map((p) => p._id),
		...(viaClientId ? { viaClientId } : {})
	};
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
			const admin = await contextFor(session.userId, session.bucketId);
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
		if (!headers.authorization || !ApplicationConfig['mcp.enabled']) {
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
		const { resolveMcpPrincipal, McpUnauthorized } = await import(
			'../../mcp/principal.js'
		);


		try {
			const principal = await resolveMcpPrincipal(headers, request.method);
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
