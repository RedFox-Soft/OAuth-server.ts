export type AuditedMethod = 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface AuditedAdminRoute {
	readonly action: string;
	readonly method: AuditedMethod;
	readonly path: string;
	readonly targetType: string;
}

/*
 * Every state-changing route of the admin control plane, with the action name and target type its
 * audit entry carries. The constitution requires an immutable record of *every* such action, and an
 * enumeration is the only way a forgotten one becomes a test failure instead of a silent hole:
 * `test/admin/audit_route_classification.spec.ts` compares this table against the mounted route set
 * in both directions.
 *
 * The table is load-bearing, not documentation. `recordAdminAudit` takes an `AuditAction` (the union
 * of the `action` values below) and resolves `targetType` from here — so an action missing from this
 * table cannot compile at the call site, and a target type cannot be mistyped at all.
 *
 * Paths are written in Elysia's declaration form so they compare directly against `elysia.routes`.
 * Matching is exact on (method, path), never a prefix test: `POST /admin/api/buckets` and
 * `POST /admin/api/buckets/:id/users` are different operations on different entities.
 *
 * Deliberately imports nothing. Anything that transitively imports `lib/adapters/mongodb/db.ts`
 * connects at module scope and is therefore unloadable under test.
 */
const routes = [
	// Unauthenticated by design — first-run setup has no session, so its entry carries the bootstrap
	// actor below rather than an administrator.
	{
		action: 'setup.bootstrap',
		method: 'POST',
		path: '/admin/api/setup',
		targetType: 'AdminUser'
	},

	{
		action: 'project.create',
		method: 'POST',
		path: '/admin/api/projects',
		targetType: 'Project'
	},
	{
		action: 'project.update',
		method: 'PATCH',
		path: '/admin/api/projects/:id',
		targetType: 'Project'
	},
	{
		action: 'project.delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id',
		targetType: 'Project'
	},
	{
		action: 'project.bucket.assign',
		method: 'PUT',
		path: '/admin/api/projects/:id/bucket',
		targetType: 'Project'
	},

	{
		action: 'client.create',
		method: 'POST',
		path: '/admin/api/projects/:id/clients',
		targetType: 'Client'
	},
	{
		action: 'client.update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/clients/:clientId',
		targetType: 'Client'
	},
	{
		action: 'client.secret.rotate',
		method: 'POST',
		path: '/admin/api/projects/:id/clients/:clientId/secret',
		targetType: 'Client'
	},
	{
		action: 'client.delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/clients/:clientId',
		targetType: 'Client'
	},

	{
		/*
		 * The reserved admin bucket's own policy. `targetType` is the bucket rather than an
		 * administrator: the change is to the bucket record, and it applies to every operator in it.
		 */
		action: 'admin.settings.update',
		method: 'PATCH',
		path: '/admin/api/admins/settings',
		targetType: 'UserBucket'
	},
	{
		action: 'admin.create',
		method: 'POST',
		path: '/admin/api/admins',
		targetType: 'AdminUser'
	},
	{
		action: 'admin.update',
		method: 'PATCH',
		path: '/admin/api/admins/:id',
		targetType: 'AdminUser'
	},
	/*
	 * `admin.deactivate`, not `admin.delete`: the handler sets `active: false` and keeps the row. A
	 * trail that says "delete" for a deactivation is a false statement an investigator would act on.
	 */
	{
		action: 'admin.deactivate',
		method: 'DELETE',
		path: '/admin/api/admins/:id',
		targetType: 'AdminUser'
	},

	{
		action: 'bucket.create',
		method: 'POST',
		path: '/admin/api/buckets',
		targetType: 'UserBucket'
	},
	/*
	 * Replaces the former `bucket.settings.update`, which was written only when a registration or
	 * verification field was present — so a rename or a manager reassignment left no trace. One entry
	 * for the whole update, with `attributes` naming what the request set. Historical entries keep the
	 * old action name and stay filterable, because the action filter matches recorded values.
	 */
	{
		action: 'bucket.update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id',
		targetType: 'UserBucket'
	},
	{
		action: 'bucket.delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id',
		targetType: 'UserBucket'
	},

	/*
	 * These end-user rows also record `targetScope` (the bucket): their users live in per-bucket storage, so
	 * a bare user id cannot be resolved to an account — not even to an email — without knowing which bucket
	 * to look in. `federation.identity.delete` below is the fifth row of this kind.
	 */
	{
		action: 'enduser.create',
		method: 'POST',
		path: '/admin/api/buckets/:id/users',
		targetType: 'EndUser'
	},
	{
		action: 'enduser.update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id/users/:uid',
		targetType: 'EndUser'
	},
	{
		action: 'enduser.password.reset',
		method: 'POST',
		path: '/admin/api/buckets/:id/users/:uid/password',
		targetType: 'EndUser'
	},
	{
		action: 'enduser.totp.clear',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/users/:uid/totp',
		targetType: 'EndUser'
	},
	{
		action: 'enduser.delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/users/:uid',
		targetType: 'EndUser'
	},

	/*
	 * Upstream federation providers. `targetType` is the bucket, because a provider has no identity outside
	 * the bucket it belongs to — it is an element of that bucket's document, and an entry naming only
	 * `acme-sso` would not say whose.
	 *
	 * Not gated by `federation.enabled`, unlike the end-user legs: a deployment that switched federation off
	 * must still be able to delete a provider it no longer trusts, and that deletion must still be recorded.
	 */
	{
		action: 'federation.provider.create',
		method: 'POST',
		path: '/admin/api/buckets/:id/federation',
		targetType: 'UserBucket'
	},
	{
		action: 'federation.provider.update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id/federation/:providerId',
		targetType: 'UserBucket'
	},
	{
		action: 'federation.provider.delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/federation/:providerId',
		targetType: 'UserBucket'
	},
	/*
	 * Severing one account's upstream identity. An end-user target, so it carries `targetScope` — the fifth
	 * row to do so, for the same reason as the other four: these users live in per-bucket storage, and a bare
	 * user id resolves to nobody, not even to an email, without knowing which bucket to look in.
	 */
	{
		action: 'federation.identity.delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/users/:uid/identities/:providerId',
		targetType: 'EndUser'
	},

	{
		action: 'jwks.generate',
		method: 'POST',
		path: '/admin/api/jwks',
		targetType: 'jwks'
	},
	{
		action: 'jwks.delete',
		method: 'DELETE',
		path: '/admin/api/jwks/:kid',
		targetType: 'jwks'
	},

	{
		action: 'settings.update',
		method: 'PUT',
		path: '/admin/api/settings',
		targetType: 'ApplicationConfig'
	},
	{
		action: 'smtp.settings.update',
		method: 'PUT',
		path: '/admin/api/settings/smtp',
		targetType: 'SmtpSettings'
	},

	/*
	 * Purging recorded faults. Audited even though what it destroys is diagnostic rather than
	 * operational: it is an irreversible deletion an administrator chose, and the trail is the only place
	 * that survives it. The count of what went is recorded separately — the trail has no update path, so
	 * the entry written before the purge can only ever state an intention.
	 */
	{
		action: 'error.purge',
		method: 'DELETE',
		path: '/admin/api/errors',
		targetType: 'ErrorRecord'
	}
] as const satisfies readonly AuditedAdminRoute[];

export const auditedAdminRoutes: readonly AuditedAdminRoute[] = routes;

export type AuditAction = (typeof routes)[number]['action'];
export type AuditTargetType = (typeof routes)[number]['targetType'];

/*
 * Mutating admin routes that deliberately write no audit entry. Enumerated rather than defaulted, so
 * excluding one is a reviewable edit and the drift guard can pin the set exactly.
 *
 * `POST /admin/api/logout` ends the caller's own session: session lifecycle, not a change to a managed
 * entity. Authentication-event logging would be its own feature.
 */
export const excludedAdminRoutes: readonly {
	readonly method: AuditedMethod;
	readonly path: string;
}[] = [{ method: 'POST', path: '/admin/api/logout' }];

/*
 * Actor recorded for first-run setup, which has no session to attribute. Distinguishable from every
 * real actor without a lookup: a real actorEmail always contains '@', a real actorId is a UUID or
 * nanoid, and neither ever contains ':'.
 */
export const BOOTSTRAP_ACTOR = 'system:bootstrap';

/* Target ids of the two singleton configuration documents, which have no entity id of their own. */
export const SETTINGS_TARGET_ID = 'settings';
export const SMTP_TARGET_ID = 'smtp';

/*
 * `<entity>[.<aspect>].<verb>`, lowercase. Pinned by the drift guard so the trail can be filtered by
 * action without knowing which subsystem wrote the entry.
 */
export const AUDIT_ACTION_PATTERN = /^[a-z]+(?:\.[a-z]+)+$/;

const routeByAction = new Map<string, AuditedAdminRoute>(
	routes.map((route) => [route.action, route])
);

// The only source of an entry's targetType. Callers pass the action; they cannot pass a target type.
export function auditTargetTypeFor(action: AuditAction): string {
	const route = routeByAction.get(action);
	if (!route) {
		// Unreachable while AuditAction is derived from this table; kept so a future non-literal
		// caller fails loudly instead of writing an entry with an empty target type.
		throw new Error(`no audited admin route declares the action: ${action}`);
	}
	return route.targetType;
}

export function auditRouteFor(
	method: string,
	path: string
): AuditedAdminRoute | undefined {
	return routes.find((route) => route.method === method && route.path === path);
}

export function isExcludedAdminRoute(method: string, path: string): boolean {
	return excludedAdminRoutes.some(
		(route) => route.method === method && route.path === path
	);
}
