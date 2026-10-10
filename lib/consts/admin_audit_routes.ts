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
		action: 'project.bucket.clear',
		method: 'DELETE',
		path: '/admin/api/projects/:id/bucket',
		targetType: 'Project'
	},

	/*
	 * Declared protected resources. `targetId` is the canonical resource identifier and `targetScope`
	 * the namespace it is unique within — the bucket, or `@root` — so an entry names the audience itself
	 * rather than an opaque id nobody can resolve after the declaration is gone, and says whose it was
	 * now that two tenants may declare the same one.
	 */
	{
		action: 'resource.create',
		method: 'POST',
		path: '/admin/api/projects/:id/resources',
		targetType: 'ProtectedResource'
	},
	{
		action: 'resource.update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/resources/:resourceId',
		targetType: 'ProtectedResource'
	},
	{
		action: 'resource.delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/resources/:resourceId',
		targetType: 'ProtectedResource'
	},

	/*
	 * Which client identities may administer this instance. `targetId` is the permitted identifier URL
	 * or bare host — the identity itself, so an entry stays meaningful after the permission is gone.
	 */
	{
		action: 'mcp.client.permit',
		method: 'POST',
		path: '/admin/api/mcp/clients',
		targetType: 'McpClientPermission'
	},
	{
		action: 'mcp.client.update',
		method: 'PATCH',
		path: '/admin/api/mcp/clients/:entryId',
		targetType: 'McpClientPermission'
	},
	{
		action: 'mcp.client.withdraw',
		method: 'DELETE',
		path: '/admin/api/mcp/clients/:entryId',
		targetType: 'McpClientPermission'
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
	/*
	 * The instance-wide privilege — membership of Super administrators — granted and withdrawn by operations
	 * of their own, so the trail and the agent surface give it its own weight rather than folding it into an
	 * ordinary account edit.
	 */
	{
		action: 'admin.superadmin.grant',
		method: 'POST',
		path: '/admin/api/admins/:id/super-admin',
		targetType: 'AdminUser'
	},
	{
		action: 'admin.superadmin.withdraw',
		method: 'DELETE',
		path: '/admin/api/admins/:id/super-admin',
		targetType: 'AdminUser'
	},

	/*
	 * Groups: the owner of every project and bucket, and therefore the thing that decides who may reach
	 * one. Membership changes are audited as carefully as container changes, because adding somebody to
	 * a group grants them everything it owns in a single call.
	 */
	{
		action: 'group.create',
		method: 'POST',
		path: '/admin/api/groups',
		targetType: 'Group'
	},
	{
		action: 'group.update',
		method: 'PATCH',
		path: '/admin/api/groups/:id',
		targetType: 'Group'
	},
	{
		action: 'group.delete',
		method: 'DELETE',
		path: '/admin/api/groups/:id',
		targetType: 'Group'
	},
	{
		action: 'group.member.add',
		method: 'POST',
		path: '/admin/api/groups/:id/members',
		targetType: 'Group'
	},
	{
		action: 'group.member.update',
		method: 'PATCH',
		path: '/admin/api/groups/:id/members/:userId',
		targetType: 'Group'
	},
	{
		action: 'group.member.remove',
		method: 'DELETE',
		path: '/admin/api/groups/:id/members/:userId',
		targetType: 'Group'
	},
	/*
	 * Invitations. `invitation.accept` is the only audited action whose actor is not an administrator
	 * acting on the plane: the invitee is not signed in when they accept, so the entry names the account
	 * that has just come into existence.
	 */
	{
		action: 'invitation.create',
		method: 'POST',
		path: '/admin/api/groups/:id/invitations',
		targetType: 'Group'
	},
	{
		action: 'invitation.revoke',
		method: 'DELETE',
		path: '/admin/api/groups/:id/invitations/:inviteId',
		targetType: 'Group'
	},
	{
		action: 'invitation.accept',
		method: 'POST',
		path: '/admin/api/invitations/accept',
		targetType: 'Group'
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
	/*
	 * Moving a bucket to a different address. Its own action rather than part of `bucket.update`,
	 * because it changes the bucket's issuer identifier and every client integrated with it stops
	 * validating tokens — a consequence that must be filterable on its own, and must not share an
	 * `ordinary` classification with a label rename on the agent surface.
	 */
	{
		action: 'bucket.address.change',
		method: 'POST',
		path: '/admin/api/buckets/:id/address',
		targetType: 'UserBucket'
	},
	/*
	 * Moving a bucket, with the projects using it, to another administrator group (specs/075). The entry
	 * carries both groups — `ownerGroupId` the one it joined, `formerOwnerGroupId` the one it left — so
	 * each reads it.
	 */
	{
		action: 'project.owner.change',
		method: 'PUT',
		path: '/admin/api/projects/:id/owner',
		targetType: 'Project'
	},
	{
		action: 'bucket.owner.change',
		method: 'PUT',
		path: '/admin/api/buckets/:id/owner',
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
		action: 'enduser.lock',
		method: 'POST',
		path: '/admin/api/buckets/:id/users/:uid/lock',
		targetType: 'EndUser'
	},
	{
		action: 'enduser.unlock',
		method: 'POST',
		path: '/admin/api/buckets/:id/users/:uid/unlock',
		targetType: 'EndUser'
	},
	/*
	 * Ending a user's access without changing the account. An upstream identity provider's global token
	 * revocation records the same action under the `upstream:` actor (specs/072), because it does the same.
	 */
	{
		action: 'enduser.signout',
		method: 'POST',
		path: '/admin/api/buckets/:id/users/:uid/sign-out',
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
	 * Handing a local user to a provisioning connection — from then on the user is read-only to every
	 * administrator, so the act is recorded against the user, with the connection named in `attributes`.
	 */
	{
		action: 'enduser.connection.assign',
		method: 'POST',
		path: '/admin/api/buckets/:id/users/:uid/connection',
		targetType: 'EndUser'
	},

	/*
	 * A bucket's groups of end users. Membership is recorded with the member ids, so the trail answers "when
	 * did this person gain or lose this group" — which is what a group means to every relying party reading
	 * the `groups` claim. A SCIM change records the same actions under the connection.
	 */
	{
		action: 'bucketgroup.create',
		method: 'POST',
		path: '/admin/api/buckets/:id/groups',
		targetType: 'BucketGroup'
	},
	{
		action: 'bucketgroup.update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id/groups/:gid',
		targetType: 'BucketGroup'
	},
	{
		action: 'bucketgroup.delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/groups/:gid',
		targetType: 'BucketGroup'
	},
	{
		action: 'bucketgroup.member.add',
		method: 'POST',
		path: '/admin/api/buckets/:id/groups/:gid/members',
		targetType: 'BucketGroup'
	},
	{
		action: 'bucketgroup.member.remove',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/groups/:gid/members/:uid',
		targetType: 'BucketGroup'
	},
	/* From then on the group is the connection's and read-only to every administrator. */
	{
		action: 'bucketgroup.connection.assign',
		method: 'POST',
		path: '/admin/api/buckets/:id/groups/:gid/connection',
		targetType: 'BucketGroup'
	},

	/*
	 * SCIM provisioning connections. The create entry names the provider it binds (the connection's id is
	 * allocated by the store); the rest name the connection. A credential's kind is recorded, its value never
	 * — the issue response is the only place a secret or static token ever appears.
	 */
	{
		action: 'provisioning.connection.create',
		method: 'POST',
		path: '/admin/api/buckets/:id/provisioning-connections',
		targetType: 'ProvisioningConnection'
	},
	{
		action: 'provisioning.connection.update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id/provisioning-connections/:connectionId',
		targetType: 'ProvisioningConnection'
	},
	{
		action: 'provisioning.connection.delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/provisioning-connections/:connectionId',
		targetType: 'ProvisioningConnection'
	},
	/*
	 * Ending a mass-deprovisioning hold (specs/072). The hold itself has no route: the connection records it
	 * under `provisioning.connection.update` with the attribute `hold`, because its record is what changed.
	 */
	{
		action: 'provisioning.connection.release',
		method: 'POST',
		path: '/admin/api/buckets/:id/provisioning-connections/:connectionId/release',
		targetType: 'ProvisioningConnection'
	},
	{
		action: 'provisioning.credential.issue',
		method: 'POST',
		path: '/admin/api/buckets/:id/provisioning-connections/:connectionId/credentials',
		targetType: 'ProvisioningConnection'
	},
	{
		action: 'provisioning.credential.revoke',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/provisioning-connections/:connectionId/credentials/:kind',
		targetType: 'ProvisioningConnection'
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
	 * An addressable bucket's own signing keys. The target is the bucket, the issuer whose keys changed;
	 * which key is a property of the change rather than a managed entity of its own.
	 */
	{
		action: 'bucket.key.generate',
		method: 'POST',
		path: '/admin/api/buckets/:id/keys',
		targetType: 'UserBucket'
	},
	{
		action: 'bucket.key.promote',
		method: 'POST',
		path: '/admin/api/buckets/:id/keys/:kid/promote',
		targetType: 'UserBucket'
	},
	{
		action: 'bucket.key.retire',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/keys/:kid',
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
		action: 'jwks.promote',
		method: 'POST',
		path: '/admin/api/jwks/:kid/promote',
		targetType: 'jwks'
	},
	{
		action: 'jwks.retire',
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
	{
		action: 'sentry.settings.update',
		method: 'PUT',
		path: '/admin/api/settings/sentry',
		targetType: 'ApplicationConfig'
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

/*
 * Audited actions that no admin route performs. Registering an administrator account happens at the
 * public registration page, not under /admin/api, yet it creates an account that can sign in to the
 * console — exactly the kind of change the trail exists for. Declared here rather than bolted onto the
 * route table so the drift guard, which compares the table against mounted admin routes, keeps meaning
 * what it says.
 */
const nonRouteActions = [
	{ action: 'admin.register', targetType: 'AdminUser' }
] as const satisfies readonly { action: string; targetType: string }[];

export const nonRouteAuditActions: readonly {
	readonly action: string;
	readonly targetType: string;
}[] = nonRouteActions;

export type AuditAction =
	| (typeof routes)[number]['action']
	| (typeof nonRouteActions)[number]['action'];
export type AuditTargetType =
	| (typeof routes)[number]['targetType']
	| (typeof nonRouteActions)[number]['targetType'];

/*
 * Mutating admin routes that deliberately write no audit entry. Enumerated rather than defaulted, so
 * excluding one is a reviewable edit and the drift guard can pin the set exactly.
 *
 * Each touches only the caller's own standing and nothing else, which is the shared reason: the trail is
 * a record of changes to managed entities, and an entry for something that changed none of them is a
 * row an investigator has to read past. No exclusion is surfaced to a caller, so the reason lives here
 * rather than as a field.
 *
 * `POST /admin/api/logout` ends the caller's own session: session lifecycle, not a change to a managed
 * entity. Authentication-event logging would be its own feature.
 *
 * `PUT /admin/api/scope` points the console at one of the groups the caller already belongs to. It
 * grants nothing — a member can only switch to a group they are in, and a super administrator reaches
 * every container without switching — so there is no access event to record. The question an entry
 * would have answered, which scope a change was made from, is already answered by `ownerGroupId` on
 * that change's own entry, recorded at the time and never re-derived.
 *
 * `POST /admin/api/me/verification` mails the caller a verification message for their own address. It
 * changes nothing; the account becomes verified at the public verification endpoint, where whoever holds
 * the mailbox completes it, so there is no administrative change here to attribute.
 */
export const excludedAdminRoutes: readonly {
	readonly method: AuditedMethod;
	readonly path: string;
}[] = [
	{ method: 'POST', path: '/admin/api/logout' },
	{ method: 'PUT', path: '/admin/api/scope' },
	{ method: 'POST', path: '/admin/api/me/verification' }
];

/*
 * Actor recorded for first-run setup, which has no session to attribute. Distinguishable from every
 * real actor without a lookup: a real actorEmail always contains '@', a real actorId is a UUID or
 * nanoid, and neither ever contains ':'.
 */
export const BOOTSTRAP_ACTOR = 'system:bootstrap';

/*
 * Actor recorded for a change a schema migration made (`bun run db:migrate`), which has no session either.
 * The bootstrap's convention — a ':' and no '@' — so it is told apart from an administrator without a
 * lookup.
 */
export const MIGRATION_ACTOR = 'system:migration';

/*
 * Prefix of the actor recorded for a change a SCIM provisioning connection made: `connection:<id>`. The
 * bootstrap's convention, so it too is told apart from a person without a lookup.
 */
export const CONNECTION_ACTOR_PREFIX = 'connection:';

/*
 * Prefix of the actor recorded when a bucket's upstream identity provider asked for a user's access to
 * end: `upstream:<bucketId>:<providerId>` (specs/072).
 */
export const UPSTREAM_ACTOR_PREFIX = 'upstream:';

/* Target ids of the singleton configuration documents, which have no entity id of their own. */
export const SETTINGS_TARGET_ID = 'settings';
export const SMTP_TARGET_ID = 'smtp';
export const SENTRY_TARGET_ID = 'sentry';

/*
 * `<entity>[.<aspect>].<verb>`, lowercase. Pinned by the drift guard so the trail can be filtered by
 * action without knowing which subsystem wrote the entry.
 */
export const AUDIT_ACTION_PATTERN = /^[a-z]+(?:\.[a-z]+)+$/;

const targetTypeByAction = new Map<string, string>(
	[...routes, ...nonRouteActions].map((entry) => [
		entry.action,
		entry.targetType
	])
);

// The only source of an entry's targetType. Callers pass the action; they cannot pass a target type.
export function auditTargetTypeFor(action: AuditAction): string {
	const targetType = targetTypeByAction.get(action);
	if (!targetType) {
		// Unreachable while AuditAction is derived from these tables; kept so a future non-literal
		// caller fails loudly instead of writing an entry with an empty target type.
		throw new Error(`no audited admin route declares the action: ${action}`);
	}
	return targetType;
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
