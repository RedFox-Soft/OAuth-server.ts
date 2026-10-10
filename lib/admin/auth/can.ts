import type { Project, UserBucket } from '../../adapters/types.js';
import { ROOT_NAMESPACE } from '../../resources/declaration_id.js';
import { ADMIN_BUCKET_ID, isUndeletableBucket } from '../consts.js';
import type { AdminContext } from './rbac.js';

/*
 * The rights a caller holds over a bucket, a project and the instance, stated as data (specs/079).
 *
 * The routes decide through these functions, and the presenters attach their answers to what the routes
 * return, so the console learns what the server will accept from the server's own predicates instead of a
 * copy of the rules kept in the browser. Each flag answers one question — would the route accept this
 * request from this caller — and nothing about the entity's current state: a bucket still used by projects
 * is deletable by right and refused by state, and the console shows those two differently.
 *
 * Pure on purpose. Nothing here reads a store, so a list can state rights for every row from facts it
 * gathered once; and nothing reads `viaClientId`, so an agent is told exactly what the console is told.
 */

export interface BucketCan {
	read: boolean;
	/* End users, their identities, and reading providers, provisioning and user groups; group membership. */
	manageUsers: boolean;
	/* The bucket's own settings (PATCH). */
	editSettings: boolean;
	/* Provider, provisioning and user-group writes, signing keys, handing a user to a connection. */
	edit: boolean;
	readActivity: boolean;
	changeAddress: boolean;
	move: boolean;
	delete: boolean;
}

export interface ProjectCan {
	read: boolean;
	edit: boolean;
	delete: boolean;
	manageClients: boolean;
	declareResources: boolean;
	assignBucket: boolean;
	move: boolean;
}

export interface MeCan {
	createBucket: boolean;
	createHost: boolean;
	createProject: boolean;
	createGroup: boolean;
	/* The instance-wide surfaces: settings, keys, administrators, agent access, usage, faults. */
	instance: boolean;
}

/*
 * The buckets a caller reaches through a project one of their groups owns, each with those groups — the one
 * fact a predicate cannot read off the context and the entity, so it is gathered once per request
 * (`projectReach` in rbac.ts) and handed in. The users right is widened by it, and so is moving: a bucket
 * moves with its projects, so an owner of a group whose project uses it is an owner of what moves.
 */
export type ProjectReach = ReadonlyMap<string, ReadonlySet<string>>;

/*
 * For a decision that never consults the reach: owning a bucket, editing it and deleting it are membership
 * questions about the bucket's own group.
 */
export const NO_PROJECT_REACH: ProjectReach = new Map();

function belongsTo(ctx: AdminContext, groupId: string): boolean {
	return ctx.memberships.some((m) => m.groupId === groupId);
}

function ownsGroup(ctx: AdminContext, groupId: string): boolean {
	return ctx.memberships.some(
		(m) => m.groupId === groupId && m.role === 'owner'
	);
}

/*
 * Authority over the bucket entity itself: instance-wide, or membership of the group that owns it. A
 * super administrator bypasses, because their authority is what makes support and recovery possible for a
 * group whose last owner has gone.
 */
export function holdsBucket(
	ctx: AdminContext,
	bucket: Pick<UserBucket, 'ownerGroupId'>
): boolean {
	return ctx.superAdmin || belongsTo(ctx, bucket.ownerGroupId);
}

/*
 * Broader than holding the bucket: a group that owns a project signing into it administers its end users,
 * though not the bucket — reading its detail and managing its users, never editing the bucket entity. Says
 * nothing about the administrators' bucket, which `bucketCan` refuses first, by its own rule.
 */
function reachesBucketUsers(
	ctx: AdminContext,
	bucket: Pick<UserBucket, '_id' | 'ownerGroupId'>,
	access: ProjectReach
): boolean {
	return holdsBucket(ctx, bucket) || access.has(bucket._id);
}

/*
 * Changing an address changes a bucket's issuer identifier and breaks every client integrated with it, and
 * a hostname reaches into the operator's domain: instance-level. The two buckets served at the root keep
 * theirs, or the console would lock every operator out of the surface that could move it back.
 */
export function mayChangeBucketAddress(
	ctx: AdminContext,
	bucketId: string
): boolean {
	return ctx.superAdmin && !isUndeletableBucket(bucketId);
}

export function bucketCan(
	ctx: AdminContext,
	bucket: Pick<UserBucket, '_id' | 'ownerGroupId'>,
	access: ProjectReach
): BucketCan {
	/*
	 * The administrators' bucket: its accounts are administrators, managed on their own routes, so everything
	 * but reading and changing its settings stays closed to it — for a super administrator as well.
	 */
	const reserved = bucket._id === ADMIN_BUCKET_ID;
	/* The instance is built on these two: neither moves, changes address or is deleted. */
	const fixed = isUndeletableBucket(bucket._id);
	const holds = holdsBucket(ctx, bucket);
	const users = reachesBucketUsers(ctx, bucket, access);
	const edit = !reserved && holds;
	const ownsWhatMoves =
		ownsGroup(ctx, bucket.ownerGroupId) ||
		[...(access.get(bucket._id) ?? [])].some((groupId) =>
			ownsGroup(ctx, groupId)
		);
	return {
		read: ctx.superAdmin || (!reserved && users),
		manageUsers: !reserved && users,
		editSettings: ctx.superAdmin || edit,
		edit,
		/* A super administrator reads any bucket's figures, the reserved ones included. */
		readActivity: ctx.superAdmin || edit,
		changeAddress: mayChangeBucketAddress(ctx, bucket._id),
		/*
		 * Taking a bucket away removes every other member's access to it, so it is an owner's act — of its
		 * group, or of a group whose project moves with it, which is how a move left half-done is finished.
		 */
		move: !fixed && holds && (ctx.superAdmin || ownsWhatMoves),
		delete: !fixed && holds
	};
}

/*
 * Reaching a project at all. The console's own project sits outside the group model, so no membership is
 * the thing that grants it; only a super administrator reaches it.
 */
export function reachesProject(
	ctx: AdminContext,
	project: Pick<Project, 'type' | 'ownerGroupId'>
): boolean {
	if (ctx.superAdmin) return true;
	return project.type !== 'admin' && belongsTo(ctx, project.ownerGroupId);
}

/* Changing, deleting and managing the clients of a project: never the console's own. */
export function managesProject(
	ctx: AdminContext,
	project: Pick<Project, 'type' | 'ownerGroupId'>
): boolean {
	return reachesProject(ctx, project) && project.type !== 'admin';
}

/*
 * Moving a project to another group removes every other member's access to it, so it is an owner's act, as
 * moving a bucket is.
 */
export function mayMoveProject(
	ctx: AdminContext,
	project: Pick<Project, 'type' | 'ownerGroupId'>
): boolean {
	return (
		managesProject(ctx, project) &&
		(ctx.superAdmin || ownsGroup(ctx, project.ownerGroupId))
	);
}

/*
 * The shared root namespace is a super administrator's to write: every tenant served at the root shares one
 * issuer, and nothing a resource could publish would stop one of them declaring another's server first.
 */
export function mayDeclareIn(ctx: AdminContext, namespace: string): boolean {
	return ctx.superAdmin || namespace !== ROOT_NAMESPACE;
}

/*
 * `namespace` is where the project's declarations live (`namespaceOfProject`): read from its bucket, so the
 * caller resolves it and hands it in rather than this module reading a store.
 */
export function projectCan(
	ctx: AdminContext,
	project: Pick<Project, 'type' | 'ownerGroupId'> & { namespace: string }
): ProjectCan {
	const reaches = reachesProject(ctx, project);
	const manages = managesProject(ctx, project);
	return {
		read: reaches,
		edit: manages,
		delete: manages,
		manageClients: manages,
		declareResources: reaches && mayDeclareIn(ctx, project.namespace),
		assignBucket: reaches,
		move: mayMoveProject(ctx, project)
	};
}

export function meCan(ctx: AdminContext): MeCan {
	/*
	 * A creation lands in the active group; a super administrator with none creates into the System group.
	 * Anyone else always has one, because a personal group is created with the account.
	 */
	const creates = ctx.superAdmin || ctx.activeGroupId !== '';
	return {
		createBucket: creates,
		/* Naming a hostname puts a name in the operator's own domain under the caller's control. */
		createHost: ctx.superAdmin,
		createProject: creates,
		createGroup: true,
		instance: ctx.superAdmin
	};
}
