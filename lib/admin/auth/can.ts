import type { UserBucket } from '../../adapters/types.js';
import { addressOf } from '../../configs/issuer.js';
import { ROOT_NAMESPACE } from '../../resources/declaration_id.js';
import { ADMIN_BUCKET_ID, isUndeletableBucket } from '../consts.js';
import { ApplicationConfig } from '../../configs/application.js';
import type { AdminContext } from './rbac.js';
import type { PlanRights } from '../../plans/rights.js';

/*
 * The rights a caller holds over a bucket and the instance, stated as data (specs/079).
 *
 * The routes decide through these functions, and the presenters attach their answers to what the routes
 * return, so the console learns what the server will accept from the server's own predicates instead of a
 * copy of the rules kept in the browser. Each flag answers one question — would the route accept this caller
 * for this entity as it is now. Most answers depend on the caller alone; two depend on the bucket's state
 * for one kind of caller (specs/081): a group owner may change the address of a bucket nothing depends on,
 * and a plain member may delete a bucket holding no accounts. A state refusal that applies to every caller
 * — a bucket still holding applications cannot be deleted by anyone — stays out of the flags: the bucket is
 * deletable by right and refused by state, and the console shows those two differently.
 *
 * Pure on purpose. Nothing here reads a store: the state a flag depends on arrives as `BucketFacts`, which
 * the caller reads only where `bucketFactsWanted` says it can change the answer, so a list states rights for
 * every row from facts gathered for it; and nothing reads `viaClientId`, so an agent is told exactly what the
 * console is told.
 */

export interface BucketCan {
	read: boolean;
	/* End users, their identities, and reading providers, provisioning and user groups; group membership. */
	manageUsers: boolean;
	/* The bucket's own settings (PATCH). */
	editSettings: boolean;
	/*
	 * Provider, provisioning and user-group writes, signing keys, handing a user to a connection, and the
	 * bucket's applications and APIs (specs/099).
	 */
	edit: boolean;
	readActivity: boolean;
	changeAddress: boolean;
	move: boolean;
	delete: boolean;
	/*
	 * Moving the project to another plan (specs/102): an instance-level decision, so a super administrator's alone,
	 * whoever owns the project. A System project is refused by its state, not by this right: it carries no plan.
	 */
	setPlan: boolean;
}

/* The address forms a project can be given (specs/101): a path, a subdomain of the instance, a hostname. */
export type AddressFormChoice = 'path' | 'subdomain' | 'host';

export interface MeCan {
	createProject: boolean;
	/*
	 * The forms this caller may give a project, in the order the console offers them: the first is the one
	 * selected. A team is limited by `projects.addressForms`; a super administrator never is.
	 */
	addressForms: AddressFormChoice[];
	createTeam: boolean;
	/* The instance-wide surfaces: settings, keys, administrators, agent access, usage, faults. */
	instance: boolean;
	/*
	 * What the plans still let the caller create (specs/102), stated beside these by the routes that answer `can`
	 * (lib/plans/rights.ts). Absent from `meCan` itself, which reads no store; absent means unlimited.
	 */
	nameSlug?: PlanRights['nameSlug'];
	projects?: PlanRights['projects'];
	teams?: PlanRights['teams'];
}

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
 * The same question about a bucket that no longer exists, answered from the group its deletion record names
 * (specs/091): that group's members may still read its usage, since its active users counted in their months.
 * A record that names no group — written before groups were recorded — is a super administrator's alone.
 */
export function heldDeletedBucket(
	ctx: AdminContext,
	tombstone: { ownerGroupId?: string }
): boolean {
	return (
		ctx.superAdmin ||
		(tombstone.ownerGroupId !== undefined &&
			belongsTo(ctx, tombstone.ownerGroupId))
	);
}

/* What depends on a bucket, counted across the instance rather than among what the caller can see. */
export interface BucketDependents {
	/* Every application in it, a self-registered one included: its integration breaks like any other. */
	readonly applications: number;
	readonly providers: number;
	readonly connections: number;
}

/*
 * The bucket's state the two state-dependent flags are decided from. Each is present only when it was read,
 * and read only when it can change the answer for this caller (`bucketFactsWanted`); one wanted but absent
 * answers as refusing, so a route that forgot to read it fails closed.
 */
export interface BucketFacts {
	readonly dependents?: BucketDependents;
	readonly accounts?: number;
}

export const NO_BUCKET_FACTS: BucketFacts = {};

type AddressedBucket = Pick<
	UserBucket,
	'_id' | 'ownerGroupId' | 'slug' | 'host' | 'subdomain'
>;

/*
 * A path, a subdomain, or none of its own yet: the forms whose change a group owner may make. A hostname
 * reaches into the operator's domain, and the root belongs to the two buckets the instance is built on. Which
 * form an owner may move *to* is `addressForms`, checked by the route.
 */
function ownerMayReaddress(bucket: AddressedBucket): boolean {
	const kind = addressOf(bucket).kind;
	return kind === 'path' || kind === 'subdomain' || kind === 'unaddressed';
}

/*
 * Which facts can change this caller's answer. A super administrator's never can, so their reads — a whole
 * list included — cost nothing new; the dependency counts matter only to a group owner whose bucket has a
 * form they may change, and the account count only to a member who is not an owner.
 */
export function bucketFactsWanted(
	ctx: AdminContext,
	bucket: AddressedBucket
): { dependents: boolean; accounts: boolean } {
	if (ctx.superAdmin || isUndeletableBucket(bucket._id)) {
		return { dependents: false, accounts: false };
	}
	const owner = ownsGroup(ctx, bucket.ownerGroupId);
	return {
		dependents: owner && ownerMayReaddress(bucket),
		accounts: !owner && belongsTo(ctx, bucket.ownerGroupId)
	};
}

/*
 * Changing an address changes a bucket's issuer identifier and breaks every client integrated with it, so it
 * stays a super administrator's once anything is integrated: an application, an identity provider registered with the old callback, or a provisioning connection pointed at the old base
 * URL. Before then nothing breaks, and an owner who mistyped a path corrects it themselves. A hostname target
 * is a super administrator's whatever the bucket's state, which the route checks, because this answers per
 * bucket and not per target. The two buckets served at the root keep theirs, or the console would lock every
 * operator out of the surface that could move it back.
 */
function mayChangeBucketAddress(
	ctx: AdminContext,
	bucket: AddressedBucket,
	facts: BucketFacts
): boolean {
	if (isUndeletableBucket(bucket._id)) return false;
	if (ctx.superAdmin) return true;
	const dependents = facts.dependents;
	return (
		ownsGroup(ctx, bucket.ownerGroupId) &&
		ownerMayReaddress(bucket) &&
		dependents !== undefined &&
		dependents.applications === 0 &&
		dependents.providers === 0 &&
		dependents.connections === 0
	);
}

/*
 * Deleting a bucket that holds accounts deletes people, so it is an owner's act, as moving it is; an empty
 * bucket is still deletable by any member of its group.
 */
function mayDeleteBucket(
	ctx: AdminContext,
	bucket: AddressedBucket,
	facts: BucketFacts
): boolean {
	if (isUndeletableBucket(bucket._id) || !holdsBucket(ctx, bucket)) {
		return false;
	}
	return (
		ctx.superAdmin ||
		ownsGroup(ctx, bucket.ownerGroupId) ||
		facts.accounts === 0
	);
}

export function bucketCan(
	ctx: AdminContext,
	bucket: AddressedBucket,
	facts: BucketFacts = NO_BUCKET_FACTS
): BucketCan {
	/*
	 * The administrators' bucket: its accounts are administrators, managed on their own routes, so everything
	 * but reading and changing its settings stays closed to it — for a super administrator as well.
	 */
	const reserved = bucket._id === ADMIN_BUCKET_ID;
	/* The instance is built on these two: neither moves, changes address or is deleted. */
	const fixed = isUndeletableBucket(bucket._id);
	const holds = holdsBucket(ctx, bucket);
	const edit = !reserved && holds;
	return {
		read: ctx.superAdmin || (!reserved && holds),
		manageUsers: !reserved && holds,
		editSettings: ctx.superAdmin || edit,
		edit,
		/* A super administrator reads any bucket's figures, the reserved ones included. */
		readActivity: ctx.superAdmin || edit,
		changeAddress: mayChangeBucketAddress(ctx, bucket, facts),
		/* Taking a bucket away removes every other member's access to it, so it is an owner's act. */
		move:
			!fixed &&
			holds &&
			(ctx.superAdmin || ownsGroup(ctx, bucket.ownerGroupId)),
		delete: mayDeleteBucket(ctx, bucket, facts),
		setPlan: ctx.superAdmin
	};
}

/*
 * The shared root namespace is a super administrator's to write: every tenant served at the root shares one
 * issuer, and nothing a resource could publish would stop one of them declaring another's server first.
 */
export function mayDeclareIn(ctx: AdminContext, namespace: string): boolean {
	return ctx.superAdmin || namespace !== ROOT_NAMESPACE;
}

export function meCan(ctx: AdminContext): MeCan {
	/*
	 * A creation lands in the active group; a super administrator with none creates into the System group.
	 * Anyone else always has one, because a personal group is created with the account.
	 */
	const creates = ctx.superAdmin || ctx.activeGroupId !== '';
	return {
		createProject: creates,
		addressForms: addressFormsFor(ctx),
		createTeam: true,
		instance: ctx.superAdmin
	};
}

/*
 * Read live, at the moment a form is chosen, so a saved setting judges the next request without a restart.
 * Subdomain first wherever it is offered: an operator who has switched it on has the wildcard DNS it needs,
 * and an origin of its own keeps a project's cookies and pages apart from every other project's.
 */
function addressFormsFor(ctx: AdminContext): AddressFormChoice[] {
	const setting = ApplicationConfig['projects.addressForms'];
	const team: AddressFormChoice[] =
		setting === 'path'
			? ['path']
			: setting === 'subdomain'
				? ['subdomain']
				: ['subdomain', 'path'];
	if (!ctx.superAdmin) return team;
	/* Naming a hostname puts a name in the operator's own domain under the caller's control. */
	const rest: AddressFormChoice[] = (['subdomain', 'path'] as const).filter(
		(form) => !team.includes(form)
	);
	return [...team, ...rest, 'host'];
}
