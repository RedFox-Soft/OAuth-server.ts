import { getBucketGroupStore, getUserStore } from '../adapters/index.js';
import { isUniqueValueTaken } from '../adapters/conflicts.js';
import {
	MAX_END_USER_PAGE,
	type BucketGroup,
	type ProvisioningConnection,
	type UserBucket
} from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import type { EndUserActor } from '../end_users/service.js';

/*
 * Every change to a bucket group, whichever surface it arrives through — the admin API (and MCP, which
 * dispatches into it) and SCIM. The rules live here so they hold however a change arrives; a surface only
 * authenticates its caller, names it as an actor, and records the audit entry.
 *
 * Every refusal is decided before the first write, and each accepted change is exactly one store call
 * (`change`), so a refused request — a foreign member, a taken name — changes nothing on any backend.
 */

export type BucketGroupActor = EndUserActor;

/* What an accepted change does, for the audit entry: attribute names, and the member ids added and removed. */
export interface GroupChangeParts {
	attributes: string[];
	added: string[];
	removed: string[];
}

/* Called once, after every check has passed and before anything is written. */
export type RecordGroupChange = (parts: GroupChangeParts) => Promise<unknown>;

export class BucketGroupError extends Error {
	constructor(
		readonly status: 404 | 409 | 422,
		message: string,
		readonly extra: Record<string, unknown> = {}
	) {
		super(message);
		this.name = 'BucketGroupError';
	}
}

const store = () => getBucketGroupStore();

const MAX_DISPLAY_NAME = 256;

function assertGroupsAllowed(bucket: UserBucket): void {
	/* The administrators' bucket groups its people only by administrator groups (specs/071 FR-005c). */
	if (bucket._id === ADMIN_BUCKET_ID) {
		throw new BucketGroupError(404, 'bucket not found');
	}
}

function displayNameOf(value: string): string {
	const trimmed = value.trim();
	if (trimmed.length === 0 || trimmed.length > MAX_DISPLAY_NAME) {
		throw new BucketGroupError(
			422,
			`displayName must be 1–${MAX_DISPLAY_NAME} characters`
		);
	}
	return trimmed;
}

/* The store's uniqueness refusal. It never names the group holding the value — that group may be invisible to the caller. */
function takenAsError(error: unknown): never {
	if (isUniqueValueTaken(error)) {
		throw new BucketGroupError(
			409,
			error.field === 'externalId'
				? 'externalId must be unique for this connection'
				: 'displayName must be unique in this bucket'
		);
	}
	throw error;
}

/*
 * Who may change this group. A provisioned group's source of truth is its connection, so an administrator is
 * refused (IPSIE §4.2), with the answer an administrator already gets for a provisioned user. A connection
 * reaches only its own groups; any other does not exist as far as it can tell.
 */
function assertActorMayChange(actor: BucketGroupActor, group: BucketGroup) {
	if (actor.kind === 'admin') {
		if (group.provisionedBy !== undefined) {
			throw new BucketGroupError(
				409,
				`group is managed by connection ${group.provisionedBy}`
			);
		}
		return;
	}
	if (group.provisionedBy !== actor.connectionId) {
		throw new BucketGroupError(404, 'group not found');
	}
}

/* A group as the actor may see it: a connection sees only its own; an administrator sees the bucket's. */
export async function loadGroup(
	bucket: UserBucket,
	actor: BucketGroupActor,
	id: string
): Promise<BucketGroup> {
	assertGroupsAllowed(bucket);
	const group = await store().find(id);
	if (
		!group ||
		group.bucketId !== bucket._id ||
		(actor.kind === 'connection' && group.provisionedBy !== actor.connectionId)
	) {
		throw new BucketGroupError(404, 'group not found');
	}
	return group;
}

function chunks<T>(items: T[], size: number): T[][] {
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size)
		out.push(items.slice(i, i + size));
	return out;
}

/*
 * Every id to be added must be an end user of the bucket — and, for a connection, one it manages. The refusal
 * is the same whether the id is unknown or someone else's, so it never says whether an account exists.
 */
async function assertMembersAllowed(
	bucket: UserBucket,
	actor: BucketGroupActor,
	ids: string[]
): Promise<void> {
	const users = getUserStore(bucket._id);
	for (const batch of chunks(ids, MAX_END_USER_PAGE)) {
		const found = new Map(
			(await users.findMany(batch)).map((user) => [user._id, user])
		);
		for (const id of batch) {
			const user = found.get(id);
			const allowed =
				user !== undefined &&
				(actor.kind === 'admin' || user.provisionedBy === actor.connectionId);
			if (!allowed) {
				throw new BucketGroupError(
					422,
					actor.kind === 'admin'
						? `user ${id} is not in this bucket`
						: `member ${id} is not a user of this connection`
				);
			}
		}
	}
}

function unique(ids: string[]): string[] {
	return [...new Set(ids)];
}

export interface CreateGroupInput {
	/* Allocated by the caller so the audit entry can name the group before it exists. */
	id: string;
	displayName: string;
	externalId?: string;
	memberIds?: string[];
}

export async function createGroup(
	bucket: UserBucket,
	actor: BucketGroupActor,
	input: CreateGroupInput,
	record: RecordGroupChange
): Promise<BucketGroup> {
	assertGroupsAllowed(bucket);
	const displayName = displayNameOf(input.displayName);
	if (input.externalId !== undefined && actor.kind !== 'connection') {
		throw new BucketGroupError(
			422,
			'an external identifier needs the connection that manages the group'
		);
	}
	const memberIds = unique(input.memberIds ?? []);
	await assertMembersAllowed(bucket, actor, memberIds);
	await record({
		attributes: [
			'displayName',
			...(input.externalId === undefined ? [] : ['externalId'])
		],
		added: memberIds,
		removed: []
	});
	try {
		return await store().create(
			{
				_id: input.id,
				bucketId: bucket._id,
				displayName,
				externalId: input.externalId,
				provisionedBy:
					actor.kind === 'connection' ? actor.connectionId : undefined
			},
			memberIds
		);
	} catch (error) {
		return takenAsError(error);
	}
}

/*
 * The one way a group changes after creation. `replace` sets the membership exactly; otherwise `add` and
 * `remove` are applied to it. `externalId: null` clears the identifier.
 */
export interface GroupChangeInput {
	displayName?: string;
	externalId?: string | null;
	add?: string[];
	remove?: string[];
	replace?: string[];
}

export async function applyGroupChange(
	bucket: UserBucket,
	actor: BucketGroupActor,
	group: BucketGroup,
	input: GroupChangeInput,
	record: RecordGroupChange
): Promise<BucketGroup> {
	assertGroupsAllowed(bucket);
	assertActorMayChange(actor, group);

	const attributes: { displayName?: string; externalId?: string } = {};
	const changed: string[] = [];
	if (input.displayName !== undefined) {
		const displayName = displayNameOf(input.displayName);
		if (displayName !== group.displayName) {
			attributes.displayName = displayName;
			changed.push('displayName');
		}
	}
	if (input.externalId !== undefined) {
		if (actor.kind !== 'connection') {
			throw new BucketGroupError(
				422,
				'an external identifier needs the connection that manages the group'
			);
		}
		const next = input.externalId ?? undefined;
		if (next !== group.externalId) {
			Object.assign(attributes, { externalId: next });
			changed.push('externalId');
		}
	}

	let add: string[];
	let remove: string[];
	if (input.replace !== undefined) {
		const wanted = new Set(input.replace);
		const current = new Set(await store().memberIds(group._id));
		add = [...wanted].filter((id) => !current.has(id));
		remove = [...current].filter((id) => !wanted.has(id));
	} else {
		/* Only what actually changes: adding a member twice or removing a non-member is not a change. */
		const touched = unique([...(input.add ?? []), ...(input.remove ?? [])]);
		const memberships = touched.length
			? await store().groupIdsOf(bucket._id, touched)
			: new Map<string, string[]>();
		const isMember = (id: string) =>
			(memberships.get(id) ?? []).includes(group._id);
		const removing = new Set(input.remove ?? []);
		add = unique(input.add ?? []).filter(
			(id) => !isMember(id) && !removing.has(id)
		);
		remove = unique(input.remove ?? []).filter((id) => isMember(id));
	}
	await assertMembersAllowed(bucket, actor, add);

	if (changed.length === 0 && add.length === 0 && remove.length === 0) {
		return group;
	}
	await record({ attributes: changed, added: add, removed: remove });
	try {
		const updated = await store().change(group._id, {
			attributes,
			add,
			remove
		});
		if (!updated) throw new BucketGroupError(404, 'group not found');
		return updated;
	} catch (error) {
		return takenAsError(error);
	}
}

export async function deleteGroup(
	bucket: UserBucket,
	actor: BucketGroupActor,
	group: BucketGroup,
	record: () => Promise<unknown>
): Promise<void> {
	assertGroupsAllowed(bucket);
	assertActorMayChange(actor, group);
	await record();
	await store().destroy(group._id);
}

/*
 * Hands an administrator-kept group to one of the bucket's connections — the explicit step that lets a
 * bucket whose groups already have the directory's names start provisioning them. Never automatic, and
 * refused while any member is someone the connection does not manage: the connection would otherwise be
 * handed authority over local users through the back door.
 */
export async function assignGroupToConnection(
	bucket: UserBucket,
	group: BucketGroup,
	connection: ProvisioningConnection,
	record: RecordGroupChange
): Promise<BucketGroup> {
	assertGroupsAllowed(bucket);
	if (group.provisionedBy !== undefined) {
		throw new BucketGroupError(
			409,
			`group is already managed by connection ${group.provisionedBy}`
		);
	}
	if (connection.bucketId !== bucket._id) {
		throw new BucketGroupError(422, 'connection belongs to another bucket');
	}
	const users = getUserStore(bucket._id);
	let foreign = 0;
	for (let startIndex = 1; ; startIndex += MAX_END_USER_PAGE) {
		const ids = await store().memberIds(group._id, {
			startIndex,
			count: MAX_END_USER_PAGE
		});
		if (ids.length === 0) break;
		const found = await users.findMany(ids);
		foreign +=
			ids.length -
			found.filter((u) => u.provisionedBy === connection._id).length;
		if (ids.length < MAX_END_USER_PAGE) break;
	}
	if (foreign > 0) {
		throw new BucketGroupError(
			409,
			`${foreign} member${foreign === 1 ? ' is' : 's are'} not managed by this connection`,
			{ blockers: [{ kind: 'enduser', count: foreign }] }
		);
	}
	await record({ attributes: ['provisionedBy'], added: [], removed: [] });
	const updated = await store().change(group._id, {
		attributes: { provisionedBy: connection._id }
	});
	if (!updated) throw new BucketGroupError(404, 'group not found');
	return updated;
}

/* The display names of the user's groups, sorted — the `groups` claim's value. */
export async function groupNamesOf(
	bucketId: string,
	userId: string
): Promise<string[]> {
	const ids = await groupIdsOfUser(bucketId, userId);
	const names: string[] = [];
	for (const batch of chunks(ids, MAX_END_USER_PAGE)) {
		names.push(...(await store().findMany(batch)).map((g) => g.displayName));
	}
	return names.sort();
}

export async function groupIdsOfUser(
	bucketId: string,
	userId: string
): Promise<string[]> {
	return (await store().groupIdsOf(bucketId, [userId])).get(userId) ?? [];
}

/* How many groups a connection owns, for the connection-delete refusal. */
export async function ownedGroupCount(
	bucketId: string,
	connectionId: string
): Promise<number> {
	return (
		await store().query(
			{ bucketId, provisionedBy: connectionId },
			{ startIndex: 1, count: 0 }
		)
	).totalResults;
}
