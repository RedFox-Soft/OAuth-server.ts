import crypto from 'node:crypto';

import { getBucketGroupStore } from '../adapters/index.js';
import type { BucketGroup } from '../adapters/types.js';
import { recordConnectionAudit } from '../admin/audit/record.js';
import {
	applyGroupChange,
	BucketGroupError,
	createGroup,
	deleteGroup,
	loadGroup,
	type BucketGroupActor,
	type GroupChangeParts
} from '../bucket_groups/service.js';
import {
	SCIM_DEFAULT_PAGE,
	SCIM_GROUP_SCHEMA,
	SCIM_LIST_RESPONSE,
	SCIM_MAX_PAGE,
	SCIM_READ_ONLY_ATTRIBUTES
} from '../consts/scim.js';
import { ScimError } from './errors.js';
import { parseGroupFilter } from './filter.js';
import { applyPatch, GROUP_PATCH } from './patch.js';
import {
	assertNoForbiddenKeys,
	scimLocation,
	toScimGroup,
	type ScimObject
} from './resource.js';
import type { ScimReply, ScimRequestContext } from './users.js';

/*
 * `/Groups` (RFC 7644 §3, IPSIE AL SCIM §6.2), over the bucket-group service with the connection as the actor:
 * ownership, uniqueness and member validation are the service's rules. What this module adds is SCIM — the
 * resource shape, the filter, PATCH, `excludedAttributes=members` — and the audit entries written under the
 * connection.
 *
 * A PATCH never reads the whole group unless an operation needs it. Entra fills a group in batches of a few
 * dozen members, one PATCH each; reading a 100,000-member group to apply each would make the cost of a change
 * the size of the group (specs/071 research R1, SC-004).
 */

const actorOf = (context: ScimRequestContext): BucketGroupActor => ({
	kind: 'connection',
	connectionId: context.connection._id
});

/* The service's refusals in SCIM's terms. A 404 is the same for an unknown group and another owner's. */
function asScim(error: unknown): never {
	if (error instanceof BucketGroupError) {
		if (error.status === 404) {
			throw new ScimError(404, undefined, 'no such group');
		}
		if (error.status === 409) {
			throw new ScimError(409, 'uniqueness', error.message);
		}
		throw new ScimError(400, 'invalidValue', error.message);
	}
	throw error;
}

function isObject(value: unknown): value is ScimObject {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function auditDetail(context: ScimRequestContext, attributes: string[]) {
	return {
		attributes,
		targetScope: context.bucket._id,
		ownerGroupId: context.bucket.ownerGroupId
	};
}

/* One entry per changed aspect: the group's attributes, members added, members removed — never member ids. */
async function recordChange(
	context: ScimRequestContext,
	groupId: string,
	parts: GroupChangeParts
): Promise<void> {
	const id = context.connection._id;
	if (parts.attributes.length) {
		await recordConnectionAudit(
			id,
			'bucketgroup.update',
			groupId,
			auditDetail(context, parts.attributes)
		);
	}
	if (parts.added.length) {
		await recordConnectionAudit(
			id,
			'bucketgroup.member.add',
			groupId,
			auditDetail(context, ['members'])
		);
	}
	if (parts.removed.length) {
		await recordConnectionAudit(
			id,
			'bucketgroup.member.remove',
			groupId,
			auditDetail(context, ['members'])
		);
	}
}

/* Query parameter names are matched case-insensitively, as SCIM attribute names are. */
function param(query: URLSearchParams, name: string): string | null {
	const lower = name.toLowerCase();
	for (const [key, value] of query) {
		if (key.toLowerCase() === lower) return value;
	}
	return null;
}

function attributeList(text: string | null): string[] | null {
	if (text === null) return null;
	return text
		.split(',')
		.map((name) => name.trim().toLowerCase())
		.map((name) =>
			name.startsWith(`${SCIM_GROUP_SCHEMA.toLowerCase()}:`)
				? name.slice(SCIM_GROUP_SCHEMA.length + 1)
				: name
		)
		.filter((name) => name !== '');
}

/*
 * Whether the response leaves `members` out: `excludedAttributes=members`, which IPSIE AL SCIM §6.2.3 asks a
 * client to send when listing, or an `attributes` list that does not name it (RFC 7644 §3.4.2.5). Other names
 * in either are accepted, and the rest of the resource is returned as it is by default.
 */
function withoutMembers(query: URLSearchParams | undefined): boolean {
	if (!query) return false;
	const excluded = attributeList(param(query, 'excludedAttributes'));
	if (excluded?.includes('members')) return true;
	const only = attributeList(param(query, 'attributes'));
	return only !== null && !only.includes('members');
}

async function present(
	context: ScimRequestContext,
	group: BucketGroup,
	query?: URLSearchParams
): Promise<ScimObject> {
	return toScimGroup(
		group,
		context.base,
		withoutMembers(query)
			? undefined
			: await getBucketGroupStore().memberIds(group._id)
	);
}

async function ownGroup(
	context: ScimRequestContext,
	id: string
): Promise<BucketGroup> {
	return loadGroup(context.bucket, actorOf(context), id).catch(asScim);
}

/* The member ids of a request's `members`, refusing a nested group (groups are flat, spec FR-002). */
function memberIdsOf(value: unknown): string[] {
	if (value === undefined || value === null) return [];
	if (!Array.isArray(value)) {
		throw new ScimError(400, 'invalidValue', 'members must be an array');
	}
	return value.map((member) => {
		if (!isObject(member)) {
			throw new ScimError(400, 'invalidValue', 'each member must be an object');
		}
		const type = Object.entries(member).find(
			([key]) => key.toLowerCase() === 'type'
		)?.[1];
		if (typeof type === 'string' && type.toLowerCase() === 'group') {
			throw new ScimError(400, 'invalidValue', 'groups do not contain groups');
		}
		const id = Object.entries(member).find(
			([key]) => key.toLowerCase() === 'value'
		)?.[1];
		if (typeof id !== 'string' || id === '') {
			throw new ScimError(400, 'invalidValue', 'each member needs a value');
		}
		return id;
	});
}

interface GroupBody {
	displayName: string;
	externalId?: string;
	members: string[];
}

/* A POST or PUT body: read-only attributes ignored (RFC 7644 §3.5.1), anything undeclared dropped or, strict, refused. */
function canonicalGroup(body: unknown, context: ScimRequestContext): GroupBody {
	if (!isObject(body)) {
		throw new ScimError(
			400,
			'invalidSyntax',
			'the request body must be a JSON object'
		);
	}
	assertNoForbiddenKeys(body, 'the request body');
	let displayName: unknown;
	let externalId: unknown;
	let members: unknown;
	for (const [key, raw] of Object.entries(body)) {
		const lower = key.toLowerCase();
		if (SCIM_READ_ONLY_ATTRIBUTES.includes(lower)) continue;
		if (lower === 'displayname') displayName = raw;
		else if (lower === 'externalid') externalId = raw;
		else if (lower === 'members') members = raw;
		else if (context.leniency.strict) {
			throw new ScimError(
				400,
				'invalidSyntax',
				`${key} is not an attribute of this resource`
			);
		}
	}
	if (typeof displayName !== 'string') {
		throw new ScimError(400, 'invalidValue', 'displayName is required');
	}
	if (
		externalId !== undefined &&
		externalId !== null &&
		typeof externalId !== 'string'
	) {
		throw new ScimError(400, 'invalidValue', 'externalId must be a string');
	}
	return {
		displayName,
		externalId: typeof externalId === 'string' ? externalId : undefined,
		members: [...new Set(memberIdsOf(members))]
	};
}

export async function createGroupResource(
	context: ScimRequestContext,
	body: unknown
): Promise<ScimReply> {
	const input = canonicalGroup(body, context);
	const id = crypto.randomUUID().replaceAll('-', '');
	const group = await createGroup(
		context.bucket,
		actorOf(context),
		{
			id,
			displayName: input.displayName,
			externalId: input.externalId,
			memberIds: input.members
		},
		(parts) =>
			recordConnectionAudit(
				context.connection._id,
				'bucketgroup.create',
				id,
				auditDetail(context, [
					...parts.attributes,
					...(parts.added.length ? ['members'] : [])
				])
			)
	).catch(asScim);
	return {
		status: 201,
		body: toScimGroup(group, context.base, input.members),
		headers: { Location: scimLocation(context.base, group._id, 'Groups') }
	};
}

export async function getGroupResource(
	context: ScimRequestContext,
	id: string,
	query: URLSearchParams
): Promise<ScimReply> {
	return {
		status: 200,
		body: await present(context, await ownGroup(context, id), query)
	};
}

function integerParam(value: string | null, fallback: number): number {
	if (value === null || value.trim() === '') return fallback;
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed)) {
		throw new ScimError(
			400,
			'invalidValue',
			'startIndex and count must be integers'
		);
	}
	return parsed;
}

export async function listGroups(
	context: ScimRequestContext,
	query: URLSearchParams
): Promise<ScimReply> {
	const startIndex = Math.max(1, integerParam(param(query, 'startIndex'), 1));
	const count = Math.min(
		SCIM_MAX_PAGE,
		Math.max(0, integerParam(param(query, 'count'), SCIM_DEFAULT_PAGE))
	);
	const filterText = param(query, 'filter');
	const parsed = filterText
		? parseGroupFilter(filterText, context.connection._id)
		: { filter: { provisionedBy: context.connection._id }, impossible: false };

	let groups: BucketGroup[] = [];
	let totalResults = 0;
	if (!parsed.impossible) {
		const page = await getBucketGroupStore().query(
			{ ...parsed.filter, bucketId: context.bucket._id },
			{ startIndex, count }
		);
		groups = page.groups;
		totalResults = page.totalResults;
	}
	return {
		status: 200,
		body: {
			schemas: [SCIM_LIST_RESPONSE],
			totalResults,
			startIndex,
			itemsPerPage: groups.length,
			Resources: await Promise.all(
				groups.map((g) => present(context, g, query))
			)
		}
	};
}

/* RFC 7644 §3.5.1: every attribute replaced, so a body without `members` empties the group. */
export async function replaceGroup(
	context: ScimRequestContext,
	id: string,
	body: unknown
): Promise<ScimReply> {
	const group = await ownGroup(context, id);
	const input = canonicalGroup(body, context);
	const updated = await applyGroupChange(
		context.bucket,
		actorOf(context),
		group,
		{
			displayName: input.displayName,
			externalId: input.externalId ?? null,
			replace: input.members
		},
		(parts) => recordChange(context, group._id, parts)
	).catch(asScim);
	return { status: 200, body: await present(context, updated) };
}

const MEMBER_FILTER = /^members\[\s*value\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\]$/i;

function stripGroupUrn(path: string): string {
	return path.toLowerCase().startsWith(`${SCIM_GROUP_SCHEMA.toLowerCase()}:`)
		? path.slice(SCIM_GROUP_SCHEMA.length + 1)
		: path;
}

/*
 * Which members a PATCH can touch, read from its operations without applying them: the ids it adds or names
 * for removal. `null` means some operation can touch any member — a `replace` of `members`, a `remove` of all
 * of them, a path-less operation carrying `members`, or a form this scan does not recognise — and the whole
 * member list is read instead. Erring towards `null` costs a read, never a wrong answer.
 */
function membersTouchedBy(body: unknown): string[] | null {
	if (!isObject(body)) return null;
	const operations = Object.entries(body).find(
		([key]) => key.toLowerCase() === 'operations'
	)?.[1];
	if (!Array.isArray(operations)) return null;
	const touched: string[] = [];
	for (const raw of operations) {
		if (!isObject(raw)) return null;
		const field = (name: string) =>
			Object.entries(raw).find(([key]) => key.toLowerCase() === name)?.[1];
		const op = field('op');
		const path = field('path');
		const value = field('value');
		if (typeof op !== 'string') return null;
		if (path === undefined || path === '') {
			if (!isObject(value)) return null;
			if (
				Object.keys(value).some(
					(k) => stripGroupUrn(k).toLowerCase() === 'members'
				)
			) {
				return null;
			}
			continue;
		}
		if (typeof path !== 'string') return null;
		const bare = stripGroupUrn(path);
		if (!bare.toLowerCase().startsWith('members')) continue;
		const filtered = MEMBER_FILTER.exec(bare);
		if (filtered) {
			touched.push(filtered[1].replace(/\\(.)/g, '$1'));
			continue;
		}
		if (bare.toLowerCase() !== 'members') return null;
		const lowerOp = op.toLowerCase();
		if (lowerOp === 'replace' || value === undefined) return null;
		const values = Array.isArray(value) ? value : [value];
		for (const v of values) {
			const id = isObject(v)
				? Object.entries(v).find(([key]) => key.toLowerCase() === 'value')?.[1]
				: undefined;
			if (typeof id !== 'string') return null;
			touched.push(id);
		}
	}
	return touched;
}

export async function patchGroup(
	context: ScimRequestContext,
	id: string,
	body: unknown
): Promise<ScimReply> {
	const group = await ownGroup(context, id);
	const store = getBucketGroupStore();
	const touched = membersTouchedBy(body);
	let before: string[];
	if (touched === null) {
		before = await store.memberIds(group._id);
	} else {
		const memberships = await store.groupIdsOf(context.bucket._id, [
			...new Set(touched)
		]);
		before = [...memberships]
			.filter(([, groupIds]) => groupIds.includes(group._id))
			.map(([userId]) => userId);
	}
	const view: ScimObject = {
		schemas: [SCIM_GROUP_SCHEMA],
		displayName: group.displayName,
		...(group.externalId === undefined ? {} : { externalId: group.externalId }),
		members: before.map((value) => ({ value }))
	};
	const patched = applyPatch(view, body, context.leniency, GROUP_PATCH);

	if (typeof patched.displayName !== 'string') {
		throw new ScimError(400, 'invalidValue', 'displayName is required');
	}
	const externalId = patched.externalId;
	if (externalId !== undefined && typeof externalId !== 'string') {
		throw new ScimError(400, 'invalidValue', 'externalId must be a string');
	}
	const after = new Set(memberIdsOf(patched.members));
	const was = new Set(before);
	await applyGroupChange(
		context.bucket,
		actorOf(context),
		group,
		{
			displayName: patched.displayName,
			externalId: externalId ?? null,
			add: [...after].filter((m) => !was.has(m)),
			remove: before.filter((m) => !after.has(m))
		},
		(parts) => recordChange(context, group._id, parts)
	).catch(asScim);
	/*
	 * 204, which RFC 7644 §3.5.2 allows and which both Entra and Okta document for a group PATCH: a 200 would
	 * have to carry the whole member list, the read this module avoids.
	 */
	return { status: 204 };
}

export async function deleteGroupResource(
	context: ScimRequestContext,
	id: string
): Promise<ScimReply> {
	const group = await ownGroup(context, id);
	await deleteGroup(context.bucket, actorOf(context), group, () =>
		recordConnectionAudit(
			context.connection._id,
			'bucketgroup.delete',
			group._id,
			auditDetail(context, [])
		)
	).catch(asScim);
	return { status: 204 };
}
