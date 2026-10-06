import crypto from 'node:crypto';

import { getUserStore } from '../adapters/index.js';
import type {
	ProvisioningConnection,
	User,
	UserBucket
} from '../adapters/types.js';
import { recordConnectionAudit } from '../admin/audit/record.js';
import {
	SCIM_DEFAULT_PAGE,
	SCIM_LIST_RESPONSE,
	SCIM_MAX_PAGE
} from '../consts/scim.js';
import type { CascadeResult } from '../helpers/cascade.js';
import {
	createEndUser,
	EndUserError,
	removeEndUser,
	updateEndUser,
	type EndUserActor
} from '../end_users/service.js';
import { ScimError } from './errors.js';
import { parseUserFilter } from './filter.js';
import { applyPatch } from './patch.js';
import {
	canonicalUser,
	createdNames,
	desiredUserOf,
	patchableView,
	scimLocation,
	toScim,
	updateFor,
	type DesiredUser,
	type Leniency,
	type ScimObject
} from './resource.js';

/*
 * `/Users`, over part 1's end-user service with the connection as the actor (spec FR-042): uniqueness,
 * provisioned-user ownership, access ending and the local lock are the service's rules, held here by not
 * being restated. What this module adds is SCIM: the resource shape, the filter, PATCH, and the audit entry
 * written under the connection.
 */

export interface ScimRequestContext {
	bucket: UserBucket;
	connection: ProvisioningConnection;
	base: string;
	leniency: Leniency;
}

export interface ScimReply {
	status: number;
	body?: unknown;
	headers?: Record<string, string>;
}

const actorOf = (connection: ProvisioningConnection): EndUserActor => ({
	kind: 'connection',
	connectionId: connection._id
});

/*
 * The service's refusals in SCIM's terms. A uniqueness message names the field and nothing about the
 * holder; a 404 is the same whether the user does not exist or belongs to another connection.
 */
function asScim(error: unknown): never {
	if (error instanceof EndUserError) {
		if (error.status === 404)
			throw new ScimError(404, undefined, 'no such user');
		if (error.status === 409) {
			const field = /^(\w+) already exists$/.exec(error.message)?.[1];
			throw new ScimError(
				409,
				'uniqueness',
				field
					? `${field === 'email' ? 'that email' : field} is already taken in this bucket`
					: 'a unique attribute is already taken in this bucket'
			);
		}
		throw new ScimError(400, 'invalidValue', error.message);
	}
	throw error;
}

/*
 * A partial sweep — the user can no longer sign in, but some record of their access could not be removed.
 * Answered as a 500 so the directory retries, and the retry sweeps again (part 1, FR-003).
 */
function assertSweepComplete(result: CascadeResult | undefined): void {
	if (result && result.failedAreas.length > 0) {
		throw new ScimError(
			500,
			undefined,
			'the change was applied but ending the user’s access did not complete; retry the request'
		);
	}
}

/* A user is this connection's to see only when it provisioned them; anything else does not exist. */
async function ownUser(context: ScimRequestContext, id: string): Promise<User> {
	const user = await getUserStore(context.bucket._id).find(id);
	if (!user || user.provisionedBy !== context.connection._id) {
		throw new ScimError(404, undefined, 'no such user');
	}
	return user;
}

function auditDetail(context: ScimRequestContext, attributes: string[]) {
	return {
		attributes,
		targetScope: context.bucket._id,
		ownerGroupId: context.bucket.ownerGroupId
	};
}

export async function createUser(
	context: ScimRequestContext,
	body: unknown
): Promise<ScimReply> {
	const desired = desiredUserOf(canonicalUser(body, context.leniency));
	const id = crypto.randomUUID().replaceAll('-', '');
	const user = await createEndUser(
		context.bucket,
		actorOf(context.connection),
		{
			id,
			email: desired.email,
			verified: context.connection.emailTrust === 'trusted',
			userName: desired.userName,
			externalId: desired.externalId,
			profile: desired.profile,
			active: desired.active
		},
		() =>
			recordConnectionAudit(
				context.connection._id,
				'enduser.create',
				id,
				auditDetail(context, createdNames(desired))
			)
	).catch(asScim);
	return {
		status: 201,
		body: toScim(user, context.base),
		headers: { Location: scimLocation(context.base, user._id) }
	};
}

export async function getUser(
	context: ScimRequestContext,
	id: string
): Promise<ScimReply> {
	return {
		status: 200,
		body: toScim(await ownUser(context, id), context.base)
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

/* Query parameter names are matched case-insensitively, as SCIM attribute names are. */
function param(query: URLSearchParams, name: string): string | null {
	const lower = name.toLowerCase();
	for (const [key, value] of query) {
		if (key.toLowerCase() === lower) return value;
	}
	return null;
}

export async function listUsers(
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
		? parseUserFilter(filterText, context.connection._id)
		: { filter: { provisionedBy: context.connection._id }, impossible: false };

	let users: User[] = [];
	let totalResults = 0;
	if (!parsed.impossible) {
		const store = getUserStore(context.bucket._id);
		if (parsed.emailType !== undefined) {
			/*
			 * At most one user holds a login email in a bucket, so the type condition is checked on that one
			 * record rather than translated into a query on the profile.
			 */
			const found = await store.query(parsed.filter, {
				startIndex: 1,
				count: 1
			});
			const type = parsed.emailType.toLowerCase();
			const matching = found.users.filter((user) =>
				(user.profile?.emails ?? []).some(
					(e) =>
						e.value.toLowerCase() === user.email &&
						e.type?.toLowerCase() === type
				)
			);
			totalResults = matching.length;
			users = startIndex === 1 ? matching.slice(0, count) : [];
		} else {
			const page = await store.query(parsed.filter, { startIndex, count });
			users = page.users;
			totalResults = page.totalResults;
		}
	}
	return {
		status: 200,
		body: {
			schemas: [SCIM_LIST_RESPONSE],
			totalResults,
			startIndex,
			itemsPerPage: users.length,
			Resources: users.map((user) => toScim(user, context.base))
		}
	};
}

async function applyDesired(
	context: ScimRequestContext,
	user: User,
	desired: DesiredUser
): Promise<ScimReply> {
	const { input, changes } = updateFor(user, desired, context.connection);
	/* Asserting what is already stored writes nothing and audits nothing (spec FR-040). */
	if (changes.length === 0) {
		return { status: 200, body: toScim(user, context.base) };
	}
	const { user: updated, revoked } = await updateEndUser(
		context.bucket,
		actorOf(context.connection),
		user._id,
		input,
		() =>
			recordConnectionAudit(
				context.connection._id,
				'enduser.update',
				user._id,
				auditDetail(context, changes)
			)
	).catch(asScim);
	assertSweepComplete(revoked);
	return { status: 200, body: toScim(updated, context.base) };
}

/* RFC 7644 §3.5.1, with `active` left as it is when the body omits it (spec FR-024). */
export async function replaceUser(
	context: ScimRequestContext,
	id: string,
	body: unknown
): Promise<ScimReply> {
	const user = await ownUser(context, id);
	const desired = desiredUserOf(canonicalUser(body, context.leniency));
	return applyDesired(context, user, desired);
}

export async function patchUser(
	context: ScimRequestContext,
	id: string,
	body: unknown
): Promise<ScimReply> {
	const user = await ownUser(context, id);
	const patched: ScimObject = applyPatch(
		patchableView(user, context.base),
		body,
		context.leniency
	);
	return applyDesired(context, user, desiredUserOf(patched));
}

export async function deleteUser(
	context: ScimRequestContext,
	id: string
): Promise<ScimReply> {
	const user = await ownUser(context, id);
	const result = await removeEndUser(
		context.bucket,
		actorOf(context.connection),
		user._id,
		() =>
			recordConnectionAudit(
				context.connection._id,
				'enduser.delete',
				user._id,
				auditDetail(context, [])
			)
	).catch(asScim);
	assertSweepComplete(result);
	return { status: 204 };
}
