import { expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { admin, type Reply } from '../provisioning/helpers.ts';

/*
 * Bucket groups as an administrator reaches them: over HTTP, through the real admin routes, so authorization,
 * validation and the audit write run as they do in production.
 */

export { admin };

/* An administrator who is neither a super administrator nor in any group that owns the bucket. */
export async function outsiderCookie(): Promise<string> {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`outsider-${Math.random()}@x.io`,
		'hash'
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

export async function endUser(
	cookie: string,
	bucketId: string,
	email = `u-${Math.random().toString(36).slice(2)}@contoso.com`
): Promise<string> {
	const res = await admin(
		'POST',
		`/admin/api/buckets/${bucketId}/users`,
		cookie,
		{
			email,
			password: 'a password that is long enough'
		}
	);
	expect(res.status).toBe(201);
	return res.json._id as string;
}

export async function group(
	cookie: string,
	bucketId: string,
	displayName: string
): Promise<string> {
	const res = await admin(
		'POST',
		`/admin/api/buckets/${bucketId}/groups`,
		cookie,
		{
			displayName
		}
	);
	expect(res.status).toBe(201);
	return res.json.id as string;
}

export function addMembers(
	cookie: string,
	bucketId: string,
	gid: string,
	userIds: string[]
): Promise<Reply> {
	return admin(
		'POST',
		`/admin/api/buckets/${bucketId}/groups/${gid}/members`,
		cookie,
		{ userIds }
	);
}

export async function memberIds(
	cookie: string,
	bucketId: string,
	gid: string
): Promise<string[]> {
	const res = await admin(
		'GET',
		`/admin/api/buckets/${bucketId}/groups/${gid}/members?count=1000`,
		cookie
	);
	expect(res.status).toBe(200);
	return (res.json.members as { id: string }[]).map((m) => m.id);
}

export interface AuditEntry {
	action: string;
	targetId: string;
	attributes?: string[];
}

export async function auditOf(
	cookie: string,
	targetId: string
): Promise<AuditEntry[]> {
	const res = await admin(
		'GET',
		`/admin/api/audit?targetId=${encodeURIComponent(targetId)}&pageSize=100`,
		cookie
	);
	expect(res.status).toBe(200);
	return res.json.entries as AuditEntry[];
}
