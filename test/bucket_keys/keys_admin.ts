import { Elysia } from 'elysia';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketKeyRoutes } from 'lib/admin/bucket_keys/routes.ts';
import { jwksRoutes } from 'lib/admin/jwks/routes.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { keysFor } from 'lib/keys/issuer_keys.ts';
import { sessionFor } from '../admin_session.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(bucketKeyRoutes)
	.use(jwksRoutes);

export async function administrator(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`keys-${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const group = await ensurePersonalGroup(user._id, user.email);
	return {
		userId: user._id,
		groupId: group._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`
	};
}

/* A bucket at an address of its own, owned by the group, already holding its first key. */
export async function ownedBucket(ownerGroupId: string) {
	const bucket = await getBucketStore().create({
		ownerGroupId,
		name: 'Keyed',
		slug: `keyed${Math.random().toString(36).slice(2, 8)}`
	});
	forgetBucketAddresses();
	await keysFor(bucket);
	return bucket;
}

export async function call(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
) {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: (text ? JSON.parse(text) : {}) as Record<string, unknown>
	};
}

export interface KeyView {
	kid: string;
	alg: string;
	state: string;
	removableAt?: string;
}

export async function listed(bucketId: string, cookie: string) {
	const { body } = await call(
		'GET',
		`/admin/api/buckets/${bucketId}/keys`,
		cookie
	);
	return (body.keys ?? []) as KeyView[];
}
