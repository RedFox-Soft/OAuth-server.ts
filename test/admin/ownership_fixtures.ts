import { adapter, getBucketStore, getGroupStore } from 'lib/adapters/index.ts';
import type { Group, User, UserBucket } from 'lib/adapters/types.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * State for the specs about moving containers between administrator groups (specs/075), seeded through the
 * stores: what those specs prove is the move, not how a group or a bucket comes to exist.
 */

export async function regularGroup(
	owners: readonly User[],
	members: readonly User[] = []
): Promise<Group> {
	return getGroupStore().create({
		_id: nanoid(),
		name: `team-${nanoid()}`,
		kind: 'regular',
		members: [
			...owners.map((u) => ({ userId: u._id, role: 'owner' as const })),
			...members.map((u) => ({ userId: u._id, role: 'member' as const }))
		]
	});
}

/* A bucket and `clientCount` applications in it, all owned by one group (specs/099). */
export async function bucketWithClients(
	ownerGroupId: string,
	clientCount: number
): Promise<{ bucket: UserBucket; clientIds: string[] }> {
	const id = nanoid().toLowerCase();
	const bucket = await getBucketStore().create({
		name: `bucket ${id}`,
		slug: `b-${id}`.replace(/[^a-z0-9-]/g, ''),
		ownerGroupId
	});
	const clientIds: string[] = [];
	for (let i = 0; i < clientCount; i += 1) {
		const clientId = `app-${String(i)}-${id}`;
		await adapter('Client').upsert(clientId, {
			clientId,
			bucketId: bucket._id,
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: [`https://${clientId}.example.com/cb`],
			token_endpoint_auth_method: 'none'
		});
		clientIds.push(clientId);
	}
	return { bucket, clientIds };
}

/* The cookie header of a fresh console session for `user`, scoped to their personal group. */
export async function cookieFor(user: User): Promise<string> {
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}
