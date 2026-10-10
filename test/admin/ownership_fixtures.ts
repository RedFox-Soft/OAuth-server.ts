import {
	getBucketStore,
	getGroupStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import type { Group, Project, User, UserBucket } from 'lib/adapters/types.ts';
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

/* A bucket and `projectCount` projects using it, all owned by one group. */
export async function bucketWithProjects(
	ownerGroupId: string,
	projectCount: number
): Promise<{ bucket: UserBucket; projects: Project[] }> {
	const id = nanoid().toLowerCase();
	const bucket = await getBucketStore().create({
		name: `bucket ${id}`,
		slug: `b-${id}`.replace(/[^a-z0-9-]/g, ''),
		ownerGroupId
	});
	const projects: Project[] = [];
	for (let i = 0; i < projectCount; i += 1) {
		projects.push(
			await getProjectStore().create({
				name: `project ${String(i)} ${id}`,
				slug: `p${String(i)}-${id}`.replace(/[^a-z0-9-]/g, ''),
				ownerGroupId,
				bucketId: bucket._id
			})
		);
	}
	return { bucket, projects };
}

/* The cookie header of a fresh console session for `user`, scoped to their personal group. */
export async function cookieFor(user: User): Promise<string> {
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}
