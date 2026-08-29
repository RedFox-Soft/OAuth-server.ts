import { adminSessionStore, getGroupStore } from '../lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from '../lib/admin/consts.ts';
import { ensurePersonalGroup } from '../lib/admin/groups/personal.ts';

/*
 * A signed-in administrator, as the login route would leave one.
 *
 * Replaces the `adminSessionStore.create({ ... })` block that was copied into three dozen specs. It
 * exists because a session now carries an active scope: writing that literal at every call site would
 * be a guess about which group the administrator is in, repeated three dozen times, and every one of
 * them would have to change again the next time the session gains a field.
 *
 * Resolves the personal group the way `createAdminSession` does, so a spec's session points where a
 * real one would rather than at a scope the caller does not belong to.
 */
/*
 * The group an administrator's containers should belong to for them to reach it.
 *
 * Specs that seed a project or bucket and then act on it as that administrator need the two to agree:
 * seeding into the reserved `unassigned` group and expecting a 200 asserts the opposite of what this
 * feature does. Returning the personal group keeps a spec's setup honest about which tenant it is in.
 */
export async function groupIdFor(user: {
	_id: string;
	email: string;
}): Promise<string> {
	return (await ensurePersonalGroup(user._id, user.email))._id;
}

/*
 * The same thing for a spec that only kept the id — most of them, because the session helpers return
 * `{ cookie, userId }`. Throws rather than returning null: a spec reaching here has already created a
 * session for this administrator, so a missing personal group means the helper above did not run and
 * the spec is about to assert against a scope that does not exist.
 */
export async function personalGroupId(userId: string): Promise<string> {
	const group = await getGroupStore().findPersonalFor(userId);
	if (!group) {
		throw new Error(`no personal group for ${userId}: create a session first`);
	}
	return group._id;
}

export async function sessionFor(user: { _id: string; email: string }) {
	const personal = await ensurePersonalGroup(user._id, user.email);
	return adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		activeGroupId: personal._id,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
}
