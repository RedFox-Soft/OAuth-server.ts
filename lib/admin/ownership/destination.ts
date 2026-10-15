import { getGroupStore } from '../../adapters/index.js';
import type { Group } from '../../adapters/types.js';
import {
	AdminError,
	assertGroupMember,
	type AdminContext
} from '../auth/rbac.js';
import { isSuperAdminsGroup } from '../super_admins.js';

/*
 * The rules a move between administrator groups is decided by (specs/075), in one place. Only a bucket
 * moves; everything it holds follows it (specs/099).
 */

/*
 * The group a container is being moved into, refused in an order no answer can learn anything from.
 *
 * Membership is checked before anything about the group's kind is said, so a caller who does not belong
 * to it gets the answer an unknown id gets — the rule every loader on this surface follows. Super
 * administrators is not a group anything is moved into; to these routes it does not exist, as it does
 * not to the group routes.
 *
 * Belonging is enough at the destination: any member may already create containers there, so receiving
 * one grants nobody anything new. A personal group admits only its own administrator's work, which is
 * reachable only by a super administrator, since nobody else can belong to another's personal group.
 */
export async function loadDestination(
	admin: AdminContext,
	groupId: string
): Promise<Group> {
	const unknown = () =>
		admin.superAdmin
			? new AdminError(404, 'group not found')
			: new AdminError(403, 'no access to this group');
	if (isSuperAdminsGroup(groupId)) throw unknown();
	const group = await getGroupStore().find(groupId);
	if (!group) throw unknown();
	assertGroupMember(admin, groupId);
	if (group.kind === 'personal' && group.members[0]?.userId !== admin.userId) {
		throw new AdminError(403, 'a personal group belongs to its administrator');
	}
	return group;
}

/*
 * A group as a move's preview names it: the stored fields, never a display label. A personal group's label
 * depends on who is looking ("Personal" to its owner, "Personal — owner@email" to anyone else), so the
 * console builds it; the server cannot. A source group nobody can find any more — reachable only by a
 * super administrator — is named by its id alone.
 */
export async function describeGroup(id: string): Promise<{
	id: string;
	kind: Group['kind'] | null;
	name: string | null;
}> {
	const group = await getGroupStore().find(id);
	return { id, kind: group?.kind ?? null, name: group?.name ?? null };
}

/*
 * The one group a bucket is moving out of. A bucket moving into the group that already owns it is refused,
 * without naming the group.
 */
export function sourceGroupOf(
	owners: readonly string[],
	destination: string
): string {
	const sources = [...new Set(owners)].filter((id) => id !== destination);
	const only = sources.at(0);
	if (only === undefined) {
		throw new AdminError(409, 'already owned by this group');
	}
	return only;
}
