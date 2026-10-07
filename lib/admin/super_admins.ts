import { getGroupStore, getUserStore } from '../adapters/index.js';
import type { Group } from '../adapters/types.js';
import { SUPER_ADMINS_GROUP_SEED } from '../consts/admin_seed.js';
import {
	ADMIN_BUCKET_ID,
	SUPER_ADMINS_GROUP_ID,
	SUPER_ADMINS_GROUP_NAME
} from './consts.js';

/*
 * The instance-wide privilege, as membership of one reserved administrator group (specs/071 research R5).
 *
 * There is no role anywhere: "is this administrator a super administrator" is "is this administrator a member
 * of Super administrators", answered from the group-membership read every admin request already makes
 * (lib/admin/auth/rbac.ts). This module is the only writer of that membership.
 */

/* Creates the group if it is missing. Idempotent; the provisioning scripts seed it too. */
export async function ensureSuperAdminsGroup(): Promise<Group> {
	const groups = getGroupStore();
	return (
		(await groups.find(SUPER_ADMINS_GROUP_ID)) ??
		groups.create({
			_id: SUPER_ADMINS_GROUP_ID,
			name: SUPER_ADMINS_GROUP_NAME,
			...SUPER_ADMINS_GROUP_SEED,
			members: [...SUPER_ADMINS_GROUP_SEED.members]
		})
	);
}

export function isSuperAdminsGroup(groupId: string): boolean {
	return groupId === SUPER_ADMINS_GROUP_ID;
}

export async function superAdminIds(): Promise<string[]> {
	return (await ensureSuperAdminsGroup()).members.map((m) => m.userId);
}

export async function isSuperAdmin(userId: string): Promise<boolean> {
	return (await superAdminIds()).includes(userId);
}

/* Adds the administrator to the group; answers false when they were a member already. */
export async function grantSuperAdmin(userId: string): Promise<boolean> {
	const group = await ensureSuperAdminsGroup();
	if (group.members.some((m) => m.userId === userId)) return false;
	await getGroupStore().update(SUPER_ADMINS_GROUP_ID, {
		members: [...group.members, { userId, role: 'member' }]
	});
	return true;
}

/* Removes the administrator from the group; answers false when they were not a member. */
export async function withdrawSuperAdmin(userId: string): Promise<boolean> {
	const group = await ensureSuperAdminsGroup();
	if (!group.members.some((m) => m.userId === userId)) return false;
	await getGroupStore().update(SUPER_ADMINS_GROUP_ID, {
		members: group.members.filter((m) => m.userId !== userId)
	});
	return true;
}

/*
 * How many active super administrators would remain if `userId` were withdrawn or deactivated — the count the
 * last-super-administrator rule refuses at zero.
 */
export async function activeSuperAdminsWithout(
	userId: string
): Promise<number> {
	const users = getUserStore(ADMIN_BUCKET_ID);
	let count = 0;
	for (const id of await superAdminIds()) {
		if (id === userId) continue;
		const user = await users.find(id);
		if (user?.active) count += 1;
	}
	return count;
}

/* Whether any active administrator holds the privilege — what keeps first-run setup closed. */
export async function hasActiveSuperAdmin(): Promise<boolean> {
	return (await activeSuperAdminsWithout('')) > 0;
}
