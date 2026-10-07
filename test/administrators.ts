import { getUserStore } from '../lib/adapters/index.ts';
import type { User } from '../lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from '../lib/admin/consts.ts';
import { grantSuperAdmin } from '../lib/admin/super_admins.ts';

/*
 * An administrator account as a spec needs one: a plain administrator, or a super administrator — which is
 * membership of Super administrators, granted the way the grant route grants it. There is no role to pass:
 * the instance privilege is a group (specs/071).
 */
export type AdminKind = 'super' | 'plain';

export async function createAdministrator(
	kind: AdminKind = 'plain',
	email = `${kind}-${Math.random().toString(36).slice(2)}@x.io`
): Promise<User> {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(email, 'hash');
	if (kind === 'super') await grantSuperAdmin(user._id);
	return user;
}
